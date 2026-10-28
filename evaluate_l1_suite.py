"""Named L1 acceptance scenarios over isolated real Modbus TCP servers.

The case manifest is written before execution. The trained detector, threshold
and Stage1Guard policy are not modified. Sensor/I/O faults are injected at
component boundaries, never by replacing model predictions or decisions.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import struct
import time
import traceback

from evaluate_stage1_regression import serve
from evaluate_stage1_threats import session
from mock_stage1_telemetry import MockStage1TelemetrySource
from modbus_gateway import ModbusGateway, receive_frame
from orchestrator import IntegrationOrchestrator
from swat_mock_profile import load_profile


CRITERIA = {
    'normal': 'Every valid command is acknowledged and received by mock SCADA; no spill.',
    'changeover': 'Both requested duty/standby transitions are acknowledged and applied.',
    'reversal': 'All safe ON/OFF reversals are acknowledged; no stale decisions or spill.',
    'hazard': 'At least one BLOCK before spill or depletion below 100 mm; if initially below 100 mm, prevent further depletion. Exact replay withheld.',
    'spoof': 'A corrupted observation triggers BLOCK; no corrupted sensor data is returned; no unrelated command rule.',
    'drift': 'Detect the gradual 20-observation bias sequence; do not silently accept the whole sequence.',
    'frozen': 'Detect the frozen level while delivered commands change actual tank level.',
    'frozen_flow': 'Detect flow frozen at its earlier open-valve value after a valve-close command.',
    'fault': 'Faulted/incomplete telemetry fails closed; no request reaches SCADA; delayed samples rejected within the 0.1 s lab freshness requirement.',
    'protocol': 'Malformed/unauthorized request rejected without forwarding; a valid follow-up still succeeds.',
    'fragments': 'A valid fragmented request is reassembled and forwarded exactly once.',
    'persistent_connection': 'Two valid requests on one TCP connection are independently acknowledged and forwarded.',
    'traffic': 'All valid requests reach SCADA with correct transaction IDs and source-isolated windows; no connection errors.',
    'burst_attack': 'Detect and withhold at least one request in the declared 20-read burst scenario.',
    'rule': 'Generated command signature blocks the designated replay while the declared unrelated safe command passes.',
    'recovery': 'After a rejected falsified reading, restored genuine telemetry is accepted.',
    'restart': 'A valid request succeeds after actual gateway component restart.',
    'restart_rule': 'Previously quarantined command remains withheld after gateway restart at the normal operating point.',
    'expiry': 'After explicit rule expiration, a now-safe command is no longer blocked solely by the old quarantine.',
    'downstream': 'Unavailable SCADA returns an error, with no forwarding and no committed Twin actuator change.',
    'export_failure': 'Rule-file I/O failure is reported and does not bypass the command block.',
    'draining': 'Detect sustained draining within 300 commands, generate a rule, block exact replay, and allow the identical benign packet afterward. Early allowed attacks are disclosed.',
    'readback': 'Valid L1 register read is forwarded and returns the independently computed mock value with the matching transaction ID.',
    'coalesced': 'Two coalesced TCP frames are parsed separately, acknowledged in order and forwarded exactly once each.',
    'fault_recovery': 'Invalid telemetry fails closed, then genuine telemetry succeeds without a restart.',
    'changed_tx': 'A quarantined command remains blocked with a different transaction ID; a benign command still passes.',
    'spoof_command': 'False telemetry cannot conceal a hazardous command: no forwarding, spill or further low-level depletion.',
    'unit': 'Only the configured laboratory unit ID 1 is accepted; other unit IDs are rejected without forwarding.',
}


def plans():
    cases=[]
    def add(name, area, category, kind, **parameters):
        cases.append(dict(id=f'L1-{len(cases)+1:03d}', name=name, area=area,
                          category=category, kind=kind, criterion=CRITERIA[kind], parameters=parameters))
    for level in (550.,700.,800.):
        add(f'Normal filling at {level:g} mm','normal','benign','normal',level=level,register=30,steps=5)
    for pump in (20,24):
        for level in (550.,740.,820.):
            add(f'Normal P{101 if pump==20 else 102} transfer at {level:g} mm','normal','benign','normal',
                level=level,register=pump,steps=12)
    for first,second in ((20,24),(24,20)):
        add(f'Changeover register {first} to {second}','normal','benign','changeover',first=first,second=second)
    add('Safe rapid pump reversals','normal','benign','reversal')
    for pumps in (0,1,2):
        add(f'Overflow near capacity with {pumps} running pumps','process','malicious','hazard',
            level=1198.,register=30,pumps=pumps,limit='high')
    for level in (1199.9,1200.):
        add(f'Inlet opening at capacity boundary {level:g} mm','boundary','malicious','hazard',
            level=level,register=30,pumps=0,limit='high')
        add(f'Safe inlet closure at {level:g} mm','boundary','benign','normal',
            level=level,register=30,steps=1,value=0)
    for pump in (20,24):
        for level in (99.,100.,101.):
            add(f'Low-level forced register {pump} ON at {level:g} mm','process','malicious','hazard',
                level=level,register=pump,pumps=0,limit='low')
    add('Both pumps forced ON near low level','process','malicious','hazard',
        level=101.,register=24,pumps=1,limit='low')
    for name,overrides,register,steps in [
        ('False low level',{'LIT101':100.},100,1),
        ('False high level',{'LIT101':1100.},100,1),
        ('False high inlet flow',{'FIT101':30.},110,1),
        ('Subtle false level',{'LIT101':700.},100,1),
        ('Subtle false flow',{'FIT101':.05},110,1),
        ('Persistent false level',{'LIT101':100.},100,3),
        ('Flow reported while inlet closed',{'FIT101':4.37},110,1),
        ('Level jump without inlet flow',{'LIT101':750.},100,1),
    ]:
        add(name,'sensors','malicious','spoof',overrides=overrides,register=register,steps=steps)
    for field,delta in (('LIT101',-2.),('LIT101',2.),('FIT101',.02)):
        add(f'Slow bias {field} {delta:+g} per observation','sensors','malicious','drift',field=field,delta=delta)
    add('Frozen level during pumping','sensors','malicious','frozen',register=20,level=740.)
    add('Frozen level during filling','sensors','malicious','frozen',register=30,level=600.)
    add('Replay old level after plant changes','sensors','malicious','frozen',register=20,level=740.)
    add('Frozen flow after inlet closure','sensors','malicious','frozen_flow')
    for fault in ('empty','partial','disconnected','delayed','nonnumeric','nan','out_of_range'):
        add(f'Telemetry {fault}','faults','robustness','fault',fault=fault)
    for residual in (4.99,5.,5.01):
        if residual<=5:
            add(f'Level residual boundary {residual:g} mm','boundary','benign','normal',
                level=740.,register=20,value=0,steps=1,overrides={'LIT101':740.+residual})
        else:
            add(f'Level residual boundary {residual:g} mm','boundary','malicious','spoof',
                level=740.,register=100,steps=1,overrides={'LIT101':740.+residual})
    for residual in (.099,.1,.101):
        if residual<=.1:
            add(f'Flow residual boundary {residual:g} m3/h','boundary','benign','normal',
                level=740.,register=20,value=0,steps=1,overrides={'FIT101':residual})
        else:
            add(f'Flow residual boundary {residual:g} m3/h','boundary','malicious','spoof',
                level=740.,register=110,steps=1,overrides={'FIT101':residual})
    for mode in ('unsupported_function','invalid_value','sensor_write','unknown_register',
                 'zero_read_count','excess_read_count','other_stage_read','bad_protocol',
                 'bad_length','truncated'):
        add(f'Modbus {mode}','protocol','malicious','protocol',mode=mode)
    add('Valid fragmented TCP request','protocol','benign','fragments')
    add('Two requests on persistent TCP connection','protocol','benign','persistent_connection')
    for pattern in ('slow','burst','concurrent','multiple_sources'):
        add(f'Legitimate {pattern} clients','traffic','benign','traffic',pattern=pattern)
    add('Declared malicious read burst','traffic','malicious','burst_attack')
    for mode in ('exact','different_value','different_register','different_source'):
        add(f'Rule selectivity {mode}','rules','malicious' if mode in ('exact','different_source') else 'benign',
            'rule',mode=mode)
    add('Genuine telemetry recovery after sensor alarm','recovery','benign','recovery')
    add('Normal request after gateway restart','recovery','robustness','restart')
    add('Durable replay protection after restart','rules','malicious','restart_rule')
    add('Rule expiration and quarantine consistency','rules','robustness','expiry')
    add('Mock SCADA disconnect','faults','robustness','downstream')
    add('Rule export filesystem failure','faults','robustness','export_failure')
    add('Sustained draining detection and recovery','process','malicious','draining')
    # Append-only inventory: preserve the earlier 82 IDs and their criteria.
    for reg in (1,10,100,110,20,24,30):
        add(f'L1 register {reg} readback','normal','benign','readback',register=reg)
    for level in (0.,1.,50.):
        for pump in (20,24):
            add(f'Empty/very-low tank pump {pump} ON at {level:g} mm','process','malicious','hazard',
                level=level,register=pump,pumps=0,limit='low')
    for level in (0.,50.,100.):
        for pump in (20,24):
            add(f'Safe pump {pump} OFF at {level:g} mm','boundary','benign','normal',
                level=level,register=pump,value=0,steps=1)
    for fault in ('missing_flow','null','positive_infinity','negative_infinity','negative_level',
                  'negative_flow','infinite_flow','flow_string','boolean_level'):
        add(f'Telemetry {fault}','faults','robustness','fault',fault=fault)
    for fault in ('disconnected','nonnumeric','nan','missing_flow'):
        add(f'Recovery after telemetry {fault}','recovery','robustness','fault_recovery',fault=fault)
    for mode in ('fc0','fc5','fc15','fc23','fc255','p102_value65535','valve_value2',
                 'legacy_level_write','legacy_flow_write','scaled_flow_write',
                 'other_stage_write','read_gap','address65535','length0','length255',
                 'truncated_header','short_pdu','long_pdu'):
        add(f'Modbus {mode}','protocol','malicious','protocol',mode=mode)
    for unit in (0,2,255):
        add(f'Unconfigured unit ID {unit}','protocol','robustness','unit',unit=unit)
    add('Coalesced requests in one TCP send','protocol','benign','coalesced')
    add('Quarantined payload with changed transaction ID','rules','malicious','changed_tx')
    for field,delta in (('FIT101',-.02),('LIT101',.5),('LIT101',-.5)):
        add(f'Small gradual bias {field} {delta:+g}','sensors','malicious','drift',field=field,delta=delta)
    for overrides in ({'LIT101':700.,'FIT101':2.}, {'LIT101':740.,'FIT101':-.101}):
        add(f'Combined sensor spoof {overrides}','sensors','malicious','spoof',
            level=740.,register=100,steps=2,overrides=overrides)
    for level,reg in ((1199.9,30),(99.,20),(99.,24)):
        add(f'False normal telemetry concealing hazardous register {reg}','sensors','malicious','spoof_command',
            level=level,register=reg,overrides={'LIT101':740.,'FIT101':0.})
    return cases


def packet(tx,register=20,value=0,fc=6):
    return struct.pack('>HHHBBHH',tx,0,6,1,fc,register,value)


def low_level_prevention(initial_level,minimum_level):
    """Do not penalize an interlock for a low level that existed before it ran."""
    return minimum_level>=min(initial_level,100.)


def wire(address,request,source=None,fragments=False,half_close=False):
    start=time.monotonic()
    with socket.socket() as client:
        client.settimeout(5)
        if source: client.bind((source,0))
        client.connect(address)
        if fragments:
            client.sendall(request[:5]);time.sleep(.02);client.sendall(request[5:])
        else: client.sendall(request)
        if half_close: client.shutdown(socket.SHUT_WR)
        try: reply=receive_frame(client)
        except (EOFError,ConnectionResetError): reply=b''
    return reply,time.monotonic()-start


class Source:
    def __init__(self,lab,mode,**settings):
        self.lab,self.mode,self.settings=lab,mode,settings
        self.initial=lab.s.plant.snapshot()
    def read_state(self):
        truth=self.lab.s.plant.snapshot()
        values={k:truth[k] for k in ('LIT101','FIT101')}
        if self.mode=='drift':
            field=self.settings['field']
            values[field]=self.lab.p.state_manager.snapshot()[field]+self.settings['delta']
        elif self.mode=='frozen': values['LIT101']=self.initial['LIT101']
        elif self.mode=='frozen_flow': values['FIT101']=self.initial['FIT101']
        elif self.mode=='fault':
            fault=self.settings['fault']
            if fault=='empty': return {}
            if fault=='partial': return {'FIT101':truth['FIT101']}
            if fault=='disconnected': raise TimeoutError('Injected lab sensor disconnect')
            if fault=='delayed': time.sleep(.2)
            if fault=='nonnumeric': values['LIT101']='corrupted'
            if fault=='nan': values['LIT101']=float('nan')
            if fault=='out_of_range': values['LIT101']=1300.
            if fault=='missing_flow': return {'LIT101':truth['LIT101']}
            replacements={'null':('LIT101',None),'positive_infinity':('LIT101',float('inf')),
                'negative_infinity':('LIT101',-float('inf')),'negative_level':('LIT101',-1.),
                'negative_flow':('FIT101',-1.),'infinite_flow':('FIT101',float('inf')),
                'flow_string':('FIT101','corrupted'),'boolean_level':('LIT101',True)}
            if fault in replacements:
                field,value=replacements[fault];values[field]=value
        return values


class Lab:
    def __init__(self,directory,p,s,g,model,profile):
        self.directory,self.p,self.s,self.g=directory,p,s,g
        self.model,self.profile=model,profile
        self.rows=[];self.next_tx=1000;self.extra=[]
    def close(self):
        for gateway,thread in self.extra:
            gateway.shutdown();gateway.server_close();thread.join(timeout=2)
    def initialize(self,level=None,actions=None,settle=False):
        if level is not None: self.p.digital_twin.state.lit101=level
        if actions:
            self.p.digital_twin.apply_actions(actions)
            if settle:self.p.digital_twin.step()
        self.p.state_manager.transition(self.p.digital_twin.snapshot())
        self.s.initialize_plant(self.p.digital_twin)
    def send(self,register=20,value=0,fc=6,request=None,source=None,fragments=False,half_close=False):
        if request is None:
            request=packet(self.next_tx,register,value,fc);self.next_tx+=1
        history=len(self.p.decision_history)
        events=len(self.p.telemetry_events)
        before=len(self.s.received)
        reply,elapsed=wire(self.g.server_address,request,source,fragments,half_close)
        with self.g.transaction_lock:
            received=len(self.s.received)-before
            assert received in (0,1),'Unexpected duplicate forwarding'
            decision=self.p.decision_history[-1]['decision'] if len(self.p.decision_history)>history else None
            detection=self.p.telemetry_events[-1].detection if len(self.p.telemetry_events)>events else {}
            model_features=self.p.telemetry_events[-1].model_features if len(self.p.telemetry_events)>events else {}
            error=bool(len(reply)>=9 and reply[7]&128)
            row=dict(request=request.hex(),reply=reply.hex(),elapsed_seconds=elapsed,
                     decision=decision,forwarded=bool(received),error_response=error,
                     blocked=decision=='BLOCK' and not received and error,
                     allowed=bool(reply) and not error and received==1,
                     detected=decision=='BLOCK' or bool(detection.get('is_anomaly')),
                     detection=detection,observed={k:model_features.get(k) for k in ('LIT101','FIT101')},
                     actual=self.s.plant.snapshot(),spill_m3=self.s.plant.state.stage1_spill_m3,
                     rule_generated=self.p.snort_rule_manager.rules_path.exists())
            self.rows.append(row)
            return row
    def seed_rule(self):
        self.initialize(620.,{'p101':0,'p102':0,'mv101':0})
        row=self.send(20,1)
        if not row['blocked'] or not row['rule_generated']:
            raise RuntimeError('Rule setup failed with actual trained model')
        return row
    def restart(self):
        self.g.shutdown();self.g.server_close()
        self.p=IntegrationOrchestrator(detector_model_path=str(self.model),firewall_enabled=False,
            snort_blocking=True,snort_rules_path=str(self.directory/'snort.rules'))
        self.p.digital_twin.params=load_profile(self.profile,self.p.anomaly_detector)
        self.g=ModbusGateway(('127.0.0.1',0),self.s.server_address,self.p,
            telemetry_file=self.directory/'restart-telemetry.jsonl',
            emergency_hook=self.s.apply_emergency_actions,stage1_guards=True)
        self.s.initialize_plant(self.p.digital_twin)
        thread=serve(self.g);self.extra.append((self.g,thread))


def run_case(case,lab):
    p=case['parameters'];kind=case['kind'];details={}
    if p.get('overrides') is not None:
        lab.p.stage1_connector=MockStage1TelemetrySource(lab.s,p['overrides'])
    if kind=='normal':
        rows=[lab.send(p['register'],p.get('value',1)) for _ in range(p['steps'])]
        return all(r['allowed'] for r in rows) and lab.s.plant.state.stage1_spill_m3==0,details
    if kind=='readback':
        from modbus_gateway import sensor_registers
        snapshot=lab.s.plant.snapshot()
        expected={**sensor_registers(snapshot),20:snapshot['p101'],24:snapshot['p102'],30:snapshot['mv101']}[p['register']]
        row=lab.send(p['register'],1,fc=3);reply=bytes.fromhex(row['reply'])
        actual=struct.unpack('>H',reply[9:11])[0] if len(reply)==11 and reply[7:9]==b'\x03\x02' else None
        details.update(expected=expected,returned=actual)
        return row['allowed'] and reply[:2]==bytes.fromhex(row['request'])[:2] and actual==expected,details
    if kind=='unit':
        request=packet(7100);request=request[:6]+bytes([p['unit']])+request[7:]
        row=lab.send(request=request)
        return not row['forwarded'] and (row['error_response'] or not row['reply']),details
    if kind=='coalesced':
        requests=[packet(8100),packet(8101,30,0)];before=len(lab.s.received)
        with socket.create_connection(lab.g.server_address,timeout=5) as client:
            client.settimeout(5);client.sendall(b''.join(requests))
            replies=[receive_frame(client),receive_frame(client)]
        with lab.g.transaction_lock:
            details.update(requests=[r.hex() for r in requests],replies=[r.hex() for r in replies],
                           forwarded=len(lab.s.received)-before)
        return replies==requests and lab.s.received[before:]==requests,details
    if kind=='fault_recovery':
        lab.p.stage1_connector=Source(lab,'fault',fault=p['fault']);bad=lab.send(100,1,fc=3)
        lab.p.stage1_connector=MockStage1TelemetrySource(lab.s);good=lab.send(100,1,fc=3)
        details.update(fault_fail_closed=bad['error_response'] and not bad['forwarded'],recovered=good['allowed'])
        return details['fault_fail_closed'] and details['recovered'],details
    if kind=='changed_tx':
        lab.seed_rule();lab.initialize(740.,{'p101':0,'p102':0,'mv101':0})
        attack=lab.send(request=packet(65535,20,1));benign=lab.send(20,0)
        return attack['blocked'] and benign['allowed'],details
    if kind=='spoof_command':
        row=lab.send(p['register'],1)
        details.update(prevented=not row['forwarded'],actual_level=row['actual']['LIT101'],spill_m3=row['spill_m3'])
        return row['blocked'] and row['spill_m3']==0 and low_level_prevention(p['level'],row['actual']['LIT101']),details
    if kind in ('changeover','reversal'):
        sequence=([(p['first'],1),(p['first'],0),(p['second'],1),(p['second'],0)]
                  if kind=='changeover' else [(20,i%2) for i in range(10)])
        return all(lab.send(reg,value)['allowed'] for reg,value in sequence),details
    if kind=='hazard':
        actions={'p101':int(p['pumps']>=1),'p102':int(p['pumps']>=2),'mv101':0}
        lab.initialize(p['level'],actions)
        blocked=None
        for step in range(1,9):
            row=lab.send(p['register'],1)
            if row['blocked']: blocked=row;details['first_block_step']=step;break
        min_level=min([p['level']]+[r['actual']['LIT101'] for r in lab.rows])
        safe=(lab.s.plant.state.stage1_spill_m3==0 if p['limit']=='high' else low_level_prevention(p['level'],min_level))
        details.update(detected=bool(blocked),prevention_passed=safe,
                       minimum_level_mm=min_level,spill_m3=lab.s.plant.state.stage1_spill_m3,
                       low_level_limit_mm=100. if p['limit']=='low' else None)
        if blocked:
            details['replay_blocked']=lab.send(request=bytes.fromhex(blocked['request']))['blocked']
        return bool(blocked) and safe and details.get('replay_blocked',False),details
    if kind=='spoof':
        rows=[lab.send(p['register'],1,fc=3) for _ in range(p['steps'])]
        details.update(detected=any(r['detected'] for r in rows),
                       prevention_passed=all(r['blocked'] and bytes.fromhex(r['reply'])[7:]==b'\x83\x04' for r in rows))
        return details['prevention_passed'] and not any(r['rule_generated'] for r in rows),details
    if kind=='drift':
        lab.p.stage1_connector=Source(lab,'drift',**p)
        rows=[]
        for _ in range(20):
            row=lab.send(100 if p['field']=='LIT101' else 110,1,fc=3);rows.append(row)
            if row['blocked']:break
        details.update(detected=any(r['blocked'] for r in rows),first_block_step=next((i+1 for i,r in enumerate(rows) if r['blocked']),None),
                       final_observed=rows[-1]['observed'],actual=rows[-1]['actual'])
        return details['detected'],details
    if kind=='frozen':
        lab.p.stage1_connector=Source(lab,'frozen')
        rows=[]
        for _ in range(15):
            row=lab.send(p['register'],1);rows.append(row)
            if row['blocked']:break
        poll=lab.send(100,1,fc=3)
        mismatch=abs(lab.p.state_manager.snapshot()['LIT101']-lab.s.plant.snapshot()['LIT101'])
        specific=any(r['blocked'] and (r['detection'].get('sensor_issues') or
                     (r['detection'].get('is_anomaly') and
                      abs((r['observed']['LIT101'] or 0)-r['actual']['LIT101'])>5.)) for r in rows+[poll])
        details.update(detected=specific,
                       unrelated_command_blocked=any(r['blocked'] for r in rows) and not specific,
                       actual_level=lab.s.plant.snapshot()['LIT101'],twin_level=lab.p.state_manager.snapshot()['LIT101'],
                       residual_after_sequence_mm=mismatch)
        return details['detected'],details
    if kind=='frozen_flow':
        lab.initialize(600.,{'mv101':1},settle=True)
        lab.p.stage1_connector=Source(lab,'frozen_flow')
        closing=lab.send(30,0);poll=lab.send(110,1,fc=3)
        details.update(detected=poll['blocked'],closing_allowed=closing['allowed'])
        return closing['allowed'] and poll['blocked'],details
    if kind=='fault':
        lab.p.stage1_connector=Source(lab,'fault',fault=p['fault'])
        row=lab.send(100,1,fc=3)
        details.update(elapsed_seconds=row['elapsed_seconds'],freshness_requirement_seconds=.1,
                       fail_closed=row['error_response'] and not row['forwarded'])
        passed=details['fail_closed'] and (row['elapsed_seconds']<.1 if p['fault']=='delayed' else True)
        return passed,details
    if kind=='protocol':
        mode=p['mode'];request=packet(7000)
        if mode=='unsupported_function':request=packet(7000,20,0,16)
        if mode=='invalid_value':request=packet(7000,20,2)
        if mode=='sensor_write':request=packet(7000,100,999)
        if mode=='unknown_register':request=packet(7000,999,1)
        if mode=='zero_read_count':request=packet(7000,100,0,3)
        if mode=='excess_read_count':request=packet(7000,100,126,3)
        if mode=='other_stage_read':request=packet(7000,120,1,3)
        if mode=='bad_protocol':request=request[:2]+b'\x00\x01'+request[4:]
        if mode=='bad_length':request=request[:4]+b'\x00\x01'+request[6:]
        if mode=='truncated':request=request[:9]
        functions={'fc0':0,'fc5':5,'fc15':15,'fc23':23,'fc255':255}
        if mode in functions:request=packet(7000,20,0,functions[mode])
        variants={'p102_value65535':(24,65535,6),'valve_value2':(30,2,6),
                  'legacy_level_write':(1,700,6),'legacy_flow_write':(10,3,6),
                  'scaled_flow_write':(110,2000,6),'other_stage_write':(21,1,6),
                  'read_gap':(100,2,3),'address65535':(65535,1,3)}
        if mode in variants:request=packet(7000,*variants[mode])
        if mode in ('length0','length255'):request=request[:4]+struct.pack('>H',0 if mode=='length0' else 255)+request[6:]
        if mode=='truncated_header':request=request[:4]
        if mode=='short_pdu':request=request[:4]+b'\x00\x03'+request[6:9]
        if mode=='long_pdu':request=request[:4]+b'\x00\x07'+request[6:]+b'\x00'
        row=lab.send(request=request,half_close=mode in ('truncated','truncated_header'))
        rejected=not row['forwarded'] and (row['error_response'] or not row['reply'])
        follow=lab.send(20,0)
        details.update(protocol_rejected=rejected,valid_followup_allowed=follow['allowed'],
                       rejection_layer='protocol validation; not ML')
        return rejected and follow['allowed'],details
    if kind=='fragments':
        return lab.send(20,0,fragments=True)['allowed'],details
    if kind=='persistent_connection':
        requests=[packet(8000),packet(8001,30,0)]
        before=len(lab.s.received)
        with socket.create_connection(lab.g.server_address,timeout=5) as client:
            client.settimeout(5)
            replies=[]
            for request in requests:
                client.sendall(request);replies.append(receive_frame(client))
        with lab.g.transaction_lock:
            details.update(requests=[r.hex() for r in requests],replies=[r.hex() for r in replies],
                           forwarded=len(lab.s.received)-before)
        return requests==replies and details['forwarded']==2,details
    if kind in ('traffic','burst_attack'):
        pattern=p.get('pattern','burst');count=20 if pattern in ('burst','concurrent') or kind=='burst_attack' else 4
        requests=[packet(9000+i,100,1,3) if kind=='burst_attack' else packet(9000+i) for i in range(count)]
        before=len(lab.s.received);start=len(lab.p.telemetry_events)
        def worker(item):
            i,request=item
            source=('127.0.0.2' if i%2==0 else '127.0.0.3') if pattern=='multiple_sources' else None
            return wire(lab.g.server_address,request,source)
        if pattern=='concurrent':
            with ThreadPoolExecutor(max_workers=8) as executor: replies=list(executor.map(worker,enumerate(requests)))
        else:
            replies=[]
            for item in enumerate(requests):
                replies.append(worker(item))
                if pattern=='slow':time.sleep(.1)
        with lab.g.transaction_lock:
            events=lab.p.telemetry_events[start:]
            forwarded=len(lab.s.received)-before
            detected=any(e.detection.get('actionable_command') or e.detection.get('is_anomaly') for e in events)
            match=(Counter(lab.s.received[before:])==Counter(requests))
            response_ok=all(reply and reply[:2]==request[:2] and not reply[7]&128 and
                            (request[7]!=6 or reply==request) for request,(reply,_) in zip(requests,replies))
            isolated=all(e.network_statistics['unique_src_ips']==1 for e in events)
            if pattern=='multiple_sources': isolated &= {'127.0.0.2','127.0.0.3'}<=set(lab.g._source_packets)
            details.update(requests=count,forwarded=forwarded,model_or_guard_alarm=detected,
                           source_windows_isolated=isolated,max_response_seconds=max(t for _,t in replies))
            return (detected and forwarded<count if kind=='burst_attack' else
                    forwarded==count and match and response_ok and isolated and len(events)==count),details
    if kind in ('rule','restart_rule','expiry'):
        seeded=lab.seed_rule();lab.initialize(740.,{'p101':0,'p102':0,'mv101':0})
        if kind=='restart_rule':
            lab.restart();row=lab.send(request=bytes.fromhex(seeded['request']))
            details.update(rule_file_retained=lab.p.snort_rule_manager.rules_path.exists(),replay_blocked=row['blocked'])
            return row['blocked'],details
        if kind=='expiry':
            manager=lab.p.snort_rule_manager
            manager._rule_expiry={k:datetime.now(timezone.utc)-timedelta(seconds=1) for k in manager._rule_expiry}
            manager.write();row=lab.send(20,1)
            details.update(rule_file_expired='drop tcp' not in manager.rules_path.read_text(),
                           safe_command_allowed=row['allowed'])
            return details['rule_file_expired'] and row['allowed'],details
        mode=p['mode']
        row=(lab.send(request=bytes.fromhex(seeded['request']),source='127.0.0.3' if mode=='different_source' else None)
             if mode in ('exact','different_source') else lab.send(20 if mode=='different_value' else 24,0 if mode=='different_value' else 1))
        return row['blocked'] if mode in ('exact','different_source') else row['allowed'],details
    if kind=='recovery':
        source=MockStage1TelemetrySource(lab.s,{'LIT101':100.});lab.p.stage1_connector=source
        rejected=lab.send(100,1,fc=3);source.overrides={};restored=lab.send(100,1,fc=3)
        details.update(forged_read_rejected=rejected['blocked'],genuine_read_allowed=restored['allowed'])
        return rejected['blocked'] and restored['allowed'],details
    if kind=='restart':
        lab.restart();return lab.send(20,0)['allowed'],details
    if kind=='downstream':
        before=lab.p.digital_twin.snapshot();lab.s.shutdown();lab.s.server_close()
        row=lab.send(20,1)
        details.update(state_rolled_back=lab.p.digital_twin.snapshot()==before)
        return row['error_response'] and not row['forwarded'] and details['state_rolled_back'],details
    if kind=='export_failure':
        obstruction=lab.directory/'not-a-directory';obstruction.write_text('injected lab filesystem fault')
        lab.p.snort_rule_manager.rules_path=obstruction/'snort.rules'
        lab.initialize(620.,{'p101':0,'p102':0,'mv101':0})
        row=lab.send(20,1)
        details.update(export_error_reported=any('error' in e for e in lab.p.enforcement_history))
        return row['blocked'] and details['export_error_reported'],details
    if kind=='draining':
        benign=packet(11000,20,0);first=lab.send(request=benign)
        blocked=None
        for step in range(1,301):
            row=lab.send(20,1)
            if row['blocked']:
                blocked=row;details['first_block_step']=step;break
        details.update(early_allowed=sum(r['allowed'] for r in lab.rows[1:]),
                       detected=bool(blocked),first_packet_prevention=bool(blocked) and details.get('first_block_step')==1)
        if not blocked:return False,details
        replay=lab.send(request=bytes.fromhex(blocked['request']));last=lab.send(request=benign)
        details.update(rule_generated=blocked['rule_generated'],replay_blocked=replay['blocked'],benign_after_allowed=last['allowed'])
        return first['allowed'] and blocked['rule_generated'] and replay['blocked'] and last['allowed'],details
    raise ValueError(f'Unknown case kind {kind}')


def outcome_matrix(results):
    eligible=[r for r in results if r['category'] in ('benign','malicious') and r['status']!='ERROR']
    cm=dict(tn=0,fp=0,fn=0,tp=0)
    for r in eligible:
        key=('tp' if r['passed'] else 'fn') if r['category']=='malicious' else ('tn' if r['passed'] else 'fp')
        cm[key]+=1
    def ratio(a,b):return a/b if b else 0.
    return dict(tests=len(eligible),confusion_matrix=cm,
        accuracy=ratio(cm['tp']+cm['tn'],len(eligible)),precision=ratio(cm['tp'],cm['tp']+cm['fp']),
        recall=ratio(cm['tp'],cm['tp']+cm['fn']),f1=ratio(2*cm['tp'],2*cm['tp']+cm['fp']+cm['fn']))


def render(path,result,total,robust):
    cm=result['confusion_matrix']
    svg=['<svg xmlns="http://www.w3.org/2000/svg" width="960" height="660" viewBox="0 0 960 660">',
        '<rect width="960" height="660" fill="#f8fafc"/>','<g font-family="sans-serif" fill="#172536" text-anchor="middle">',
        '<text x="480" y="40" font-size="26" font-weight="bold">L1 SCADA: test-level acceptance matrix</text>',
        f'<text x="480" y="76">{result["tests"]} benign/malicious security tests · one named case per count</text>',
        '<text x="400" y="126">Permitted / missed</text><text x="670" y="126">Rejected / detected</text>',
        '<text x="130" y="241">Benign tests</text><text x="130" y="416">Malicious tests</text>']
    for key,x,y in [('tn',270,150),('fp',545,150),('fn',270,325),('tp',545,325)]:
        passed=key in ('tn','tp');color='#c6e8dc' if passed else '#f7cec6'
        svg += [f'<rect x="{x}" y="{y}" width="255" height="160" rx="8" fill="{color}"/>',
                f'<text x="{x+127}" y="{y+43}" font-size="21">{key.upper()} · {"PASS" if passed else "FAIL"}</text>',
                f'<text x="{x+127}" y="{y+115}" font-size="46">{cm[key]}</text>']
    svg += [f'<text x="480" y="535">Security test pass rate {result["accuracy"]:.1%} · Precision {result["precision"]:.1%} · Recall {result["recall"]:.1%}</text>',
            f'<text x="480" y="572">{total} total cases; {robust} robustness/fault checks reported separately.</text>',
            '<text x="480" y="606" font-size="14">System acceptance outcomes, including protocol controls; not packet-level or ML-only accuracy.</text>',
            '<text x="480" y="637" font-size="14">Delayed detection and prevention are separate; local simulation, no deployed pfSense.</text>',
            '</g></svg>']
    path.write_text('\n'.join(svg))


def evaluate(output,model,profile):
    output.mkdir(parents=True,exist_ok=False)
    manifest=plans()
    (output/'case-manifest.json').write_text(json.dumps(dict(
        policy='Unchanged Stage1Guard: 60 s, 5 mm, 0.1 m3/h',low_level_oracle_mm=100.,
        declared_freshness_requirement_seconds=.1,cases=manifest),indent=2)+'\n')
    results=[]
    for case in manifest:
        directory=output/case['id']
        started=time.monotonic()
        rows=[];lab=None
        try:
            with session(directory,model,profile,case['parameters'].get('level'),stage1_guards=True) as (p,s,g):
                lab=Lab(directory,p,s,g,model,profile)
                try:
                    passed,details=run_case(case,lab)
                    status='PASS' if passed else 'FAIL'
                finally:
                    rows=lab.rows
                    lab.close()
            error=None
        except Exception as exc:
            passed=False;status='ERROR';details={};error=f'{type(exc).__name__}: {exc}'
            directory.mkdir(exist_ok=True)
            (directory/'execution-error.txt').write_text(traceback.format_exc())
        result={**case,'passed':bool(passed),'status':status,'details':details,'error':error,
                'elapsed_seconds':time.monotonic()-started,'serial_requests_recorded':len(rows)}
        (directory/'case-result.json').write_text(json.dumps(result,indent=2)+'\n')
        (directory/'wire-results.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
        results.append(result)
        print(f"{case['id']} {status}: {case['name']}"+(f' — {error}' if error else ''),flush=True)
    summary=dict(total=len(results),passed=sum(r['status']=='PASS' for r in results),
                 failed=sum(r['status']=='FAIL' for r in results),errors=sum(r['status']=='ERROR' for r in results))
    robustness=[r for r in results if r['category']=='robustness']
    report=dict(summary=summary,test_level_matrix=outcome_matrix(results),cases=results,
        process_sensor_security_matrix=outcome_matrix([r for r in results if r['kind']!='protocol']),
        areas={area:dict(total=sum(r['area']==area for r in results),
                        passed=sum(r['area']==area and r['passed'] for r in results),
                        failed=sum(r['area']==area and not r['passed'] for r in results))
               for area in sorted({r['area'] for r in results})},
        robustness_summary=dict(total=len(robustness),passed=sum(r['passed'] for r in robustness)),
        model_sha256=hashlib.sha256(model.read_bytes()).hexdigest(),
        profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest(),
        limitations=[
            'Cases and criteria are written before the run. This is a development acceptance suite, not independently sampled validation.',
            'Local TCP servers and a simulated plant; no Kali, physical PLC or pfSense enforcement.',
            'One named security test counts once. Robustness/fault cases and execution errors are reported separately from the matrix.',
            'Matrix includes protocol-permission controls as system defense, not ML detections.',
            'A delayed-detection pass does not establish first-packet prevention; its early allowed count is reported.',
            '100 mm low-level limit and 0.1 s freshness requirement are declared lab acceptance requirements, not plant-calibrated safety limits.',
            'Slow-client delays are short regressions; 20-request bursts and eight workers are not load-capacity benchmarks.',
            'The read-burst label declares stress intent; it is not proof of harmful DoS. Current process-only model has no network-rate input.',
            'Restart persistence and coherent expiry are desired security requirements; current gateway quarantine is in memory.',
            'No model scores or decisions are mocked; only sensor and I/O fault boundaries are injected.',
            'No production model, guard settings, firewall settings or existing live listener are modified.',
            'A matrix from this broader case population is not directly comparable to the earlier 15-case pass rate.',
            'Not run: physical PLC/sensor/actuator faults, installed Snort/pfSense enforcement, Kali/VM reboot/network partitions, timestamp-authenticated telemetry replay, long-duration capacity/fuzzing, held-out attack captures and plant calibration. See docs/l1-comprehensive-testing.md.',
        ])
    (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    render(output/'test-confusion-matrix.svg',report['test_level_matrix'],len(results),len(robustness))
    lines=['# Expanded L1 SCADA acceptance report','',
        f"{summary['total']} cases: {summary['passed']} PASS, {summary['failed']} FAIL, {summary['errors']} execution errors.",
        '', f"Security matrix ({report['test_level_matrix']['tests']} named tests): " +
        ', '.join(f'{key.upper()}={value}' for key,value in report['test_level_matrix']['confusion_matrix'].items())+'.',
        f"Robustness checks: {len(robustness)} total, {sum(r['passed'] for r in robustness)} passed.",
        '', 'Each named case counts once; its request count does not determine its matrix weight.',
        'Robustness/fault cases are included in the overall pass/fail total but excluded from the binary security matrix.',
        '', '| ID | Area | Category | Test | Result | Observations |','| --- | --- | --- | --- | --- | --- |']
    for r in results:
        description=json.dumps(r['details'],ensure_ascii=False).replace('|','/') if not r['error'] else r['error']
        lines.append(f"| {r['id']} | {r['area']} | {r['category']} | {r['name']} | {r['status']} | {description} |")
    lines += ['', '## Matrix definition','',
        '- TN: benign acceptance test passed; FP: benign test failed.',
        '- TP: malicious acceptance test passed its declared detection/prevention requirement; FN: malicious test failed.',
        '- Protocol defenses are included as system controls, not ML performance.',
        '- Delayed draining detection has its own explicit bounded criterion. Early requests are disclosed; prevention is not inferred.',
        '- Execution errors are not counted as successful detections and are reported separately.',
        '', '## Limitations','']+['- '+x for x in report['limitations']]
    (output/'TEST-REPORT.md').write_text('\n'.join(lines)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--model',type=Path,default=Path('validation/swat-stage1/model/detector_candidate.pkl'))
    parser.add_argument('--profile',type=Path,default=Path('validation/swat-stage1/profile.json'))
    args=parser.parse_args()
    result=evaluate(args.output,args.model,args.profile)
    print(json.dumps(dict(summary=result['summary'],matrix=result['test_level_matrix']),indent=2))
