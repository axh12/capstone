"""Execute the PHP helper with stubbed pfSense APIs in temporary directories."""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from snort_integration import SnortRuleManager

PHP = os.environ.get('CAPSTONE_PHP') or shutil.which('php')


@unittest.skipUnless(PHP, 'PHP CLI required to execute pfSense helper harness')
class PfsenseHelperTests(unittest.TestCase):
    def run_helper(self, payload, existing='', mode='legacy', failure=''):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            conf_dir = root/'snort_123_em0'
            conf_dir.mkdir()
            (root/'state.json').write_text(json.dumps({'customrules': existing}))
            stub = root/'stub.php'
            stub.write_text('''<?php
define('SNORTDIR', __DIR__);
$state = json_decode(file_get_contents(__DIR__.'/state.json'), true);
$instances = [['interface'=>'wan', 'uuid'=>'123', 'ips_mode'=>getenv('TEST_MODE') === 'inline' ? 'ips_mode_inline' : 'legacy', 'blockoffenders7'=>'on', 'customrules'=>base64_encode($state['customrules'])]];
$reloads=0;
function config_get_path($path,$default=[]) { global $instances; return $instances; }
function config_set_path($path,$values) { global $instances; $instances=$values; }
function get_real_interface($interface) { return 'em0'; }
function snort_is_running($uuid) { return true; }
function snort_generate_conf($instance) { file_put_contents(__DIR__.'/snort_123_em0/snort.conf', base64_decode($instance['customrules'])); }
function write_config($message) { global $instances; file_put_contents(__DIR__.'/saved.json',json_encode($instances)); }
function snort_reload_config($instance) { global $reloads; $reloads++; file_put_contents(__DIR__.'/reloads', $reloads); if (getenv('TEST_FAILURE') === 'reload' && $reloads === 1) { throw new RuntimeException('reload failed'); } }
''')
            validator = root/'snort-validator'
            validator.write_text('#!/bin/sh\nif [ "$TEST_FAILURE" = validation ]; then exit 1; fi\nexit 0\n')
            validator.chmod(0o700)
            original = Path(__file__).resolve().parents[1]/'pfsense_snort_apply.php'
            source = original.read_text()
            source = source.replace("require_once('/etc/inc/config.inc');", 'require_once('+json.dumps(str(stub))+');')
            source = source.replace("require_once('/etc/inc/interfaces.inc');", '')
            source = source.replace("require_once('/usr/local/pkg/snort/snort.inc');", '')
            source = source.replace('/var/run/capstone-snort.lock', str(root/'lock'))
            source = source.replace('/conf/capstone-backups', str(root/'backups'))
            source = source.replace('/usr/local/bin/snort', str(validator))
            helper = root/'helper.php'
            helper.write_text(source)
            env=dict(os.environ, TEST_MODE=mode, TEST_FAILURE=failure)
            completed=subprocess.run([PHP,'-n',str(helper)],input=json.dumps(payload),
                text=True,capture_output=True,env=env,timeout=10)
            self.assertTrue(completed.stdout.strip(), completed.stderr)
            result=json.loads(completed.stdout.strip().splitlines()[-1])
            generated=(conf_dir/'snort.conf').read_text() if (conf_dir/'snort.conf').exists() else None
            saved=json.loads((root/'saved.json').read_text()) if (root/'saved.json').exists() else None
            return result, generated, saved, completed.returncode

    def rule(self, blocking=False, register=20):
        return SnortRuleManager(blocking=blocking).rules_from_signature(
            {'modbus_commands':[{'function':6,'register':register,'value':1}]})[0]

    def payload(self, blocking=False):
        return {'operation':'apply','interface':'wan','mode':'inline' if blocking else 'legacy',
                'rules':[self.rule(blocking)]}

    def test_inspection_does_not_write_config_or_rules(self):
        result, generated, saved, code=self.run_helper({'operation':'inspect','interface':'wan'})
        self.assertEqual(code,0)
        self.assertEqual(result['device'],'em0')
        self.assertIsNone(generated)
        self.assertIsNone(saved)

    def test_applies_and_preserves_unrelated_custom_rule(self):
        existing='alert tcp any any -> any 80 (msg:"Existing"; sid:99;)\n'
        result, generated, saved, code=self.run_helper(self.payload(),existing)
        self.assertEqual(code,0)
        self.assertTrue(result['ok'])
        self.assertIn(existing.strip(),generated)
        self.assertIn(self.rule(),generated)
        self.assertEqual(len(saved),1)

    def test_unknown_sid_collision_refused(self):
        existing='alert tcp any any -> any 80 (msg:"Unrelated"; sid:1781355;)\n'
        result,generated,saved,code=self.run_helper(self.payload(),existing)
        self.assertEqual(code,1)
        self.assertIn('conflicts',result['error'])
        self.assertIsNone(saved)

    def test_mode_mismatch_refused(self):
        result,_,saved,code=self.run_helper(self.payload(True))
        self.assertEqual(code,1)
        self.assertIsNone(saved)

    def test_validation_failure_restores_old_generated_rules(self):
        existing='# original rules\n'
        result,generated,saved,code=self.run_helper(self.payload(),existing,failure='validation')
        self.assertEqual(code,1)
        self.assertFalse(result['ok'])
        self.assertEqual(generated,existing)
        self.assertIsNone(saved)
        self.assertIsNone(result['rollback_error'])

    def test_reload_failure_restores_saved_and_generated_rules(self):
        existing='# original rules\n'
        result,generated,saved,code=self.run_helper(self.payload(),existing,failure='reload')
        self.assertEqual(code,1)
        self.assertEqual(generated,existing)
        import base64
        self.assertEqual(base64.b64decode(saved[0]['customrules']).decode(),existing)
        self.assertIsNone(result['rollback_error'])

    def test_existing_managed_rule_is_not_duplicated(self):
        existing='# outside\n# BEGIN CAPSTONE MANAGED\n'+self.rule()+'\n# END CAPSTONE MANAGED\n'
        result,generated,_,code=self.run_helper(self.payload(),existing)
        self.assertEqual(code,0)
        self.assertFalse(result['changed'])
        self.assertIsNone(generated)

    def test_new_rule_accumulates_with_rule_from_previous_run(self):
        old_rule=self.rule(blocking=True,register=20)
        new_rule=self.rule(blocking=True,register=23)
        existing='# outside\n# BEGIN CAPSTONE MANAGED\n'+old_rule+'\n# END CAPSTONE MANAGED\n'
        payload={'operation':'apply','interface':'wan','mode':'inline','rules':[new_rule]}
        result,generated,_,code=self.run_helper(payload,existing,mode='inline')
        self.assertEqual(code,0)
        self.assertEqual(result['rules'],2)
        self.assertEqual(generated.count(old_rule),1)
        self.assertEqual(generated.count(new_rule),1)
        self.assertIn('# outside',generated)

    def test_empty_apply_cannot_clear_persisted_rules(self):
        existing='# BEGIN CAPSTONE MANAGED\n'+self.rule()+'\n# END CAPSTONE MANAGED\n'
        payload={'operation':'apply','interface':'wan','mode':'legacy','rules':[]}
        result,generated,saved,code=self.run_helper(payload,existing)
        self.assertEqual(code,0)
        self.assertFalse(result['changed'])
        self.assertIsNone(generated)
        self.assertIsNone(saved)

    def test_explicit_clear_removes_only_managed_rules(self):
        existing='# outside\n# BEGIN CAPSTONE MANAGED\n'+self.rule()+'\n# END CAPSTONE MANAGED\n'
        payload={'operation':'clear_managed','interface':'wan','mode':'legacy','rules':[]}
        result,generated,_,code=self.run_helper(payload,existing)
        self.assertEqual(code,0)
        self.assertEqual(result['rules'],0)
        self.assertIn('# outside',generated)
        self.assertNotIn(self.rule(),generated)
        self.assertIn('# BEGIN CAPSTONE MANAGED\n\n# END CAPSTONE MANAGED',generated)

    def test_clear_refuses_attached_rules(self):
        payload={'operation':'clear_managed','interface':'wan','mode':'legacy',
                 'rules':[self.rule()]}
        result,_,saved,code=self.run_helper(payload)
        self.assertEqual(code,1)
        self.assertIn('cannot include rules',result['error'])
        self.assertIsNone(saved)

    def test_inline_accepts_drop_rule(self):
        result,generated,_,code=self.run_helper(self.payload(True),mode='inline')
        self.assertEqual(code,0)
        self.assertIn('drop tcp',generated)
