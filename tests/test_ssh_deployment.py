import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from deploy_snort_rules_ssh import SSHRuleDeployer, configure_deployment
from snort_integration import SnortRuleManager


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.deployer = SSHRuleDeployer({'host':'192.0.2.1', 'mode':'legacy'})
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = SnortRuleManager(str(Path(self.directory.name)/'custom.rules'))
        self.manager.export_signature({'modbus_commands':[{'function':6,'register':20,'value':1}]})

    def test_generated_rules_sent_as_json_without_shell_interpolation(self):
        with patch.object(self.deployer, 'request', return_value={'ok':True}) as request:
            self.deployer.deploy(self.manager.rules_path)
        payload = request.call_args.args[0]
        self.assertEqual(payload['operation'], 'apply')
        self.assertEqual(payload['mode'], 'legacy')
        self.assertTrue(payload['rules'][0].startswith('alert tcp any any'))

    def test_ip_only_rule_refused_before_contacting_pfsense(self):
        self.manager.rules_path.write_text('alert tcp 192.0.2.2 any -> any 5020 (sid:1;)\n')
        with patch.object(self.deployer, 'request') as request, self.assertRaises(ValueError):
            self.deployer.deploy(self.manager.rules_path)
        request.assert_not_called()

    def test_wrong_mode_refused(self):
        self.deployer.mode='inline'
        with self.assertRaises(ValueError):
            self.deployer.deploy(self.manager.rules_path)

    def test_strict_host_keys_and_noninteractive_ssh(self):
        options = self.deployer.command('ssh')
        self.assertIn('StrictHostKeyChecking=yes', options)
        self.assertIn('BatchMode=yes', options)

    def test_helper_cleanup_after_remote_failure(self):
        failure = subprocess.CalledProcessError(1, ['ssh'], output='validation failed', stderr='')
        with patch('deploy_snort_rules_ssh.subprocess.run', side_effect=[Mock(), failure, Mock()]) as run:
            with self.assertRaisesRegex(RuntimeError, 'validation failed'):
                self.deployer.inspect()
        self.assertEqual(run.call_count, 3)
        self.assertIn('rm -f /tmp/capstone-snort-', run.call_args.args[0][-1])

    def test_manager_reports_deployment_and_propagates_failure(self):
        self.manager.deployer=Mock(return_value={'ok':True})
        result=self.manager.export_signature({'modbus_commands':[{'function':6,'register':20,'value':1}]})
        self.assertTrue(result['applied'])
        self.manager.deployer.side_effect=RuntimeError('reload failed')
        with self.assertRaises(RuntimeError):
            self.manager.export_signature({'modbus_commands':[{'function':6,'register':21,'value':1}]})

    def test_configuration_does_not_enable_deployment_on_mismatched_mode(self):
        path=Path(self.directory.name)/'config.json'
        path.write_text(json.dumps({'host':'192.0.2.1','mode':'legacy'}))
        pipeline=Mock(snort_rule_manager=self.manager)
        with patch.object(SSHRuleDeployer,'inspect',return_value={'mode':'inline','running':True,'blocking':True}):
            with self.assertRaises(ValueError):
                configure_deployment(pipeline,path)
        self.assertIsNone(self.manager.deployer)

    def test_failed_deployment_keeps_gateway_block_decision_and_records_failure(self):
        from orchestrator import IntegrationOrchestrator
        from run_mock_lab import LabGateway
        from test_modbus_gateway import frame
        pipeline=IntegrationOrchestrator(firewall_enabled=False,
            snort_rules_path=str(Path(self.directory.name)/'failed.rules'))
        pipeline.snort_rule_manager.deployer=Mock(side_effect=RuntimeError('remote reload failed'))
        with LabGateway(('127.0.0.1',0),('127.0.0.1',1),pipeline) as gateway:
            with patch('modbus_gateway.socket.create_connection') as upstream:
                gateway.process_request_frame(frame(),('192.0.2.1',12345))
            upstream.assert_not_called()
        self.assertEqual(pipeline.decision_history[-1]['decision'],'BLOCK')
        self.assertFalse(pipeline.enforcement_history[-1]['applied'])
        self.assertIn('remote reload failed',pipeline.enforcement_history[-1]['error'])
