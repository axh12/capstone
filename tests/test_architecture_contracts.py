import unittest

from decision_engine import Decision, DecisionEngine
from physical_stage1 import NullStage1Connector
from snort_integration import SnortRuleManager
from state_manager import StateManager
from telemetry import TelemetryEvent


class FakeDetection:
    def __init__(self, anomaly):
        self.is_anomaly = anomaly


class ArchitectureContractTests(unittest.TestCase):
    def test_state_manager_rejects_invalid_process_state(self):
        manager = StateManager({"LIT101": 500.0})
        with self.assertRaises(ValueError):
            manager.apply_patch({"LIT101": 5000.0})

    def test_stage1_connector_is_read_only(self):
        self.assertEqual(NullStage1Connector().read_state(), {})
        self.assertFalse(hasattr(NullStage1Connector, "write_state"))

    def test_normal_discards_candidate(self):
        result = DecisionEngine().decide(FakeDetection(False), {"candidate": True}, "alert")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertIsNone(result.signature)

    def test_modbus_rule_does_not_use_source_ip(self):
        manager = SnortRuleManager("/tmp/contract.rules")
        rules = manager.rules_from_signature({
            "src_ips": ["192.168.56.10"],
            "dst_ips": ["192.168.58.10"],
            "ports": [5020],
            "modbus_commands": [{"function": 6, "register": 20, "value": 1}],
        })
        self.assertEqual(len(rules), 1)
        self.assertIn("tcp any any -> any 5020", rules[0])
        self.assertIn("06 00 14 00 01", rules[0])
        self.assertNotIn("192.168.56.10", rules[0])

    def test_telemetry_is_json_serializable(self):
        event = TelemetryEvent.create("test", process={"LIT101": 500.0})
        self.assertEqual(event.to_dict()["event_id"], "test")
        self.assertIn("LIT101", event.to_json())


if __name__ == "__main__":
    unittest.main()
