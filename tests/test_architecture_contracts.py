import unittest

from decision_engine import Decision, DecisionEngine
from physical_stage1 import (
    ArduinoSerialStage1Connector,
    ModbusBidirectionalStage1Connector,
    NullStage1Connector,
)
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

    def test_arduino_connector_parses_telemetry(self):
        state = {}
        connector = ArduinoSerialStage1Connector("/dev/null")
        connector._parse_line("Distance: 8 cm", state)
        connector._parse_line("Flow: 2.5 L/min", state)
        connector._parse_line("Pump: ON", state)
        self.assertEqual(state, {"LIT101": 8.0, "FIT101": 2.5, "p101": 1})

    def test_arduino_actuation_is_disabled_by_default(self):
        connector = ArduinoSerialStage1Connector("/dev/null")
        with self.assertRaises(PermissionError):
            connector.set_pump(True)

    def test_bidirectional_stage1_requires_separate_register_maps(self):
        with self.assertRaises(ValueError):
            ModbusBidirectionalStage1Connector(
                "192.0.2.10",
                state_register_map={"LIT101": 10},
                command_register_map={"p101": 10},
                enable_writeback=True,
            )

    def test_bidirectional_stage1_requires_state_map_for_writeback(self):
        with self.assertRaises(ValueError):
            ModbusBidirectionalStage1Connector(
                "192.0.2.10",
                command_register_map={"p101": 20},
                enable_writeback=True,
            )

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
