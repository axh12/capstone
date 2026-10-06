"""Translate detected network signatures into Snort custom rules.

The project deliberately keeps rule generation separate from pfSense's GUI
state.  The generated file can be reviewed/imported as ``custom.rules``.  An
optional, explicitly configured command may reload a local Snort installation
after the file is written.
"""

from __future__ import annotations

import ipaddress
import hashlib
import os
import shlex
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional


class SnortRuleManager:
    """Generate and persist conservative rules from network signatures."""

    def __init__(
        self,
        rules_path: str = "snort_custom.rules",
        blocking: bool = False,
        expiration_seconds: int = 300,
        apply_command: Optional[str] = None,
        allow_ip_fallback: bool = False,
    ) -> None:
        self.rules_path = Path(rules_path).expanduser()
        self.blocking = blocking
        self.expiration_seconds = expiration_seconds
        self.apply_command = apply_command
        # IP-only blocking is disabled by default to avoid false positives.
        self.allow_ip_fallback = allow_ip_fallback
        self._rules: Dict[str, str] = {}
        self._rule_expiry: Dict[str, datetime] = {}

    @staticmethod
    def _ip(value: str) -> str:
        """Validate an IPv4/IPv6 address before placing it in a rule."""
        return str(ipaddress.ip_address(value))

    @staticmethod
    def _ports(signature: Dict) -> Iterable[int]:
        for value in signature.get("ports", []):
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                yield port

    def rules_from_signature(self, signature: Dict) -> List[str]:
        """Return Snort rules for concrete source/destination/port tuples.

        A signature containing no concrete network indicators produces no
        packet rule; sensor-only statistical signatures must remain in the ML
        pipeline rather than becoming an unsafe catch-all rule.
        """
        # Prefer command-level Modbus signatures.  These match the protocol
        # payload and deliberately do not include a source IP.
        command_rules: List[str] = []
        for command in signature.get("modbus_commands", []):
            try:
                function = int(command["function"])
                register = int(command["register"])
                value = int(command["value"])
            except (KeyError, TypeError, ValueError):
                continue
            if not (0 <= function <= 255 and 0 <= register <= 65535 and 0 <= value <= 65535):
                continue
            if function != 6:  # FC06 = Write Single Register
                continue
            payload = bytes([function]) + register.to_bytes(2, "big") + value.to_bytes(2, "big")
            hex_payload = " ".join(f"{byte:02X}" for byte in payload)
            identity = f"MODBUS_FC{function}_REG{register}_VAL{value}".encode()
            sid = 1000000 + (int(hashlib.sha256(identity).hexdigest()[:8], 16) % 899999)
            action = "drop" if self.blocking else "alert"
            msg = f"Capstone Modbus write register {register} value {value}"
            command_rules.append(
                f'{action} tcp any any -> any 5020 (msg:"{msg}"; '
                f'flow:to_server,established; content:"|{hex_payload}|"; offset:7; depth:5; '
                f'sid:{sid}; rev:1;)'
            )
        if command_rules:
            for rule in command_rules:
                self._rules[rule] = rule
                self._rule_expiry[rule] = datetime.now(timezone.utc) + timedelta(seconds=self.expiration_seconds)
            return command_rules

        # Do not turn a statistical/sensor anomaly into an IP block.  A
        # command-level signature is required unless the caller explicitly
        # opts into the legacy tuple rule behavior.
        if not self.allow_ip_fallback:
            return []

        sources = []
        destinations = []
        for value in signature.get("src_ips", []):
            try:
                sources.append(self._ip(value))
            except ValueError:
                pass
        for value in signature.get("dst_ips", []):
            try:
                destinations.append(self._ip(value))
            except ValueError:
                pass
        ports = list(dict.fromkeys(self._ports(signature)))
        if not sources or not destinations or not ports:
            return []

        action = "drop" if self.blocking else "alert"
        attack_type = str(signature.get("attack_type", "UNKNOWN"))[:48]
        identity = repr((attack_type, tuple(sources), tuple(destinations), tuple(ports))).encode()
        sid_base = 1000000 + (int(hashlib.sha256(identity).hexdigest()[:8], 16) % 899999)
        generated: List[str] = []
        for offset, (src, dst, port) in enumerate(
            ( (src, dst, port) for src in sources for dst in destinations for port in ports )
        ):
            sid = sid_base + offset
            msg = f"Capstone {attack_type} {src}:{port}"
            # Snort messages cannot contain quotes or newlines.
            msg = msg.replace('"', "'").replace("\n", " ")
            rule = f'{action} tcp {src} any -> {dst} {port} (msg:"{msg}"; sid:{sid}; rev:1;)'
            self._rules[str(sid)] = rule
            generated.append(rule)
        return generated

    def write(self) -> Path:
        """Atomically write the current rule set and return its path."""
        self.cleanup_expired()
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        data = "# Generated by Capstone SnortRuleManager\n" + "\n".join(self._rules.values()) + "\n"
        fd, tmp_name = tempfile.mkstemp(prefix=".snort_custom.", dir=str(self.rules_path.parent), text=True)
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.rules_path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
        return self.rules_path

    def cleanup_expired(self) -> int:
        """Remove expired generated rules before the next deployment."""
        now = datetime.now(timezone.utc)
        expired = [key for key, deadline in self._rule_expiry.items() if deadline <= now]
        for key in expired:
            self._rule_expiry.pop(key, None)
            self._rules.pop(key, None)
        return len(expired)

    def apply(self) -> Optional[str]:
        """Run the explicitly configured reload command, if any."""
        if not self.apply_command:
            return None
        command = self.apply_command.replace("{rules_file}", shlex.quote(str(self.rules_path)))
        completed = subprocess.run(command, shell=True, check=True, text=True, capture_output=True, timeout=30)
        return completed.stdout.strip()

    def export_signature(self, signature: Dict) -> Dict:
        """Generate rules, persist them, and optionally reload Snort."""
        rules = self.rules_from_signature(signature)
        if not rules:
            return {"rules": [], "path": None, "applied": False, "reason": "no concrete network tuple"}
        path = self.write()
        output = self.apply()
        return {"rules": rules, "path": str(path), "applied": bool(self.apply_command), "command_output": output}
