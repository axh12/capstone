"""
Firewall Manager
================
Manages firewall rules based on anomaly detection results and extracted signatures.
Supports both iptables-based and rule-database approaches.
"""

import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


class FirewallRule:
    """Container for a firewall rule."""
    
    def __init__(
        self,
        rule_id: str,
        action: str,  # 'BLOCK' or 'ALLOW'
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        port: Optional[int] = None,
        protocol: str = 'tcp',
        reason: str = '',
        timestamp: Optional[datetime] = None,
        expiration: Optional[datetime] = None
    ):
        self.rule_id = rule_id
        self.action = action
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = port
        self.protocol = protocol
        self.reason = reason
        self.timestamp = timestamp or datetime.now()
        self.expiration = expiration
        self.active = True
    
    def is_expired(self) -> bool:
        """Check if rule has expired."""
        if self.expiration is None:
            return False
        return datetime.now() > self.expiration
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'rule_id': self.rule_id,
            'action': self.action,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'port': self.port,
            'protocol': self.protocol,
            'reason': self.reason,
            'timestamp': self.timestamp.isoformat(),
            'expiration': self.expiration.isoformat() if self.expiration else None,
            'active': self.active
        }
    
    def to_iptables_command(self) -> Optional[str]:
        """Convert to iptables command."""
        if not self.active or self.is_expired():
            return None
        
        chain = 'DROP' if self.action == 'BLOCK' else 'ACCEPT'
        
        # Build iptables rule
        cmd = f"iptables -A OUTPUT -j {chain}"
        
        if self.src_ip:
            cmd += f" -s {self.src_ip}"
        if self.dst_ip:
            cmd += f" -d {self.dst_ip}"
        if self.port:
            cmd += f" -p {self.protocol} --dport {self.port}"
        elif self.protocol:
            cmd += f" -p {self.protocol}"
        
        cmd += f" -m comment --comment '{self.reason}'"
        return cmd


class FirewallManager:
    """Manages firewall rules and their application."""
    
    def __init__(self, use_iptables: bool = False, dry_run: bool = True):
        """
        Initialize firewall manager.
        
        Args:
            use_iptables: If True, apply rules via iptables (requires root)
            dry_run: If True, don't actually apply rules (safe for testing)
        """
        self.use_iptables = use_iptables
        self.dry_run = dry_run
        self.rules: Dict[str, FirewallRule] = {}
        self.rule_counter = 0
        self.blocked_ips = set()
        self.blocked_pairs = set()  # (src, dst) pairs
    
    def add_rule(self, rule: FirewallRule) -> str:
        """
        Add a firewall rule.
        
        Args:
            rule: FirewallRule object
            
        Returns:
            Rule ID
        """
        if not rule.rule_id:
            rule.rule_id = f"rule_{self.rule_counter}"
            self.rule_counter += 1
        
        self.rules[rule.rule_id] = rule
        self._track_blocked_target(rule)
        
        print(f"📋 Added rule {rule.rule_id}: {rule.action} {rule.src_ip or 'any'} -> {rule.dst_ip or 'any'}")
        return rule.rule_id
    
    def block_ip(
        self,
        ip_address: str,
        reason: str = '',
        duration_seconds: Optional[int] = None
    ) -> str:
        """
        Block traffic from/to an IP address.
        
        Args:
            ip_address: IP to block
            reason: Reason for blocking
            duration_seconds: How long to block (None = permanent)
            
        Returns:
            Rule ID
        """
        expiration = None
        if duration_seconds:
            expiration = datetime.now() + timedelta(seconds=duration_seconds)
        
        rule = FirewallRule(
            rule_id=f"block_ip_{self.rule_counter}",
            action='BLOCK',
            src_ip=ip_address,
            reason=reason or f"Anomaly detected: {ip_address}",
            expiration=expiration
        )
        
        return self.add_rule(rule)
    
    def block_ip_pair(
        self,
        src_ip: str,
        dst_ip: str,
        reason: str = '',
        duration_seconds: Optional[int] = None
    ) -> str:
        """
        Block traffic from specific source to specific destination.
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            reason: Reason for blocking
            duration_seconds: How long to block
            
        Returns:
            Rule ID
        """
        expiration = None
        if duration_seconds:
            expiration = datetime.now() + timedelta(seconds=duration_seconds)
        
        rule = FirewallRule(
            rule_id=f"block_pair_{self.rule_counter}",
            action='BLOCK',
            src_ip=src_ip,
            dst_ip=dst_ip,
            reason=reason or f"Anomalous traffic: {src_ip} -> {dst_ip}",
            expiration=expiration
        )
        
        return self.add_rule(rule)
    
    def block_port(
        self,
        port: int,
        protocol: str = 'tcp',
        reason: str = '',
        duration_seconds: Optional[int] = None
    ) -> str:
        """
        Block traffic on a specific port.
        
        Args:
            port: Port number to block
            protocol: 'tcp' or 'udp'
            reason: Reason for blocking
            duration_seconds: Duration
            
        Returns:
            Rule ID
        """
        expiration = None
        if duration_seconds:
            expiration = datetime.now() + timedelta(seconds=duration_seconds)
        
        rule = FirewallRule(
            rule_id=f"block_port_{port}_{self.rule_counter}",
            action='BLOCK',
            port=port,
            protocol=protocol,
            reason=reason or f"Port {port} blocked due to anomaly",
            expiration=expiration
        )
        
        return self.add_rule(rule)
    
    def extract_rules_from_signature(
        self,
        signature: Dict
    ) -> List[str]:
        """
        Extract firewall rules from attack signature.
        
        Args:
            signature: Dictionary with signature information from SEM
                      Expected keys: 'src_ips', 'dst_ips', 'ports', 'attack_type'
            
        Returns:
            List of rule IDs created
        """
        rule_ids = []
        attack_type = signature.get('attack_type', 'UNKNOWN')
        
        # Block anomalous source IPs
        for src_ip in signature.get('src_ips', [])[:5]:  # Limit to top 5
            rid = self.block_ip(
                src_ip,
                reason=f"Attack detected: {attack_type}",
                duration_seconds=300  # 5 minutes
            )
            rule_ids.append(rid)
        
        # Block anomalous destination IPs
        for dst_ip in signature.get('dst_ips', [])[:5]:
            rid = self.block_ip(
                dst_ip,
                reason=f"Attack detected: {attack_type}",
                duration_seconds=300
            )
            rule_ids.append(rid)
        
        # Block anomalous ports
        for port in signature.get('ports', [])[:3]:
            rid = self.block_port(
                int(port),
                reason=f"Attack detected: {attack_type}",
                duration_seconds=300
            )
            rule_ids.append(rid)
        
        # Block anomalous IP pairs
        for pair in signature.get('ip_pairs', [])[:5]:
            src, dst = pair.split('_') if '_' in pair else (None, None)
            if src and dst:
                rid = self.block_ip_pair(
                    src, dst,
                    reason=f"Attack detected: {attack_type}",
                    duration_seconds=300
                )
                rule_ids.append(rid)
        
        return rule_ids
    
    def apply_rules(self) -> Tuple[int, List[str]]:
        """
        Apply active firewall rules.
        
        Returns:
            Tuple of (num_rules_applied, error_messages)
        """
        errors = []
        applied_count = 0
        
        for rule_id, rule in self.rules.items():
            if not rule.active or rule.is_expired():
                continue
            
            if self.use_iptables:
                cmd = rule.to_iptables_command()
                if cmd:
                    if self.dry_run:
                        print(f"[DRY RUN] {cmd}")
                    else:
                        try:
                            subprocess.run(cmd, shell=True, check=True,
                                         capture_output=True, timeout=5)
                        except Exception as e:
                            errors.append(f"Rule {rule_id} failed: {str(e)}")
                    applied_count += 1
            else:
                # Database mode
                if self.dry_run:
                    print(f"[DRY RUN] Would apply rule {rule_id}: {rule.to_dict()}")
                else:
                    print(f"Applied rule {rule_id}: {rule.to_dict()}")
                applied_count += 1
        
        return applied_count, errors
    
    def revoke_rule(self, rule_id: str) -> bool:
        """
        Revoke a firewall rule.
        
        Args:
            rule_id: ID of rule to revoke
            
        Returns:
            True if successful
        """
        if rule_id not in self.rules:
            return False
        
        rule = self.rules[rule_id]
        rule.active = False
        print(f"🚫 Revoked rule {rule_id}")
        return True
    
    def cleanup_expired_rules(self) -> int:
        """
        Remove expired rules from the system.
        
        Returns:
            Number of rules removed
        """
        to_remove = [
            rid for rid, rule in self.rules.items()
            if rule.is_expired()
        ]
        
        for rid in to_remove:
            del self.rules[rid]
        
        if to_remove:
            print(f"🧹 Cleaned up {len(to_remove)} expired rules")
        
        return len(to_remove)
    
    def get_active_rules(self) -> List[Dict]:
        """Get all active rules."""
        return [
            rule.to_dict()
            for rule in self.rules.values()
            if rule.active and not rule.is_expired()
        ]
    
    def get_rule_statistics(self) -> Dict:
        """Get statistics about current rules."""
        active = [r for r in self.rules.values() if r.active and not r.is_expired()]
        
        return {
            'total_rules': len(self.rules),
            'active_rules': len(active),
            'blocked_ips': len(self.blocked_ips),
            'blocked_pairs': len(self.blocked_pairs),
            'block_rules': len([r for r in active if r.action == 'BLOCK']),
            'allow_rules': len([r for r in active if r.action == 'ALLOW'])
        }
    
    def _track_blocked_target(self, rule: FirewallRule) -> None:
        """Track blocked IPs and pairs for statistics."""
        if rule.action == 'BLOCK':
            if rule.src_ip and not rule.dst_ip:
                self.blocked_ips.add(rule.src_ip)
            if rule.dst_ip and not rule.src_ip:
                self.blocked_ips.add(rule.dst_ip)
            if rule.src_ip and rule.dst_ip:
                self.blocked_pairs.add((rule.src_ip, rule.dst_ip))
    
    def export_rules(self, filepath: str) -> None:
        """Export rules to JSON file."""
        rules_data = {
            'timestamp': datetime.now().isoformat(),
            'rules': [rule.to_dict() for rule in self.rules.values()],
            'statistics': self.get_rule_statistics()
        }
        
        with open(filepath, 'w') as f:
            json.dump(rules_data, f, indent=2)
        
        print(f"📤 Exported rules to {filepath}")
    
    def import_rules(self, filepath: str) -> int:
        """Import rules from JSON file."""
        with open(filepath, 'r') as f:
            rules_data = json.load(f)
        
        count = 0
        for rule_dict in rules_data.get('rules', []):
            rule = FirewallRule(**rule_dict)
            self.add_rule(rule)
            count += 1
        
        print(f"📥 Imported {count} rules from {filepath}")
        return count
