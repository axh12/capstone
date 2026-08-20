"""
Network Integration Module
===========================
Captures packets from the network and provides them to the Digital Twin and feature extractor.
Uses scapy for packet sniffing or can work with pre-captured PCAP files.
"""

import threading
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠ Scapy not available. Install with: pip install scapy")


class PacketEvent:
    """Container for packet information."""
    
    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        size: int,
        timestamp: datetime,
        raw_data: Optional[bytes] = None
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.size = size
        self.timestamp = timestamp
        self.raw_data = raw_data
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'size': self.size,
            'timestamp': self.timestamp.isoformat()
        }


class NetworkSniffer:
    """Captures network packets in background thread."""
    
    def __init__(
        self,
        interface: Optional[str] = None,
        packet_count: Optional[int] = None,
        filters: Optional[Dict] = None
    ):
        """
        Initialize network sniffer.
        
        Args:
            interface: Network interface to sniff on (e.g., 'eth0', 'enp0s31f6')
            packet_count: Max packets to capture (None = infinite)
            filters: BPF filters (e.g., {'src_ip': '192.168.1.1'})
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available. Install with: pip install scapy")
        
        self.interface = interface
        self.packet_count = packet_count
        self.filters = filters or {}
        self.running = False
        self.thread = None
        self.packet_queue = deque(maxlen=10000)  # Keep last 10k packets
        self.callbacks = []
    
    def start(self) -> None:
        """Start packet sniffer in background thread."""
        if self.running:
            print("⚠ Sniffer already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.thread.start()
        print(f"📡 Started packet sniffer on {self.interface or 'default interface'}")
    
    def stop(self) -> None:
        """Stop packet sniffer."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("📡 Stopped packet sniffer")
    
    def _sniff_packets(self) -> None:
        """Internal method to sniff packets."""
        try:
            # Build BPF filter
            bpf_filter = self._build_bpf_filter()
            
            # Sniff packets
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                filter=bpf_filter,
                count=self.packet_count,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            print(f"✗ Sniffer error: {e}")
            self.running = False
    
    def _build_bpf_filter(self) -> str:
        """Build Berkeley Packet Filter string from filters."""
        conditions = []
        
        if 'src_ip' in self.filters:
            conditions.append(f"src {self.filters['src_ip']}")
        if 'dst_ip' in self.filters:
            conditions.append(f"dst {self.filters['dst_ip']}")
        if 'src_port' in self.filters:
            conditions.append(f"src port {self.filters['src_port']}")
        if 'dst_port' in self.filters:
            conditions.append(f"dst port {self.filters['dst_port']}")
        if 'protocol' in self.filters:
            conditions.append(self.filters['protocol'].lower())
        
        return ' and '.join(conditions) if conditions else ''
    
    def _packet_callback(self, packet) -> None:
        """Called for each captured packet."""
        try:
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = 0
            dst_port = 0
            protocol = 'unknown'
            
            # Extract port and protocol info
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = 'tcp'
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = 'udp'
            
            packet_size = len(packet)
            timestamp = datetime.now()
            
            # Create packet event
            event = PacketEvent(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=packet_size,
                timestamp=timestamp,
                raw_data=bytes(packet)
            )
            
            # Add to queue
            self.packet_queue.append(event)
            
            # Call registered callbacks
            for callback in self.callbacks:
                try:
                    callback(event)
                except Exception as e:
                    print(f"✗ Callback error: {e}")
        
        except Exception as e:
            pass  # Silently ignore packet parse errors
    
    def register_callback(self, callback: Callable[[PacketEvent], None]) -> None:
        """Register callback to be called for each packet."""
        self.callbacks.append(callback)
    
    def get_packets(self, count: int = 100) -> List[PacketEvent]:
        """Get last N packets from queue."""
        return list(deque(self.packet_queue, maxlen=count))
    
    def get_packet_statistics(self) -> Dict:
        """Get statistics about captured packets."""
        packets = list(self.packet_queue)
        
        if not packets:
            return {
                'total_packets': 0,
                'unique_src_ips': 0,
                'unique_dst_ips': 0,
                'protocols': {}
            }
        
        src_ips = defaultdict(int)
        dst_ips = defaultdict(int)
        protocols = defaultdict(int)
        total_bytes = 0
        
        for pkt in packets:
            src_ips[pkt.src_ip] += 1
            dst_ips[pkt.dst_ip] += 1
            protocols[pkt.protocol] += 1
            total_bytes += pkt.size
        
        return {
            'total_packets': len(packets),
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'total_bytes': total_bytes,
            'protocols': dict(protocols),
            'top_src_ips': sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:5],
            'top_dst_ips': sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
        }


class SimulatedNetworkSource:
    """Simulates network traffic for testing (when scapy not available)."""
    
    def __init__(self):
        """Initialize simulator."""
        self.packet_history = []
    
    def generate_normal_traffic(self, count: int = 100) -> List[PacketEvent]:
        """Generate normal-looking network traffic."""
        packets = []
        normal_ips = ['192.168.1.10', '192.168.1.20', '10.0.0.1']
        
        for i in range(count):
            packet = PacketEvent(
                src_ip=normal_ips[i % len(normal_ips)],
                dst_ip='192.168.1.1',
                src_port=5000 + (i % 100),
                dst_port=502,  # Modbus port
                protocol='tcp',
                size=64 + (i % 100),
                timestamp=datetime.now(),
                raw_data=None
            )
            packets.append(packet)
        
        self.packet_history.extend(packets)
        return packets
    
    def generate_attack_traffic(self, count: int = 50, attack_type: str = 'exfiltration') -> List[PacketEvent]:
        """Generate attack traffic."""
        packets = []
        
        if attack_type == 'exfiltration':
            # High volume to many destinations
            for i in range(count):
                ephemeral_port = 40000 + (i % 1000)
                packet = PacketEvent(
                    src_ip='192.168.1.50',  # Suspicious source
                    dst_ip=f'8.8.8.{i % 256}',  # Many external destinations
                    src_port=ephemeral_port,
                    dst_port=443,
                    protocol='tcp',
                    size=1024 + (i % 500),  # Large packets
                    timestamp=datetime.now(),
                    raw_data=None
                )
                packets.append(packet)
        
        elif attack_type == 'tampering':
            # Packets targeting control ports
            for i in range(count):
                packet = PacketEvent(
                    src_ip='10.0.0.50',
                    dst_ip='192.168.1.100',
                    src_port=45000 + i,
                    dst_port=502,  # Modbus
                    protocol='tcp',
                    size=256 + (i % 128),  # Modbus-like sizes
                    timestamp=datetime.now(),
                    raw_data=None
                )
                packets.append(packet)
        
        self.packet_history.extend(packets)
        return packets
