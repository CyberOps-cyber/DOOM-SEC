#!/usr/bin/env python3
"""
PacketForge - Network Packet Generation and Crafting Utility
Crafts and analyzes custom network packets for penetration testing.
"""

import argparse
import socket
import struct
import textwrap
import sys
import logging
from typing import List, Tuple, Optional


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PacketForge:
    """Core packet forging and crafting engine."""
    
    def __init__(self):
        self.packets = []
        self.packet_count = 0
        self.verbose = False
    
    def format_ipv4(self, bytes_seq: bytes) -> str:
        """Convert 4 bytes to IPv4 notation."""
        return '.'.join(map(str, bytes_seq))
    
    def format_mac(self, bytes_seq: bytes) -> str:
        """Convert 6 bytes to MAC notation."""
        return ':'.join(map(lambda x: f'{x:02x}', bytes_seq))
    
    def format_multi_byte(self, bytes_seq: bytes) -> str:
        """Format arbitrary bytes as hex string."""
        return ' '.join([f'{x:02x}' for x in bytes_seq])
    
    def ipv4_packet(self, src_ip: str, dst_ip: str, protocol: int = 6, payload: bytes = b'') -> bytes:
        """
        Construct a raw IPv4 packet.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            protocol: Protocol number (6=TCP, 17=UDP)
            payload: Packet payload
        
        Returns:
            Bytes representing the IPv4 packet
        """
        version_header_length = (4 << 4) + 5
        dscp_ecn = 0
        total_length = 20 + len(payload)
        identification = 0x1234
        flags_fragment = 0x4000
        ttl = 64
        
        src_parts = [int(x) for x in src_ip.split('.')]
        dst_parts = [int(x) for x in dst_ip.split('.')]
        
        src_addr = struct.pack('!BBBB', *src_parts)
        dst_addr = struct.pack('!BBBB', *dst_parts)
        
        header = struct.pack(
            '!BHHHBBH4s4s',
            version_header_length,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            0,
            src_addr,
            dst_addr
        )
        
        checksum = self.calculate_checksum(header)
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        
        return header + payload
    
    def calculate_checksum(self, data: bytes) -> int:
        """Calculate Internet checksum."""
        if len(data) % 2:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        
        while (checksum >> 16) > 0:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF
    
    def tcp_header(self, src_port: int, dst_port: int, flags: int = 0x02, payload: bytes = b'') -> bytes:
        """
        Construct a TCP header.
        
        Args:
            src_port: Source port
            dst_port: Destination port
            flags: TCP flags (0x02 = SYN, 0x01 = FIN, etc.)
            payload: TCP payload
        
        Returns:
            Bytes representing TCP header + payload
        """
        seq_num = 0x1000
        ack_num = 0
        data_offset = (5 << 4) + 0
        window = 8192
        
        tcp_header = struct.pack(
            '!HHIIBBHHH',
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window,
            0,
            0
        )
        
        tcp_checksum = self.calculate_checksum(tcp_header + payload)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
        
        return tcp_header + payload
    
    def udp_header(self, src_port: int, dst_port: int, payload: bytes = b'') -> bytes:
        """
        Construct a UDP header.
        
        Args:
            src_port: Source port
            dst_port: Destination port
            payload: UDP payload
        
        Returns:
            Bytes representing UDP header + payload
        """
        length = 8 + len(payload)
        
        udp_header = struct.pack(
            '!HHHH',
            src_port,
            dst_port,
            length,
            0
        )
        
        udp_checksum = self.calculate_checksum(udp_header + payload)
        udp_header = udp_header[:6] + struct.pack('!H', udp_checksum)
        
        return udp_header + payload
    
    def icmp_echo_request(self, identifier: int = 1, sequence: int = 1, payload: bytes = b'PacketForge') -> bytes:
        """
        Construct an ICMP Echo Request (ping) packet.
        
        Args:
            identifier: ICMP identifier
            sequence: ICMP sequence number
            payload: Echo payload
        
        Returns:
            Bytes representing ICMP packet
        """
        icmp_type = 8
        code = 0
        
        icmp_header = struct.pack(
            '!BBHHh',
            icmp_type,
            code,
            0,
            identifier,
            sequence
        )
        
        icmp_checksum = self.calculate_checksum(icmp_header + payload)
        icmp_header = icmp_header[:2] + struct.pack('!H', icmp_checksum) + icmp_header[4:]
        
        return icmp_header + payload
    
    def craft_tcp_syn(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """Craft a TCP SYN packet."""
        tcp_payload = self.tcp_header(src_port, dst_port, flags=0x02)
        packet = self.ipv4_packet(src_ip, dst_ip, protocol=6, payload=tcp_payload)
        self.packets.append(packet)
        self.packet_count += 1
        return packet
    
    def craft_tcp_fin(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
        """Craft a TCP FIN packet."""
        tcp_payload = self.tcp_header(src_port, dst_port, flags=0x01)
        packet = self.ipv4_packet(src_ip, dst_ip, protocol=6, payload=tcp_payload)
        self.packets.append(packet)
        self.packet_count += 1
        return packet
    
    def craft_udp_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, data: bytes = b'') -> bytes:
        """Craft a UDP packet."""
        udp_payload = self.udp_header(src_port, dst_port, payload=data)
        packet = self.ipv4_packet(src_ip, dst_ip, protocol=17, payload=udp_payload)
        self.packets.append(packet)
        self.packet_count += 1
        return packet
    
    def craft_icmp_ping(self, src_ip: str, dst_ip: str) -> bytes:
        """Craft an ICMP Echo Request packet."""
        icmp_payload = self.icmp_echo_request()
        packet = self.ipv4_packet(src_ip, dst_ip, protocol=1, payload=icmp_payload)
        self.packets.append(packet)
        self.packet_count += 1
        return packet
    
    def display_packet(self, packet: bytes, label: str = "Packet"):
        """Display packet in hex and ASCII format."""
        print(f"\n[+] {label}")
        print(f"    Packet Size: {len(packet)} bytes")
        print(f"    Hex Dump:")
        
        for i in range(0, len(packet), 16):
            hex_part = ' '.join(f'{b:02x}' for b in packet[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in packet[i:i+16])
            print(f"    {i:04x}: {hex_part:<48} {ascii_part}")
    
    def save_packet(self, packet: bytes, filename: str):
        """Save packet to file."""
        try:
            with open(filename, 'wb') as f:
                f.write(packet)
            logger.info(f"Packet saved to {filename}")
        except IOError as e:
            logger.error(f"Failed to save packet: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PacketForge - Network Packet Crafting and Generation Utility",
        epilog="Examples:\n"
               "  python packetforge.py tcp --src 192.168.1.10 --dst 8.8.8.8 --sport 12345 --dport 80\n"
               "  python packetforge.py udp --src 10.0.0.1 --dst 10.0.0.2 --sport 53 --dport 53\n"
               "  python packetforge.py icmp --src 192.168.1.10 --dst 8.8.8.8",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Packet type to craft')
    
    # TCP command
    tcp_parser = subparsers.add_parser('tcp', help='Craft TCP packet')
    tcp_parser.add_argument('--src', required=True, help='Source IP address')
    tcp_parser.add_argument('--dst', required=True, help='Destination IP address')
    tcp_parser.add_argument('--sport', type=int, required=True, help='Source port')
    tcp_parser.add_argument('--dport', type=int, required=True, help='Destination port')
    tcp_parser.add_argument('--flag', type=str, default='SYN', choices=['SYN', 'FIN', 'RST'], help='TCP flag')
    tcp_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # UDP command
    udp_parser = subparsers.add_parser('udp', help='Craft UDP packet')
    udp_parser.add_argument('--src', required=True, help='Source IP address')
    udp_parser.add_argument('--dst', required=True, help='Destination IP address')
    udp_parser.add_argument('--sport', type=int, required=True, help='Source port')
    udp_parser.add_argument('--dport', type=int, required=True, help='Destination port')
    udp_parser.add_argument('--data', type=str, default='', help='Payload data')
    udp_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # ICMP command
    icmp_parser = subparsers.add_parser('icmp', help='Craft ICMP Echo Request')
    icmp_parser.add_argument('--src', required=True, help='Source IP address')
    icmp_parser.add_argument('--dst', required=True, help='Destination IP address')
    icmp_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    forge = PacketForge()
    
    if args.command == 'tcp':
        logger.info(f"Crafting TCP packet: {args.src}:{args.sport} -> {args.dst}:{args.dport}")
        if args.flag == 'SYN':
            packet = forge.craft_tcp_syn(args.src, args.dst, args.sport, args.dport)
        elif args.flag == 'FIN':
            packet = forge.craft_tcp_fin(args.src, args.dst, args.sport, args.dport)
        else:
            packet = forge.craft_tcp_syn(args.src, args.dst, args.sport, args.dport)
        
        forge.display_packet(packet, f"TCP {args.flag} Packet")
    
    elif args.command == 'udp':
        logger.info(f"Crafting UDP packet: {args.src}:{args.sport} -> {args.dst}:{args.dport}")
        packet = forge.craft_udp_packet(args.src, args.dst, args.sport, args.dport, args.data.encode())
        forge.display_packet(packet, "UDP Packet")
    
    elif args.command == 'icmp':
        logger.info(f"Crafting ICMP Echo Request: {args.src} -> {args.dst}")
        packet = forge.craft_icmp_ping(args.src, args.dst)
        forge.display_packet(packet, "ICMP Echo Request")
    
    print(f"\n[+] Total packets crafted: {forge.packet_count}")


if __name__ == "__main__":
    main()
