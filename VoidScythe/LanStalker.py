
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | LanStalker
Author: CyberOps
Version: 3.0.0
"""

from scapy.all import *
import time
import argparse
import threading
import json
import socket
import csv
from datetime import datetime

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "LanStalker"

# Expanded Vendor OUI Database (Mockup for standalone file free operation)
VENDORS = {
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading Ltd",
    "00:1A:11": "Google, Inc.",
    "d4:f4:6f": "Apple, Inc.",
    "3c:d9:2b": "Hewlett Packard",
    "f0:1f:af": "Dell Inc.",
    "00:25:90": "Super Micro Computer, Inc.",
    "a8:5b:78": "Sony Corporation",
    "9c:eb:e8": "Samsung Electronics",
    "00:d8:61": "Ubiquiti Networks",
    "74:83:c2": "Ubiquiti Networks",
    "00:15:5d": "Microsoft Corporation",
    "48:2a:e3": "Microsoft XBOX",
    "unknown": "Unknown Vendor"
}

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

class LanStalker:
    def __init__(self, interface=None, passive=True, timeout=0, output=None, resolve=False):
        self.interface = interface
        self.passive = passive
        self.timeout = timeout
        self.output = output
        self.resolve_hostnames = resolve
        
        self.db = {} # storage for discovered hosts: MAC -> {ip, vendor, hostname, seen_at}
        self.lock = threading.Lock()
        self.start_time = None

    def print_banner(self):
        banner = f"""{Colors.HEADER}
        ██╗      █████╗ ███╗   ██╗███████╗████████╗███████╗██╗     ██╗  ██╗███████╗██████╗ 
        ██║     ██╔══██╗████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██║ ██╔╝██╔════╝██╔══██╗
        ██║     ███████║██╔██╗ ██║███████╗   ██║   █████╗  ██║     █████╔╝ █████╗  ██████╔╝
        ██║     ██╔══██║██║╚██╗██║╚════██║   ██║   ██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
        ███████╗██║  ██║██║ ╚████║███████║   ██║   ███████╗███████╗██║  ██╗███████╗██║  ██║
        ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: LanStalker v{VERSION} ]
        [ Passive Inventory Mapper & Tracker ]
        {Colors.ENDC}"""
        print(banner)

    def resolve_vendor(self, mac):
        mac_clean = mac.lower().replace('-', ':')
        prefix = mac_clean[:8]
        
        for p, vendor in VENDORS.items():
            if p in prefix:
                return vendor
                
        # Heuristic for popular brands based on OUI prefix caching would go here
        if mac_clean.startswith("00:50"): return "VMware"
        return "Unknown"

    def get_hostname(self, ip):
        if not self.resolve_hostnames:
            return "N/A"
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"

    def packet_handler(self, pkt):
        if pkt.haslayer(ARP):
            # scapy ARP fields: hwsrc/psrc (Source), hwdst/pdst (Dest)
            # We care about SOURCE mostly to identify active devices speaking
            
            src_mac = pkt[ARP].hwsrc
            src_ip = pkt[ARP].psrc
            opcode = pkt[ARP].op # 1=who-has (request), 2=is-at (reply)
            
            self.update_db(src_mac, src_ip, "ARP Request" if opcode == 1 else "ARP Reply")

    def update_db(self, mac, ip, activity_type):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        with self.lock:
            # Check for New Device
            if mac not in self.db:
                vendor = self.resolve_vendor(mac)
                hostname = self.get_hostname(ip)
                
                print(f"{Colors.GREEN}[+] {timestamp} | NEW | {ip:<15} | {mac} | {vendor}{Colors.ENDC}")
                
                self.db[mac] = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "count": 1
                }
            else:
                # Existing Device
                record = self.db[mac]
                record["last_seen"] = timestamp
                record["count"] += 1
                
                # Check for IP Change (DHCP / Spoofing)
                if record["ip"] != ip:
                    print(f"{Colors.WARNING}[!] {timestamp} | FLUX | {mac} changed IP: {record['ip']} -> {ip}{Colors.ENDC}")
                    record["ip"] = ip # Update to latest
                
                # Check for MAC Spoofing (Duplicate IP for diff MAC) - simplistic check
                # (Iterating dict is expensive in high traffic, optimize later)

    def save_report(self):
        if not self.output:
            return
            
        print(f"\n{Colors.BLUE}[*] Saving inventory report to {self.output}...{Colors.ENDC}")
        try:
            # Convert DB to list
            data_list = list(self.db.values())
            
            with open(self.output, "w") as f:
                json.dump(data_list, f, indent=4)
                
            self.logger.success("Done.")
        except:
            pass

    def start(self):
        self.print_banner()
        
        iface_str = self.interface if self.interface else conf.iface
        print(f"{Colors.BLUE}[*] Interface: {iface_str}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Resolve Hostnames: {self.resolve_hostnames}{Colors.ENDC}")
        print(f"{Colors.BLUE}[*] Listening for ARP broadcasts...{Colors.ENDC}")
        print("-" * 60)
        
        self.start_time = datetime.now()
        
        try:
            # We filter for ARP only
            sniff(
                iface=self.interface, 
                filter="arp", 
                prn=self.packet_handler, 
                store=0,
                timeout=None # Run forever until user stop
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"{Colors.FAIL}[!] Error: {e}{Colors.ENDC}")

    def stop(self):
        print("\n\n" + "=" * 60)
        print(f"{Colors.BOLD}NETWORK INVENTORY SUMMARY{Colors.ENDC}")
        print("=" * 60)
        
        # Sort by IP for display
        sorted_hosts = sorted(self.db.values(), key=lambda x: x['ip'])
        
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<20} {'First Seen'}")
        print("-" * 60)
        
        for host in sorted_hosts:
            print(f"{host['ip']:<16} {host['mac']:<18} {host['vendor'][:20]:<20} {host['first_seen']}")
            
        print("-" * 60)
        print(f"Total Unique Devices: {len(self.db)}")
        
        self.save_report()

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"LanStalker v{VERSION}",
        epilog="Passive LAN Asset Discovery."
    )
    
    parser.add_argument("-i", "--interface", help="Network Interface")
    parser.add_argument("-o", "--output", help="Save JSON report")
    parser.add_argument("-r", "--resolve", action="store_true", help="Try to resolve hostnames (active query)")
    
    args = parser.parse_args()
    
    stalker = LanStalker(
        interface=args.interface,
        output=args.output,
        resolve=args.resolve
    )
    
    try:
        stalker.start()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
