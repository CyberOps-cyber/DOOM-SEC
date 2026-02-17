
from scapy.all import *
import time
import threading

# LanStalker - Passive ARP Monitor & Mapper
# Part of DOOM-SEC ShadowArsenal

active_hosts = {}

def banner():
    print("""
    ██╗      █████╗ ███╗   ██╗███████╗████████╗███████╗██╗     ██╗  ██╗███████╗██████╗ 
    ██║     ██╔══██╗████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██║ ██╔╝██╔════╝██╔══██╗
    ██║     ███████║██╔██╗ ██║███████╗   ██║   █████╗  ██║     █████╔╝ █████╗  ██████╔╝
    ██║     ██╔══██║██║╚██╗██║╚════██║   ██║   ██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
    ███████╗██║  ██║██║ ╚████║███████║   ██║   ███████╗███████╗██║  ██╗███████╗██║  ██║
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    
    [ LanStalker v1.0 | LAN Asset Tracker ]
    [ Part of DOOM-SEC | ShadowArsenal ]
    """)

def packet_handler(pkt):
    if pkt.haslayer(ARP):
        # We only care about unique MACs
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        
        if src_mac not in active_hosts:
            print(f"[+] NEW DEVICE FOUND: {src_ip} ({src_mac})")
            active_hosts[src_mac] = src_ip
        else:
            # Update IP if it changed (DHCP churn)
            if active_hosts[src_mac] != src_ip:
                print(f"[!] IP CHANGED: {src_mac} moved from {active_hosts[src_mac]} -> {src_ip}")
                active_hosts[src_mac] = src_ip

def monitor():
    print("[*] Listening for ARP traffic...")
    sniff(filter="arp", prn=packet_handler, store=0)

def main():
    banner()
    print("[*] Starting LanStalker...")
    print(f"[*] Current Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("--------------------------------------------------")
    
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n\n[*] Scan Stopped.")
        print(f"[*] Total Unique Devices Found: {len(active_hosts)}")
        print("--------------------------------------------------")
        for mac, ip in active_hosts.items():
            print(f"{ip}\t{mac}")

if __name__ == "__main__":
    main()
