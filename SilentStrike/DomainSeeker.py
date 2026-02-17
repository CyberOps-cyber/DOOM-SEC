
import dns.resolver
import dns.zone
import socket
import argparse
import sys

# DomainSeeker - Advanced DNS Enumeration Tool
# Part of DOOM-SEC SilentStrike Toolkit

def banner():
    print("""
    ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
    ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
    ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
    ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
    
    [ DomainSeeker v1.0 | DNS Enumeration & Zone Transfer ]
    [ Part of DOOM-SEC | SilentStrike ]
    """)

def get_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        print(f"[*] {record_type} Records for {domain}:")
        for rdata in answers:
            print(f"    - {rdata}")
    except Exception as e:
        pass # Silence errors for cleaner output

def check_zone_transfer(domain, nameservers):
    print(f"\n[*] Attempting Zone Transfer on {domain}...")
    for ns in nameservers:
        ns_val = str(ns)
        print(f"    - Trying NS: {ns_val}")
        try:
            ns_ip = socket.gethostbyname(ns_val)
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
            print(f"[!] SUCCESS! Zone Transfer allowed on {ns_val}")
            for n, v in z.nodes.items():
                print(f"      {n} : {v}")
            return True
        except Exception:
            print(f"    - Failed on {ns_val}")
    return False

def main():
    banner()
    if len(sys.argv) < 2:
        print("Usage: python DomainSeeker.py <domain>")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    
    print(f"[*] Starting Enumeration on: {target_domain}\n")
    
    # 1. Standard Records
    for r in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']:
        get_records(target_domain, r)
        
    # 2. Zone Transfer
    try:
        ns_records = dns.resolver.resolve(target_domain, 'NS')
        ns_list = [r.target for r in ns_records]
        check_zone_transfer(target_domain, ns_list)
    except Exception:
        print("\n[-] Could not retrieve NS records for Zone Transfer check.")

    print("\n[*] DomainSeeker Scan Complete.")

if __name__ == "__main__":
    main()
