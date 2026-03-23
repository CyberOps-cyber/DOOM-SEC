# vortexscan.py
# VortexScan - Advanced Multi-Threaded Port Scanner with Banner Grabbing
# Educational Red Team Tool - Use ONLY on systems you own or have explicit permission!
# Author: Group Collaboration (2026)
# Features: High concurrency, service detection, banner grabbing, reporting

import socket
import threading
import queue
import sys
import time
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Colors
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'

print_lock = Lock()
results = []
open_ports = []

# Common ports database
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8000: "HTTP-Alt", 8888: "HTTP-Alt"
}

TOP_1000_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]

def banner():
    print(f"""
{GREEN} __     ___            _            
 \ \   / / |          | |           
  \ \ / /| | ___  __ _| |_ ___ _ __ 
   \ V / | |/ _ \/ _` | __/ _ \ '__|
    | |  | |  __/ (_| | ||  __/ |   
    |_|  |_|\___|\__,_|\__\___|_|   {CYAN}v2.0{RESET}
                                    
Advanced Port Scanner with Banner Grabbing - Educational Use Only
{RESET}""")

def grab_banner(ip, port, timeout=4):
    try:
        socket.setdefaulttimeout(timeout)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        if banner and len(banner) > 0:
            return banner[:200]  # Truncate long banners
    except:
        pass
    
    # Special HTTP title grab
    if port in [80, 443, 8080, 8000, 8443, 8888]:
        try:
            scheme = "https" if port in [443, 8443] else "http"
            import urllib.request
            req = urllib.request.Request(f"{scheme}://{ip}:{port}", headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=timeout)
            data = response.read(4096).decode('utf-8', errors='ignore')
            title_match = re.search(r'<title>(.*?)</title>', data, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
                return f"HTTP Title: {title}"
        except:
            pass
    return None

def scan_port(ip, port, q, total):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            banner = grab_banner(ip, port)
            with print_lock:
                open_ports.append(port)
                result_line = f"{GREEN}[+] OPEN{GREEN} {port}/tcp {YELLOW}{service.ljust(15)}{RESET}"
                if banner:
                    result_line += f" {CYAN}| Banner: {banner}{RESET}"
                print(result_line)
                results.append({"port": port, "service": service, "banner": banner or ""})
        
        # Progress update
        with print_lock:
            scanned = total - q.qsize()
            progress = (scanned / total) * 100
            sys.stdout.write(f"\r{BLUE}[*] Scanning: {scanned}/{total} ports ({progress:.1f}%) | Open: {len(open_ports)}{RESET}")
            sys.stdout.flush()
            
    except Exception as e:
        pass

def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except:
        print(f"{RED}[-] Cannot resolve hostname: {target}{RESET}")
        sys.exit(1)

def parse_ports(port_arg):
    ports = set()
    if port_arg.lower() == "top-1000":
        return TOP_1000_PORTS
    elif port_arg.lower() == "top-500":
        return TOP_1000_PORTS[:500]
    parts = port_arg.split(',')
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def main():
    banner()
    
    if len(sys.argv) < 4:
        print(f"{RED}Usage: python3 vortexscan.py <target> <ports> <threads>{RESET}")
        print(f"Ports examples: 1-1000 | top-1000 | top-500 | 22,80,443,445")
        print(f"Example: python3 vortexscan.py 192.168.1.1 top-1000 200")
        sys.exit(1)
    
    target = sys.argv[1].strip()
    port_arg = sys.argv[2]
    try:
        threads = int(sys.argv[3])
        if threads > 500: threads = 500
        if threads < 10: threads = 100
    except:
        threads = 150
    
    ip = resolve_host(target)
    
    print(f"{BLUE}[*] Target: {target} ({ip})")
    print(f"[*] Port range: {port_arg}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")
    
    ports = parse_ports(port_arg)
    if not ports:
        print(f"{RED}[-] No valid ports specified!{RESET}")
        sys.exit(1)
    
    print(f"{YELLOW}[+] Scanning {len(ports)} ports...{RESET}\n")
    
    q = queue.Queue()
    for port in ports:
        q.put(port)
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, port, q, len(ports)) for port in ports]
        for future in as_completed(futures):
            future.result()
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"\n\n{GREEN}[+] Scan completed in {duration:.2f} seconds")
    print(f"[+] Found {len(open_ports)} open ports{RESET}")
    
    if results:
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_file = f"vortexscan_{target}_{timestamp}.txt"
        csv_file = f"vortexscan_{target}_{timestamp}.csv"
        
        with open(txt_file, 'w') as f:
            f.write(f"VortexScan Report - {target} ({ip})\n")
            f.write(f"Scan time: {datetime.now()}\n")
            f.write(f"Duration: {duration:.2f}s | Open ports: {len(results)}\n\n")
            for r in results:
                banner_str = f" | {r['banner']}" if r['banner'] else ""
                f.write(f"Port {r['port']}/tcp open  {r['service']}{banner_str}\n")
        
        with open(csv_file, 'w') as f:
            f.write("Port,Service,Banner\n")
            for r in results:
                banner_clean = r['banner'].replace(',', ' ')
                f.write(f"{r['port']},{r['service']},{banner_clean}\n")
        
        print(f"{YELLOW}[*] Results saved to:{RESET}")
        print(f"    • {txt_file}")
        print(f"    • {csv_file}")
    
    print(f"\n{RED}[!] Educational use only. Only scan systems you have explicit permission for!{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(0)