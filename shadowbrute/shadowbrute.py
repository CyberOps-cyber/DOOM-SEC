# shadowbrute.py
# ShadowBrute - Advanced Multi-Threaded Subdomain Brute-Forcer
# Educational Red Team Tool - Use ONLY on domains you own or have explicit permission for!
# Author: Your Group Collaboration (2026)
# Features: Threading, DNS resolution, progress tracking, colored output

import socket
import threading
import queue
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Colors for output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'

print_lock = Lock()

def banner():
    print(f"""
{GREEN}   _____ _               __      __  ___       __      
  / ___/(_)_____ __ __  / /____ / /_/ _ )___  / /______
  \\__ \\/ / __/ // / / / __/ -_) __/ _  / _ \\/ __/ / __/
 ___/ / /_/ /\\_,_/_/  \\__/\\__/\\__/____/\\___/\\__/\\_\\__/ 
/____/                                                 
Advanced Subdomain Brute-Forcer v1.0 - Educational Use Only!
{RESET}""")

def resolve_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return ip
    except socket.gaierror:
        return None
    except Exception:
        return None

def check_subdomain(domain, sub, q, total, mode='normal'):
    full_sub = f"{sub}.{domain}".lower().strip()
    ip = resolve_subdomain(full_sub)
    
    with print_lock:
        scanned = total - q.qsize()
        progress = (scanned / total) * 100
        sys.stdout.write(f"\r{YELLOW}[*] Progress: {scanned}/{total} ({progress:.2f}%) | Testing: {full_sub.ljust(40)}{RESET}")
        sys.stdout.flush()
    
    if ip:
        with print_lock:
            print(f"\n{GREEN}[+] LIVE SUBDOMAIN FOUND: {full_sub} -> {ip}{RESET}")
        return full_sub, ip
    return None

def main():
    banner()
    
    if len(sys.argv) < 4:
        print(f"{RED}Usage: python3 shadowbrute.py <domain> <wordlist.txt> <threads> [fast]{RESET}")
        print(f"Example: python3 shadowbrute.py example.com wordlist.txt 100")
        sys.exit(1)
    
    domain = sys.argv[1].lower().strip().replace('http://', '').replace('https://', '')
    wordlist_path = sys.argv[2]
    try:
        max_threads = int(sys.argv[3])
        if max_threads > 500 or max_threads < 1:
            max_threads = 100
    except:
        max_threads = 100
    
    fast_mode = len(sys.argv) > 4 and sys.argv[4].lower() == 'fast'
    
    print(f"{BLUE}[*] Target Domain: {domain}")
    print(f"[*] Wordlist: {wordlist_path}")
    print(f"[*] Threads: {max_threads}")
    print(f"[*] Mode: {'Fast (lower timeout)' if fast_mode else 'Normal'}{RESET}\n")
    
    # Load wordlist
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            subs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        subs = list(set(subs))  # Remove duplicates
        print(f"{BLUE}[+] Loaded {len(subs)} unique subdomains from wordlist{RESET}\n")
    except Exception as e:
        print(f"{RED}[-] Error loading wordlist: {e}{RESET}")
        sys.exit(1)
    
    if len(subs) == 0:
        print(f"{RED}[-] Wordlist is empty!{RESET}")
        sys.exit(1)
    
    # Queue for thread safety
    q = queue.Queue()
    for sub in subs:
        q.put(sub)
    
    live_subs = []
    total = len(subs)
    
    socket.setdefaulttimeout(3 if fast_mode else 5)
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_subdomain, domain, sub, q, total, 'fast' if fast_mode else 'normal') for sub in subs]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                live_subs.append(result)
    
    end_time = time.time()
    
    print(f"\n\n{GREEN}[+] Scan Complete! Found {len(live_subs)} live subdomains in {end_time - start_time:.2f} seconds{RESET}")
    
    if live_subs:
        print(f"\n{BLUE}=== LIVE SUBDOMAINS ==={RESET}")
        for sub, ip in live_subs:
            print(f"{GREEN}{sub} -> {ip}{RESET}")
        
        # Optional: Save to file
        with open(f"live_subs_{domain}.txt", 'w') as out:
            for sub, ip in live_subs:
                out.write(f"{sub} {ip}\n")
        print(f"\n{YELLOW}[*] Results saved to live_subs_{domain}.txt{RESET}")
    
    print(f"\n{RED}[!] Reminder: Use only with explicit authorization! Educational purposes only.{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(0)