
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | DomainSeeker
Author: CyberOps
Version: 3.0.0
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
import socket
import argparse
import sys
import time
import os
import json
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "DomainSeeker"
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 5.0

# Extended record types for deep enumeration
RECORD_TYPES = [
    'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SPF', 'PTR', 'SRV', 
    'CAA', 'HINFO', 'ISDN', 'RP', 'AFSDB', 'LOC', 'NAPTR'
]

# A built-in small wordlist for demonstration if no file is provided
BUILTIN_SUBS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", 
    "smtp", "secure", "vpn", "m", "shop", "dev", "test", "admin", 
    "portal", "api", "stage", "staging", "beta", "intranet", "help", 
    "support", "billing", "cpanel", "whm", "web", "ftp", "cloud", 
    "git", "svn", "jenkins", "jira", "confluence", "internal", "corp",
    "mobile", "status", "dashboard", "monitor", "analytics", "graph",
    "db", "sql", "mysql", "auth", "login", "sso", "oauth", "payments"
]

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
    UNDERLINE = '\033[4m'
    CYAN = '\033[96m'

class Logger:
    def __init__(self, verbose=False, log_file=None):
        self.verbose = verbose
        self.log_file = log_file
        if log_file:
            try:
                with open(log_file, "w") as f:
                    f.write(f"--- {TOOL_NAME} Scan Log Started: {datetime.now()} ---\n")
            except Exception as e:
                print(f"[!] Failed to initiate log file: {e}")

    def _write(self, msg):
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(f"{datetime.now()} | {msg}\n")

    def info(self, msg):
        print(f"{Colors.BLUE}[*]{Colors.ENDC} {msg}")
        self._write(f"[INFO] {msg}")

    def success(self, msg):
        print(f"{Colors.GREEN}[+]{Colors.ENDC} {msg}")
        self._write(f"[SUCCESS] {msg}")

    def error(self, msg):
        print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")
        self._write(f"[ERROR] {msg}")

    def warning(self, msg):
        print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")
        self._write(f"[WARNING] {msg}")
    
    def debug(self, msg):
        if self.verbose:
            print(f"{Colors.CYAN}[DEBUG]{Colors.ENDC} {msg}")
            self._write(f"[DEBUG] {msg}")

    def header(self, msg):
        print(f"\n{Colors.BOLD}{Colors.UNDERLINE}{msg}{Colors.ENDC}")
        self._write(f"[SECTION] {msg}")

# ==============================================================================
# CORE TOOL LOGIC
# ==============================================================================

class DomainSeeker:
    def __init__(self, domain, wordlist=None, threads=10, verbose=False, output_file=None):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.output_file = output_file
        self.logger = Logger(verbose, "domainseeker.log")
        self.logger.verbose = verbose
        
        self.results = {
            "domain": domain,
            "scan_time": str(datetime.now()),
            "records": {},
            "zone_transfer": False,
            "subdomains": []
        }

    def print_banner(self):
        banner = f"""{Colors.FAIL}
        ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
        ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
        ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
        ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
        ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
        ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: DomainSeeker v{VERSION} ]
        [ Advanced DNS Reconnaissance & Enumeration ]
        {Colors.ENDC}"""
        print(banner)

    def resolve_record(self, record_type):
        try:
            answers = dns.resolver.resolve(self.domain, record_type)
            found_data = []
            for rdata in answers:
                found_data.append(str(rdata))
            
            if found_data:
                self.logger.success(f"Found {record_type} records:")
                for item in found_data:
                    print(f"    -> {item}")
                self.results["records"][record_type] = found_data
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records found.")
        except dns.resolver.NXDOMAIN:
            self.logger.error("Domain does not exist (NXDOMAIN). Aborting.")
            sys.exit(1)
        except Exception as e:
            self.logger.debug(f"Error querying {record_type}: {e}")

    def perform_zone_transfer(self):
        self.logger.header("Zone Transfer (AXFR) Attempt")
        
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(r.target) for r in ns_records]
            
            if not nameservers:
                self.logger.warning("No Nameservers found to test for transfer.")
                return

            for ns in nameservers:
                # Resolve NS to IP
                try:
                    ns_ip = socket.gethostbyname(ns)
                except Exception:
                    self.logger.warning(f"Could not resolve NS: {ns}")
                    continue
                
                self.logger.info(f"Testing NS: {ns} ({ns_ip})")
                
                try:
                    # Attempt AXFR
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=5.0))
                    
                    if zone:
                        self.logger.warning(f"!!! ZONE TRANSFER SUCCESSFUL ON {ns} !!!")
                        self.results["zone_transfer"] = True
                        
                        count = 0
                        for name, node in zone.nodes.items():
                            try:
                                record_text = str(node.to_text(name))
                                print(f"    {record_text}")
                                count += 1
                            except:
                                pass
                        
                        self.logger.success(f"Dumped {count} records from zone!")
                        return True
                        
                except Exception as e:
                     self.logger.debug(f"Transfer failed on {ns}: {e}")

        except Exception as e:
            self.logger.error(f"Zone Transfer check failed: {e}")
            
        self.logger.info("Zone Transfer failed on all nameservers.")
        return False

    def check_subdomain(self, sub):
        target = f"{sub}.{self.domain}"
        try:
            # We use socket directly for speed here instead of dnspython overhead
            ip = socket.gethostbyname(target)
            msg = f"Found: {target} -> {ip}"
            self.logger.success(msg)
            return {"subdomain": target, "ip": ip}
        except Exception:
            return None

    def brute_force_subdomains(self):
        self.logger.header("Subdomain Brute-Force")
        
        subs_to_check = []
        
        if self.wordlist:
            if os.path.exists(self.wordlist):
                self.logger.info(f"Loading wordlist from: {self.wordlist}")
                try:
                    with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        subs_to_check = [line.strip() for line in f if line.strip()]
                except Exception as e:
                    self.logger.error(f"Failed to read wordlist: {e}")
                    self.logger.info("Falling back to built-in list.")
                    subs_to_check = BUILTIN_SUBS
            else:
                self.logger.error("Wordlist file not found.")
                subs_to_check = BUILTIN_SUBS
        else:
            self.logger.info("Using built-in common subdomain list.")
            subs_to_check = BUILTIN_SUBS
            
        self.logger.info(f"Starting brute-force on {len(subs_to_check)} potential targets with {self.threads} threads...")
        
        found_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_subdomain, sub) for sub in subs_to_check]
            for future in futures:
                res = future.result()
                if res:
                    self.results["subdomains"].append(res)
                    found_count += 1
                    
        self.logger.info(f"Brute-force complete. Found {found_count} valid subdomains.")

    def save_results(self):
        if self.output_file:
            self.logger.header("Saving Results")
            try:
                with open(self.output_file, "w") as f:
                    json.dump(self.results, f, indent=4)
                self.logger.success(f"Results saved to {self.output_file}")
            except Exception as e:
                self.logger.error(f"Failed to save results: {e}")

    def run(self):
        self.print_banner()
        
        self.logger.header("Enumerating DNS Records")
        for r_type in RECORD_TYPES:
            self.resolve_record(r_type)
            
        self.perform_zone_transfer()
        self.brute_force_subdomains()
        self.save_results()
        
        print("\n")
        self.logger.info("DomainSeeker Scan Complete.")

# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"DomainSeeker v{VERSION} | Advanced DNS Enumeration Tool",
        epilog="Do not use for illegal purposes."
    )
    
    parser.add_argument("domain", help="Target Domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to custom subdomain wordlist")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for brute-force")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    try:
        seeker = DomainSeeker(
            domain=args.domain,
            wordlist=args.wordlist,
            threads=args.threads,
            verbose=args.verbose,
            output_file=args.output
        )
        seeker.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.FAIL}[!] Interrupted by user. Exiting...{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Critical Error: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
