
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | CloudJack
Author: CyberOps
Version: 3.0.0
"""

import dns.resolver
import sys
import requests
import argparse
import time
import json
import socket
import urllib3
import threading
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "CloudJack"

# Extensive Signature Database
SIGNATURES = {
    "github.io": {
        "service": "GitHub Pages",
        "fingerprints": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)", "404: Not Found"],
        "cname": ["github.io"]
    },
    "herokuapp.com": {
        "service": "Heroku",
        "fingerprints": ["herokucdn.com/error-pages/no-such-app.html", "No such app", "no-such-app"],
        "cname": ["herokuapp.com"]
    },
    "amazonaws.com": {
        "service": "AWS S3",
        "fingerprints": ["The specified bucket does not exist", "Repository not found", "NoSuchBucket"],
        "cname": ["s3.amazonaws.com", "s3-website"]
    },
    "azurewebsites.net": {
        "service": "Microsoft Azure",
        "fingerprints": ["404 Web Site not found", "The resource you are looking for has been removed"],
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"]
    },
    "bitbucket.org": {
        "service": "Bitbucket",
        "fingerprints": ["Repository not found", "Bitbucket Cloud"],
        "cname": ["bitbucket.io", "bitbucket.org"]
    },
    "ghost.io": {
        "service": "Ghost",
        "fingerprints": ["The thing you are looking for is no longer here", "The thing you are looking for is no longer here"],
        "cname": ["ghost.io"]
    },
    "wordpress.com": {
        "service": "WordPress",
        "fingerprints": ["Do you want to register", "is quite a nice domain name", "doesn't exist"],
        "cname": ["wordpress.com"]
    },
    "pantheon.io": {
        "service": "Pantheon",
        "fingerprints": ["404 Not Found", "The gods are wise"],
        "cname": ["pantheonsite.io"]
    },
    "myshopify.com": {
        "service": "Shopify",
        "fingerprints": ["Sorry, this shop is currently unavailable"],
        "cname": ["myshopify.com"]
    },
    "tumblr.com": {
        "service": "Tumblr",
        "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
        "cname": ["tumblr.com"]
    },
    "wpengine.com": {
        "service": "WPEngine",
        "fingerprints": ["The site you were looking for could not be found"],
        "cname": ["wpengine.com"]
    },
    "cargo.site": {
        "service": "Cargo",
        "fingerprints": ["If you're moving your domain away from Cargo"],
        "cname": ["cargocollective.com"]
    },
    "feedpress.me": {
        "service": "Feedpress",
        "fingerprints": ["The feed has not been found"],
        "cname": ["feedpress.me"]
    },
    "surges.sh": {
        "service": "Surge.sh",
        "fingerprints": ["project not found"],
        "cname": ["surge.sh"]
    },
    "help.juicefs.com": {
        "service": "HelpJucie",
        "fingerprints": ["We could not find what you're looking for"],
        "cname": ["helpjuice.com"]
    },
    "helpscoutdocs.com": {
        "service": "HelpScout",
        "fingerprints": ["No settings were found for this company"],
        "cname": ["helpscoutdocs.com"]
    },
    "pingdom.com": {
        "service": "Pingdom",
        "fingerprints": ["Sorry, couldn't find the status page"],
        "cname": ["stats.pingdom.com"]
    },
    "tilda.ws": {
        "service": "Tilda",
        "fingerprints": ["Domain has been assigned"],
        "cname": ["tilda.ws"]
    },
    "campaign-archive.com": {
        "service": "MailChimp",
        "fingerprints": ["records indicate that you've used MailChimp"],
        "cname": ["campaign-archive.com"]
    }
}

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

class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, msg):
        print(f"{Colors.BLUE}[*]{Colors.ENDC} {msg}")

    def success(self, msg):
        print(f"{Colors.GREEN}[+]{Colors.ENDC} {msg}")

    def error(self, msg):
        print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")

    def warning(self, msg):
        print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")
    
    def vuln(self, msg):
        print(f"{Colors.FAIL}{Colors.BOLD}[!!!] {msg}{Colors.ENDC}")

# ==============================================================================
# CORE TOOL LOGIC
# ==============================================================================

class CloudJack:
    def __init__(self, targets, threads=10, timeout=5, output=None, verbose=False):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        
        self.vulnerable_hosts = []
        self.logger = Logger(verbose)
        
        # Suppress SSL warnings
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Statistics
        self.stats = {
            "total": len(targets),
            "scanned": 0,
            "vulnerable": 0,
            "errors": 0
        }
        self.scan_lock = threading.Lock()

    def print_banner(self):
        banner = f"""{Colors.HEADER}
         ██████╗██╗      ██████╗ ██╗   ██╗██████╗      ██╗ █████╗  ██████╗██╗  ██╗
        ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗     ██║██╔══██╗██╔════╝██║ ██╔╝
        ██║     ██║     ██║   ██║██║   ██║██║  ██║     ██║███████║██║     █████╔╝ 
        ██║     ██║     ██║   ██║██║   ██║██║  ██║██   ██║██╔══██║██║     ██╔═██╗ 
        ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝╚█████╔╝██║  ██║╚██████╗██║  ██╗
         ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: CloudJack v{VERSION} ]
        [ Subdomain Takeover Scanner & Cloud Enumerator ]
        {Colors.ENDC}"""
        print(banner)

    def resolve_cname(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            return None

    def check_http_response(self, domain, fingerprints):
        protocols = ["http", "https"]
        
        for proto in protocols:
            url = f"{proto}://{domain}"
            try:
                # Custom User-Agent to avoid blocking
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                
                resp = requests.get(
                    url, 
                    headers=headers,
                    timeout=self.timeout, 
                    verify=False,
                    allow_redirects=True
                )
                
                content = resp.text
                
                for fp in fingerprints:
                    if fp in content:
                        return True, proto, fp
                        
            except requests.exceptions.Timeout:
                pass
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                pass
                
        return False, None, None

    def analyze_target(self, domain):
        """
        Main worker function for a single target.
        """
        domain = domain.strip()
        if not domain:
            return

        cname = self.resolve_cname(domain)
        
        with self.scan_lock:
            self.stats["scanned"] += 1
            if self.verbose:
                if cname:
                    print(f"{Colors.BLUE}[*] Resolved {domain} -> {cname}{Colors.ENDC}")
                else:
                    # Ignore non-CNAME records usually
                    pass

        if not cname:
            return

        # Check against signature database
        for provider_key, data in SIGNATURES.items():
            # Check if CNAME matches the provider domain pattern
            is_match = False
            for cname_pattern in data["cname"]:
                if cname_pattern in cname:
                    is_match = True
                    break
            
            # If CNAME looks suspicious
            if provider_key in cname or is_match:
                self.logger.warning(f"Suspicious CNAME found: {domain} -> {cname} ({data['service']})")
                
                # Active Check
                is_vuln, proto, fp_found = self.check_http_response(domain, data["fingerprints"])
                
                if is_vuln:
                    msg = f"TAKEOVER DETECTED on {domain}!"
                    self.logger.vuln(msg)
                    print(f"    -> Service: {data['service']}")
                    print(f"    -> CNAME: {cname}")
                    print(f"    -> Protocol: {proto}")
                    print(f"    -> Fingerprint: '{fp_found}'")
                    
                    vuln_record = {
                        "domain": domain,
                        "cname": cname,
                        "service": data['service'],
                        "protocol": proto,
                        "fingerprint": fp_found,
                        "timestamp": str(datetime.now())
                    }
                    
                    with self.scan_lock:
                        self.vulnerable_hosts.append(vuln_record)
                        self.stats["vulnerable"] += 1
                else:
                    if self.verbose:
                        self.logger.info(f"Target {domain} seems patched or claimed.")
                
                # Assume one provider match is enough
                return

    def save_results(self):
        if not self.output:
            return
            
        try:
            with open(self.output, "w") as f:
                report = {
                    "scan_info": {
                        "version": VERSION,
                        "date": str(datetime.now()),
                        "stats": self.stats
                    },
                    "vulnerabilities": self.vulnerable_hosts
                }
                json.dump(report, f, indent=4)
            self.logger.success(f"Results saved to {self.output}")
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")

    def run(self):
        self.print_banner()
        self.logger.info(f"Loaded {len(self.targets)} targets.")
        self.logger.info(f"Using {self.threads} threads with {self.timeout}s timeout.")
        self.logger.info("Starting scan...")
        print("-" * 60)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.analyze_target, self.targets)
            
        duration = time.time() - start_time
        
        print("\n" + "=" * 60)
        print(f"{Colors.BOLD}SCAN COMPLETE{Colors.ENDC}")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total Scanned: {self.stats['scanned']}")
        print(f"Vulnerable Hosts Found: {Colors.FAIL}{self.stats['vulnerable']}{Colors.ENDC}")
        print("=" * 60)
        
        self.save_results()

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"CloudJack v{VERSION}",
        epilog="Detects dangling CNAME records vulnerable to subdomain takeover."
    )
    
    parser.add_argument("input", help="Target Domain (single) OR File path containing list of subdomains")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout in seconds")
    parser.add_argument("-o", "--output", help="Save vulnerable targets to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    targets = []
    
    # Check if input is file or single domain
    if os.path.isfile(args.input):
        print(f"{Colors.BLUE}[*] Loading targets from file: {args.input}{Colors.ENDC}")
        try:
            with open(args.input, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error reading file: {e}{Colors.ENDC}")
            sys.exit(1)
    else:
        # Assume single domain
        targets.append(args.input)
        
    jack = CloudJack(
        targets=targets,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output,
        verbose=args.verbose
    )
    
    try:
        jack.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user.{Colors.ENDC}")
        jack.save_results()
        sys.exit(0)

if __name__ == "__main__":
    main()
