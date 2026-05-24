#!/usr/bin/env python3
"""
SubFinder - Fast Subdomain Enumeration and Discovery Engine
Performs concurrent DNS resolution and pattern-based subdomain discovery
"""

import argparse
import socket
import dns.resolver
import dns.exception
import sys
import logging
import time
from typing import Any, List, Set, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class SubFinder:
    """Advanced subdomain enumeration and discovery engine."""
    
    def __init__(self, domain: str, threads: int = 16, timeout: int = 3):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains: Set[str] = set()
        self.stats = {
            'checked': 0,
            'found': 0,
            'failed': 0,
            'nxdomain': 0,
            'timeout': 0
        }
        self.lock = threading.Lock()
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
    
    def load_wordlist(self, wordlist_path: str) -> List[str]:
        """Load subdomain wordlist from file."""
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"[+] Loaded {len(words)} words from {wordlist_path}")
            return words
        except FileNotFoundError:
            logger.error(f"[!] Wordlist file not found: {wordlist_path}")
            sys.exit(1)
    
    def check_subdomain(self, subdomain: str) -> Tuple[str, bool]:
        """Check if a subdomain resolves via DNS."""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            answers = self.resolver.resolve(full_domain, 'A', tcp=False)
            ips = [str(rr) for rr in answers]
            
            with self.lock:
                self.stats['checked'] += 1
                self.stats['found'] += 1
                self.found_subdomains.add(full_domain)
            
            logger.info(f"[FOUND] {full_domain:45s} -> {', '.join(ips)}")
            return full_domain, True
        
        except dns.resolver.NXDOMAIN:
            with self.lock:
                self.stats['checked'] += 1
                self.stats['nxdomain'] += 1
            return full_domain, False
        
        except dns.resolver.NoAnswer:
            with self.lock:
                self.stats['checked'] += 1
                self.stats['checked'] += 0
            return full_domain, False
        
        except dns.exception.Timeout:
            with self.lock:
                self.stats['checked'] += 1
                self.stats['timeout'] += 1
            logger.debug(f"DNS timeout for {full_domain}")
            return full_domain, False
        
        except dns.exception.DNSException as exc:
            with self.lock:
                self.stats['checked'] += 1
                self.stats['failed'] += 1
            logger.debug(f"DNS error for {full_domain}: {exc}")
            return full_domain, False
        
        except Exception as exc:
            with self.lock:
                self.stats['checked'] += 1
                self.stats['failed'] += 1
            logger.debug(f"Error checking {full_domain}: {exc}")
            return full_domain, False
    
    def enumerate_wordlist(self, wordlist: List[str]):
        """Enumerate subdomains from wordlist with concurrent requests."""
        logger.info(f"[+] Starting subdomain enumeration for {self.domain}")
        logger.info(f"[+] Wordlist size: {len(wordlist)}, Threads: {self.threads}")
        logger.info(f"[+] Resolver: {self.resolver.nameservers}")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, word): word for word in wordlist}
            
            completed = 0
            for future in as_completed(futures):
                try:
                    domain, found = future.result()
                    completed += 1
                    
                    if completed % max(1, len(wordlist) // 10) == 0 or completed == len(wordlist):
                        progress = (completed / len(wordlist)) * 100
                        logger.info(f"[*] Progress: {completed}/{len(wordlist)} ({progress:.0f}%)")
                
                except Exception as exc:
                    logger.debug(f"Error: {exc}")
        
        elapsed = time.time() - start_time
        logger.info(f"[+] Enumeration completed in {elapsed:.2f}s")
    
    def enumerate_patterns(self, base_names: List[str]):
        """Enumerate common subdomain patterns."""
        patterns = [
            "{name}",
            "www.{name}",
            "api.{name}",
            "dev.{name}",
            "test.{name}",
            "staging.{name}",
            "prod.{name}",
            "mail.{name}",
            "ftp.{name}",
            "vpn.{name}",
            "admin.{name}",
            "dashboard.{name}",
            "api-{name}",
            "cdn.{name}",
            "assets.{name}",
            "images.{name}",
            "static.{name}",
            "app.{name}",
            "mobile.{name}",
            "old.{name}",
            "backup.{name}",
            "cache.{name}",
            "beta.{name}",
            "internal.{name}",
            "support.{name}",
            "panel.{name}",
            "control.{name}",
            "cpanel.{name}",
            "webmail.{name}",
            "smtp.{name}",
        ]
        
        subdomains = []
        for base in base_names:
            for pattern in patterns:
                subdomains.append(pattern.format(name=base))
        
        logger.info(f"[+] Enumerating {len(subdomains)} pattern-based subdomains")
        self.enumerate_wordlist(subdomains)
    
    def get_nameservers(self) -> List[str]:
        """Get authoritative nameservers for domain."""
        try:
            ns_answers = self.resolver.resolve(self.domain, 'NS')
            return [str(rr) for rr in ns_answers]
        except Exception as exc:
            logger.debug(f"Failed to get nameservers: {exc}")
            return []
    
    def print_results(self):
        """Print comprehensive enumeration results."""
        print("\n" + "="*80)
        print(f"SubFinder - Enumeration Results for {self.domain}")
        print("="*80)
        
        print(f"\n[STATISTICS]")
        print(f"  Checked:              {self.stats['checked']}")
        print(f"  Found:                {self.stats['found']}")
        print(f"  NXDOMAIN:             {self.stats['nxdomain']}")
        print(f"  Timeouts:             {self.stats['timeout']}")
        print(f"  Failed:               {self.stats['failed']}")
        
        if self.stats['checked'] > 0:
            success_rate = (self.stats['found'] / self.stats['checked']) * 100
            print(f"  Success Rate:         {success_rate:.2f}%")
        
        print(f"\n[NAMESERVERS]")
        nameservers = self.get_nameservers()
        if nameservers:
            for ns in nameservers:
                print(f'  - {ns}')

        print(f"\n[HTTP PROBE VALIDATION]")
        for domain in sorted(self.found_subdomains):
            response = self.probe_domain(domain)
            if response:
                print(f"  {domain} -> {response['status_code']} ({response['content_type']})")
            else:
                print(f"  {domain} -> no response")

    def probe_domain(self, domain: str) -> Dict[str, Any]:
        """Probe discovered subdomain with an HTTP HEAD request."""
        try:
            url = f'http://{domain}'
            response = requests.head(url, timeout=self.timeout, allow_redirects=True)
            return {
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'server': response.headers.get('Server', ''),
            }
        except requests.RequestException:
            return {}

    def export_json(self, output_file: str):
        """Export subdomain discovery results to JSON."""
        import json
        payload = {
            'domain': self.domain,
            'found_subdomains': sorted(self.found_subdomains),
            'stats': self.stats,
        }
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Exported subdomain results to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def export_text(self, output_file: str):
        """Export subdomain results to a plain text file."""
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                fh.write('SubFinder Report\n')
                fh.write('='*80 + '\n')
                for subdomain in sorted(self.found_subdomains):
                    fh.write(f'{subdomain}\n')
                fh.write('\n')
                fh.write(f'Checked: {self.stats['checked']}\n')
                fh.write(f'Found: {self.stats['found']}\n')
            logger.info(f'Plain text report written to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to write text report: {exc}')


def main():
    parser = argparse.ArgumentParser(
        description="SubFinder - Fast Subdomain Enumeration and Discovery",
        epilog="Examples:\n"
               "  python subfinder.py example.com\n"
               "  python subfinder.py example.com -w wordlist.txt\n"
               "  python subfinder.py example.com -p api dev www --threads 32",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-w', '--wordlist', type=str, help='Path to subdomain wordlist file')
    parser.add_argument('-p', '--patterns', nargs='+', help='Base names for pattern enumeration')
    parser.add_argument('-t', '--threads', type=int, default=16, help='Number of concurrent threads (default: 16)')
    parser.add_argument('--timeout', type=int, default=3, help='DNS timeout in seconds (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    finder = SubFinder(args.domain, threads=args.threads, timeout=args.timeout)
    
    try:
        if args.wordlist:
            wordlist = finder.load_wordlist(args.wordlist)
            finder.enumerate_wordlist(wordlist)
        
        if args.patterns:
            finder.enumerate_patterns(args.patterns)
        
        if not args.wordlist and not args.patterns:
            common_subs = ['www', 'api', 'dev', 'test', 'staging', 'prod', 'mail', 'admin', 'app', 'cdn']
            finder.enumerate_wordlist(common_subs)
        
        finder.print_results()
    
    except KeyboardInterrupt:
        logger.warning("\n[!] Enumeration interrupted by user")
        finder.print_results()
        sys.exit(1)
    except Exception as exc:
        logger.error(f"[!] Fatal error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
