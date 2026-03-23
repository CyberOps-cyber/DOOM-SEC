
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | ShadowCrawl
Author: CyberOps
Version: 3.0.0
"""

import requests
from bs4 import BeautifulSoup, Comment
import sys
import argparse
from urllib.parse import urljoin, urlparse, unquote
import re
import threading
import time
import os
import random
import json
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "ShadowCrawl"

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
]

# Regex patterns for data extraction
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"\+?1?[-.]?\(?[0-9]{3}\)?[ -.]?[0-9]{3}[-.]?[0-9]{4}"
API_KEY_REGEX = r"(api_key|apikey|secret|token|auth)[-_]?(key)?['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,})['\"]?"

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
    CYAN = '\033[96m'

class ShadowCrawl:
    def __init__(self, start_url, depth=2, threads=5, output=None, verbose=False):
        self.start_url = start_url
        self.max_depth = depth
        self.threads = threads
        self.output = output
        self.verbose = verbose
        
        self.visited = set()
        self.assets = {
            "emails": set(),
            "phones": set(),
            "js_files": set(),
            "external_links": set(),
            "forms": [],
            "comments": set(),
            "secrets": set()
        }
        
        self.queue_lock = threading.Lock()
        self.session = requests.Session()
        
        # Determine strict scope
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc

    def print_banner(self):
        banner = f"""{Colors.HEADER}
        ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
        ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
        ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
        ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
        ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
        ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: ShadowCrawl v{VERSION} ]
        [ Advanced Web Spider, Secret Hunter & Asset Mapper ]
        {Colors.ENDC}"""
        print(banner)

    def get_random_headers(self):
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }

    def analyze_content(self, html, url):
        """
        Deep inspection of HTML content for juicy details.
        """
        # 1. Email Extraction
        new_emails = set(re.findall(EMAIL_REGEX, html))
        if new_emails:
            with self.queue_lock:
                for email in new_emails:
                    if email not in self.assets["emails"]:
                        print(f"{Colors.GREEN}[+] EMAIL: {email} (from {url}){Colors.ENDC}")
                        self.assets["emails"].add(email)

        # 2. Phone Extraction
        new_phones = set(re.findall(PHONE_REGEX, html))
        if new_phones:
            with self.queue_lock:
                for phone in new_phones:
                    # Basic filter to remove false positives like CSS versions or dates
                    if len(phone) >= 10 and phone not in self.assets["phones"]:
                        # print(f"{Colors.GREEN}[+] PHONE: {phone}{Colors.ENDC}") 
                        self.assets["phones"].add(phone)

        # 3. Secret Hunting (Regex)
        matches = re.findall(API_KEY_REGEX, html, re.IGNORECASE)
        if matches:
            with self.queue_lock:
                for m in matches:
                    secret_str = "".join(m)
                    if secret_str not in self.assets["secrets"]:
                        print(f"{Colors.FAIL}[!] POTENTIAL SECRET: {secret_str} (in {url}){Colors.ENDC}")
                        self.assets["secrets"].add(secret_str)

        soup = BeautifulSoup(html, "html.parser")

        # 4. JS Files
        for script in soup.find_all("script"):
            src = script.attrs.get("src")
            if src:
                js_url = urljoin(url, src)
                with self.queue_lock:
                    if js_url not in self.assets["js_files"]:
                        print(f"{Colors.WARNING}[J] SCRIPT: {js_url}{Colors.ENDC}")
                        self.assets["js_files"].add(js_url)

        # 5. Extract Comments (Devs often leave clues)
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for c in comments:
            c = c.strip()
            if len(c) > 5: # Filter empty comments
                with self.queue_lock:
                    if c not in self.assets["comments"]:
                         self.assets["comments"].add(c)
                         if self.verbose:
                             print(f"{Colors.CYAN}[C] Comment found: {c[:60]}...{Colors.ENDC}")

        # 6. Form Analysis (Input Vectors)
        forms = soup.find_all("form")
        for form in forms:
            action = form.attrs.get("action", "")
            method = form.attrs.get("method", "get").upper()
            inputs = [i.attrs.get("name") for i in form.find_all("input") if i.attrs.get("name")]
            
            form_data = {
                "page": url,
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs
            }
            
            with self.queue_lock:
                self.assets["forms"].append(form_data)
                print(f"{Colors.BLUE}[F] FORM: {method} {action} | Params: {', '.join(inputs)}{Colors.ENDC}")

        return soup

    def crawl_recursive(self, url, depth):
        if depth > self.max_depth:
            return

        with self.queue_lock:
            if url in self.visited:
                return
            self.visited.add(url)

        prefix = "  " * depth
        print(f"{prefix}{Colors.BLUE}[*] Crawling: {url}{Colors.ENDC}")

        try:
            # Random delay to avoid WAF limiting
            time.sleep(random.uniform(0.1, 0.5))
            
            try:
                response = self.session.get(url, headers=self.get_random_headers(), timeout=10, verify=False)
            except requests.exceptions.SSLError:
                # Retry without verifying verify=False logic handled above but explicit pass
                pass
            except Exception as e:
                if self.verbose:
                    print(f"{Colors.FAIL}[-] Failed to fetch {url}: {e}{Colors.ENDC}")
                return

            if response.status_code != 200:
                pass # Ignore non-200 for recursion, but maybe log?

            # Analyze content
            if "text/html" in response.headers.get("Content-Type", ""):
                 soup = self.analyze_content(response.text, url)
                 
                 if soup:
                     # Find next links
                     links = soup.find_all("a")
                     for link in links:
                         href = link.attrs.get("href")
                         if not href or href.startswith("#") or href.startswith("mailto:"):
                             continue
                         
                         full_url = urljoin(url, href)
                         
                         # Check Scope
                         parsed_link = urlparse(full_url)
                         
                         # If same domain, keep recursion
                         if parsed_link.netloc == self.base_domain:
                             self.crawl_recursive(full_url, depth + 1)
                         elif parsed_link.netloc:
                             # External Link
                             with self.queue_lock:
                                 if full_url not in self.assets["external_links"]:
                                     self.assets["external_links"].add(full_url)
        except Exception as e:
            pass

    def save_report(self):
        if not self.output:
            return
        
        print(f"\n{Colors.BLUE}[*] Saving report to {self.output}...{Colors.ENDC}")
        
        # Convert sets to lists for JSON serialization
        report = {
            "target": self.start_url,
            "scan_time": str(datetime.now()),
            "stats": {
                "pages_visited": len(self.visited),
                "emails_found": len(self.assets["emails"]),
                "forms_found": len(self.assets["forms"])
            },
            "data": {
                "emails": list(self.assets["emails"]),
                "phones": list(self.assets["phones"]),
                "js_files": list(self.assets["js_files"]),
                "external_links": list(self.assets["external_links"]),
                "secrets": list(self.assets["secrets"]),
                "forms": self.assets["forms"],
                "comments": list(self.assets["comments"])
            }
        }
        
        try:
            with open(self.output, "w") as f:
                json.dump(report, f, indent=4)
            print(f"{Colors.GREEN}[+] Report saved successfully.{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Failed to save report: {e}{Colors.ENDC}")

    def run(self):
        self.print_banner()
        
        # Suppress SSL Warnings
        requests.packages.urllib3.disable_warnings() 
        
        print(f"{Colors.BLUE}[*] Target: {self.start_url}")
        print(f"[*] Max Depth: {self.max_depth}")
        print(f"[*] Scope: {self.base_domain}{Colors.ENDC}")
        print("-" * 60)
        
        self.crawl_recursive(self.start_url, 0)
        
        print("-" * 60)
        print(f"{Colors.BOLD}SCAN COMPLETE{Colors.ENDC}")
        print(f"Pages Visited: {len(self.visited)}")
        print(f"Emails Found: {len(self.assets['emails'])}")
        print(f"Secrets Found: {len(self.assets['secrets'])}")
        print(f"JS Files Found: {len(self.assets['js_files'])}")
        
        self.save_report()

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"ShadowCrawl v{VERSION} | Recursive Web Spider",
        epilog="Do not use for illegal purposes."
    )
    
    parser.add_argument("url", help="Target URL (including http/https)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawling depth (default: 2)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Concurrent threads (Future impl)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode (show all comments/debug)")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    # Basic URL validation
    if not args.url.startswith("http"):
        print(f"{Colors.FAIL}[!] Invalid URL. Must start with http:// or https://{Colors.ENDC}")
        sys.exit(1)
        
    crawler = ShadowCrawl(
        start_url=args.url,
        depth=args.depth,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose
    )
    
    try:
        crawler.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Crawl interrupted by user.{Colors.ENDC}")
        crawler.save_report()
        sys.exit(0)

if __name__ == "__main__":
    main()
