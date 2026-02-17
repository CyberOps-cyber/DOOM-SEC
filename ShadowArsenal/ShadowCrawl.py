
import requests
from bs4 import BeautifulSoup
import sys
import argparse
from urllib.parse import urljoin, urlparse
import re

# ShadowCrawl - Advanced Web Crawler & Recon Tool
# Part of DOOM-SEC ShadowArsenal

visited_urls = set()
external_urls = set()
emails = set()
js_files = set()

def banner():
    print("""
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ 
    
    [ ShadowCrawl v1.0 | Web Spider & Asset Extractor ]
    [ Part of DOOM-SEC | ShadowArsenal ]
    """)

def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def crawl(url, max_depth, current_depth=0):
    if current_depth > max_depth:
        return
    
    if url in visited_urls:
        return

    print(f"[*] Crawling: {url}")
    visited_urls.add(url)

    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Extract Emails
        new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I))
        if new_emails:
            print(f"  [!] Found Emails: {', '.join(new_emails)}")
            emails.update(new_emails)

        # Extract JS Files
        for script in soup.find_all("script"):
            if script.attrs.get("src"):
                js_url = urljoin(url, script.attrs.get("src"))
                if js_url not in js_files:
                    print(f"  [J] JS Asset: {js_url}")
                    js_files.add(js_url)

        # Find Links
        for link in soup.find_all("a"):
            href = link.attrs.get("href")
            if href == "" or href is None:
                continue
            
            full_url = urljoin(url, href)
            
            if is_valid(full_url):
                if urlparse(full_url).netloc == urlparse(url).netloc:
                    crawl(full_url, max_depth, current_depth + 1)
                else:
                    if full_url not in external_urls:
                        print(f"  [E] External Link: {full_url}")
                        external_urls.add(full_url)
                        
    except Exception as e:
        print(f"[-] Error crawling {url}: {e}")

def main():
    banner()
    if len(sys.argv) < 2:
        print("Usage: python ShadowCrawl.py <URL> [Depth (Default 2)]")
        sys.exit(1)
        
    target_url = sys.argv[1]
    depth = 2
    if len(sys.argv) > 2:
        depth = int(sys.argv[2])
    
    print(f"[*] Starting ShadowCrawl on {target_url} (Depth: {depth})\n")
    crawl(target_url, depth)
    
    print("\n" + "="*40)
    print("[-] Crawl Complete Check Report")
    print(f"[-] Total Pages Visited: {len(visited_urls)}")
    print(f"[-] Emails Found: {len(emails)}")
    print(f"[-] JS Files Found: {len(js_files)}")
    print("="*40)

if __name__ == "__main__":
    main()
