
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | MetaMantis
Author: CyberOps
Version: 3.0.0
"""

import os
import sys
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import argparse
import time
import json
import hashlib
from datetime import datetime

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "MetaMantis"
SUPPORTED_EXTENSIONS = ['pdf', 'docx', 'xlsx', 'pptx', 'jpg', 'jpeg', 'png']

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

# Check dependencies
try:
    import PyPDF2
except ImportError:
    print(Colors.FAIL + "[-] PyPDF2 not installed. Install with: pip install PyPDF2" + Colors.ENDC)
    # Don't exit, just disable PDF features

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    pass # Image analysis disabled

# ==============================================================================
# CORE TOOL LOGIC
# ==============================================================================

class MetaMantis:
    def __init__(self, target, file_types=None, output_dir=None, json_report=None):
        self.target = target
        self.file_types = file_types if file_types else ['pdf']
        self.output_dir = output_dir if output_dir else "metamantis_downloads"
        self.json_report = json_report
        
        self.metadata_db = [] # List of dicts
        self.users_found = set()
        self.software_found = set()
        self.emails_found = set()

    def print_banner(self):
        banner = f"""{Colors.HEADER}
        ███╗   ███╗███████╗████████╗██████╗ 
        ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗
        ██╔████╔██║█████╗     ██║   ██████╔╝
        ██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗
        ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║
        ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: MetaMantis v{VERSION} ]
        [ Corporate Metadata Harvester & Document Hunter ]
        {Colors.ENDC}"""
        print(banner)

    def calculate_hash(self, file_path):
        """Calculates SHA256 of downloaded file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "error"

    def analyze_pdf(self, file_path):
        """
        Extracts metadata using PyPDF2
        """
        if 'PyPDF2' not in sys.modules:
            return {}
            
        result = {}
        try:
            with open(file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                info = pdf.metadata
                
                if info:
                    # Clean up keys (remove leading /)
                    for k, v in info.items():
                        key = k.replace('/', '')
                        result[key] = str(v)
                        
                        # Intelligence Extraction
                        if 'Author' in key and v:
                            self.users_found.add(v)
                        if 'Creator' in key and v:
                            self.software_found.add(v)
                        if 'Producer' in key and v:
                            self.software_found.add(v)
        except Exception as e:
            # print(f"Error reading PDF: {e}")
            pass
        return result

    def analyze_image(self, file_path):
        """
        Extracts EXIF from images using Pillow
        """
        if 'PIL' not in sys.modules:
            return {}
            
        result = {}
        try:
            image = Image.open(file_path)
            exifdata = image.getexif()
            if exifdata:
                for tag_id, data in exifdata.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if isinstance(data, bytes):
                        try:
                            data = data.decode()
                        except:
                            data = str(data)
                    result[str(tag)] = str(data)
                    
                    if str(tag) == "Software" and data:
                        self.software_found.add(data)
                    if str(tag) == "Artist" and data:
                        self.users_found.add(data)
        except:
            pass
        return result

    def process_file(self, file_path, source_url="Local"):
        filename = os.path.basename(file_path)
        ext = filename.split('.')[-1].lower()
        
        print(f"{Colors.BLUE}[*] Analyzing: {filename}{Colors.ENDC}")
        
        meta = {}
        if ext == 'pdf':
            meta = self.analyze_pdf(file_path)
        elif ext in ['jpg', 'jpeg', 'png']:
            meta = self.analyze_image(file_path)
        else:
            # Placeholder for other text files or python-docx integration
            pass
            
        if meta:
            # Print interesting findings immediately
            if 'Author' in meta:
                print(f"    {Colors.GREEN}-> Author: {meta['Author']}{Colors.ENDC}")
            if 'Producer' in meta:
                print(f"    {Colors.WARNING}-> Software: {meta['Producer']}{Colors.ENDC}")
            
            # Store full record
            record = {
                "filename": filename,
                "local_path": file_path,
                "source": source_url,
                "file_hash": self.calculate_hash(file_path),
                "metadata": meta
            }
            self.metadata_db.append(record)
        else:
            print(f"    {Colors.FAIL}-> No metadata found.{Colors.ENDC}")

    def download_mode(self):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        print(f"{Colors.BLUE}[*] Crawling {self.target} for {self.file_types}...{Colors.ENDC}")
        
        try:
            # Headers to mimic browser
            headers = {'User-Agent': 'Mozilla/5.0'}
            r = requests.get(self.target, headers=headers, timeout=10, verify=False)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            links = soup.find_all('a')
            download_queue = []
            
            for link in links:
                href = link.attrs.get('href')
                if not href:
                    continue
                
                # Check extension
                for ftype in self.file_types:
                    if href.lower().endswith(f".{ftype}"):
                        full_url = urljoin(self.target, href)
                        download_queue.append(full_url)
                        break
            
            # Unique links
            download_queue = list(set(download_queue))
            print(f"{Colors.GREEN}[+] Found {len(download_queue)} matching documents.{Colors.ENDC}")
            
            for url in download_queue:
                filename = url.split('/')[-1]
                # Avoid overwriting or weird chars
                filename = "".join([c for c in filename if c.isalpha() or c.isdigit() or c in '._-'])
                local_path = os.path.join(self.output_dir, filename)
                
                print(f"  [D] Downloading {filename}...")
                try:
                    file_resp = requests.get(url, headers=headers, timeout=15)
                    with open(local_path, 'wb') as f:
                        f.write(file_resp.content)
                    
                    # Analyze immediately
                    self.process_file(local_path, source_url=url)
                    
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"    {Colors.FAIL}Error: {e}{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Critical Crawler Error: {e}{Colors.ENDC}")

    def report(self):
        print("\n" + "=" * 60)
        print(f"{Colors.BOLD}METAMANTIS INTELLIGENCE SUMMARY{Colors.ENDC}")
        print("=" * 60)
        
        print(f"Files Analyzed: {len(self.metadata_db)}")
        
        if self.users_found:
            print(f"\n{Colors.GREEN}[+] IDENTIFIED USERS / AUTHORS:{Colors.ENDC}")
            for u in self.users_found:
                print(f"    - {u}")
                
        if self.software_found:
            print(f"\n{Colors.WARNING}[+] SOFTWARE VERSIONS:{Colors.ENDC}")
            for s in self.software_found:
                print(f"    - {s}")

        if self.json_report:
            try:
                with open(self.json_report, "w") as f:
                    json.dump(self.metadata_db, f, indent=4)
                print(f"\n{Colors.BLUE}[*] Detailed JSON report saved to {self.json_report}{Colors.ENDC}")
            except:
                print(f"{Colors.FAIL}[!] Failed to write JSON report.{Colors.ENDC}")

    def run(self):
        self.print_banner()
        
        requests.packages.urllib3.disable_warnings()
        
        if self.target.startswith("http"):
            self.download_mode()
        elif os.path.isfile(self.target):
            self.process_file(self.target)
        elif os.path.isdir(self.target):
            print(f"{Colors.BLUE}[*] Scanning Local Directory: {self.target}{Colors.ENDC}")
            for root, dirs, files in os.walk(self.target):
                for file in files:
                    ext = file.split('.')[-1].lower()
                    if ext in self.file_types:
                        full_path = os.path.join(root, file)
                        self.process_file(full_path)
                        
        self.report()

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"MetaMantis v{VERSION}",
        epilog="Supported formats: " + ", ".join(SUPPORTED_EXTENSIONS)
    )
    
    parser.add_argument("target", help="Target URL (to crawl) OR Local File/Directory")
    parser.add_argument("-t", "--types", help="Comma-separated file types (default: pdf,docx,xlsx)")
    parser.add_argument("-o", "--output-dir", help="Directory to save downloaded files (default: metamantis_downloads)")
    parser.add_argument("-r", "--report", help="JSON report file output")
    
    args = parser.parse_args()
    
    # Parse types
    target_types = ['pdf']
    if args.types:
        target_types = [t.strip() for t in args.types.split(',')]
    else:
        # Default set
        target_types = ['pdf', 'docx', 'xlsx', 'pptx']
        
    mantis = MetaMantis(
        target=args.target,
        file_types=target_types,
        output_dir=args.output_dir,
        json_report=args.report
    )
    
    try:
        mantis.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted by user.{Colors.ENDC}")
        mantis.report()
        sys.exit(0)

if __name__ == "__main__":
    main()
