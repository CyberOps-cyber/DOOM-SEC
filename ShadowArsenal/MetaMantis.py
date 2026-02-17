
import os
import sys
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
try:
    import PyPDF2
except ImportError:
    pass

# MetaMantis - Document Metadata Extractor
# Part of DOOM-SEC ShadowArsenal

def banner():
    print("""
    ███╗   ███╗███████╗████████╗██████╗ 
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗
    ██╔████╔██║█████╗     ██║   ██████╔╝
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██╗
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝
    
    [ MetaMantis v1.0 | Metadata Extraction Hunter ]
    [ Part of DOOM-SEC | ShadowArsenal ]
    """)

def analyze_pdf(file_path):
    print(f"[*] Analyzing: {file_path}")
    try:
        if 'PyPDF2' not in sys.modules:
            print("[-] PyPDF2 not installed. Cannot analyze PDF internal metadata.")
            return

        with open(file_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            info = pdf.metadata
            if info:
                for k, v in info.items():
                    print(f"  [+] {k}: {v}")
            else:
                print("  [-] No metadata found.")
    except Exception as e:
        print(f"[-] Error reading PDF: {e}")

def download_docs(url):
    print(f"[*] Scouring {url} for documents...")
    try:
        r = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        soup = BeautifulSoup(r.text, 'html.parser')
        
        target_dir = "downloaded_docs"
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)
            
        count = 0
        for link in soup.find_all('a'):
            href = link.attrs.get('href')
            if href and href.lower().endswith('.pdf'):
                full_url = urljoin(url, href)
                filename = os.path.join(target_dir, href.split('/')[-1])
                print(f"  [D] Downloading {href}...")
                
                with open(filename, 'wb') as f:
                    f.write(requests.get(full_url).content)
                analyze_pdf(filename)
                count += 1
                
        print(f"[*] Finished. Analyzed {count} documents.")
        
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    banner()
    if len(sys.argv) < 2:
        print("Usage: python MetaMantis.py <Target_URL> OR <Local_File_Path>")
        sys.exit(1)
        
    target = sys.argv[1]
    
    if target.startswith("http"):
        download_docs(target)
    elif os.path.isfile(target):
        if target.endswith(".pdf"):
            analyze_pdf(target)
        else:
            print("[-] Currently supports PDF analysis only.")
    else:
        print("[-] Invalid target.")

if __name__ == "__main__":
    main()
