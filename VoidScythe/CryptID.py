
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | CryptID
Author: CyberOps
Version: 3.0.0
"""

import sys
import re
import argparse
import base64
import binascii
import json
import time
from datetime import datetime

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "CryptID"

# ------------------------------------------------------------------------------
# PATTERN DATABASE
# Format: (Regex, Algorithm Name, Hashcat Mode, John Format)
# ------------------------------------------------------------------------------
PATTERNS = [
    (r"^[a-fA-F0-9]{32}$", "MD5", "0", "raw-md5"),
    (r"^[a-fA-F0-9]{32}$", "NTLM", "1000", "nt"),
    (r"^[a-fA-F0-9]{32}$", "Domain Cached Credentials (DCC)", "1100", "mscash"),
    (r"^[a-fA-F0-9]{40}$", "SHA-1", "100", "raw-sha1"),
    (r"^[a-fA-F0-9]{40}$", "MySQL 4.1+", "300", "mysql-sha1"),
    (r"^[a-fA-F0-9]{56}$", "SHA-224", "1300", "raw-sha224"),
    (r"^[a-fA-F0-9]{64}$", "SHA-256", "1400", "raw-sha256"),
    (r"^[a-fA-F0-9]{64}$", "GOST R 34.11-94", "6900", "gost"),
    (r"^[a-fA-F0-9]{96}$", "SHA-384", "10800", "raw-sha384"),
    (r"^[a-fA-F0-9]{128}$", "SHA-512", "1700", "raw-sha512"),
    (r"^[a-fA-F0-9]{128}$", "Whirlpool", "6100", "whirlpool"),
    (r"^\$2[ayb]\$.{56}$", "Bcrypt (Blowfish)", "3200", "bcrypt"),
    (r"^\$1\$.{22}$", "MD5-Crypt (Unix)", "500", "md5crypt"),
    (r"^\$5\$.{43}$", "SHA-256-Crypt", "7400", "sha256crypt"),
    (r"^\$6\$.{86}$", "SHA-512-Crypt", "1800", "sha512crypt"),
    (r"^\$P\$.{31}$", "WordPress / PHPass", "400", "phpass"),
    (r"^[a-fA-F0-9]{16}$", "MySQL323 / DES(Oracle)", "200", "mysql"),
    (r"^(\$3\$\$)[a-fA-F0-9]{32}$", "NTLMv2", "5600", "netntlmv2"),
    (r"^sha1\$[a-zA-Z0-9]+\$[a-fA-F0-9]{40}$", "Django (SHA-1)", "124", "django-sha1"),
    (r"^pbkdf2_sha256\$[0-9]+\$[a-zA-Z0-9.\/+]+\$[a-zA-Z0-9.\/]+=$", "Django (PBKDF2-SHA256)", "10000", "django-sha256"),
    (r"^(\$argon2).+$", "Argon2", "Unknown", "argon2"),
    (r"^[A-Za-z0-9+/]{22}==$", "Base64 (Generic)", "N/A", "N/A"),
    (r"^[a-fA-F0-9]{48}$", "Haval-192", "Unknown", "haval-192"),
    (r"^[a-fA-F0-9]{160}$", "RIPEMD-320", "Unknown", "ripemd-320"),
    (r"^\$H\$.{31}$", "phpBB v3.x", "400", "phpass"),
    (r"^:([0-9]{4}):([a-f0-9]+):([a-f0-9]+)$", "IPMI2 RAKP", "7300", "rakp"),
    (r"^sqrl:[a-fA-F0-9]{45}$", "SQRL", "Unknown", "sqrl"),
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

class CryptID:
    def __init__(self, hash_input, verbose=False):
        self.hash_input = hash_input.strip()
        self.verbose = verbose
        self.results = []
        self.is_file = False
        
        # Check if input is file
        try:
            with open(self.hash_input, 'r') as f:
                self.file_content = [line.strip() for line in f if line.strip()]
            self.is_file = True
        except:
            self.file_content = None

    def print_banner(self):
        banner = f"""{Colors.HEADER}
         ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗██████╗ 
        ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔══██╗
        ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██║  ██║
        ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██║  ██║
        ╚██████╗██║  ██║   ██║   ██║        ██║   ██║██████╔╝
         ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝╚═════╝ 
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: CryptID v{VERSION} ]
        [ Advanced Hash Anomaly & Algorithm Identifier ]
        {Colors.ENDC}"""
        print(banner)

    def analyze_single(self, hash_str):
        if not hash_str:
            return None

        analysis = {
            "hash": hash_str,
            "length": len(hash_str),
            "matches": []
        }
        
        # Check Character Set
        charset = "Unknown"
        if re.match(r"^[0-9]+$", hash_str):
            charset = "Numeric"
        elif re.match(r"^[a-f0-9]+$", hash_str):
            charset = "Hexadecimal (Lowercase)"
        elif re.match(r"^[A-F0-9]+$", hash_str):
            charset = "Hexadecimal (Uppercase)"
        elif re.match(r"^[a-zA-Z0-9+/=]+$", hash_str):
            charset = "Base64-like"
        else:
            charset = "Mixed / Special Chars"
            
        analysis["charset"] = charset

        # Check Patterns
        for regex, name, mode, john in PATTERNS:
            try:
                if re.match(regex, hash_str):
                     analysis["matches"].append({
                         "algorithm": name,
                         "hashcat": mode,
                         "john": john
                     })
            except:
                pass
        
        return analysis

    def print_analysis(self, result):
        if not result:
            return

        print("-" * 60)
        print(f"{Colors.BLUE}[*] Target Hash: {result['hash'][:50]}..." + Colors.ENDC)
        print(f"{Colors.BLUE}[*] Length: {result['length']} | Charset: {result['charset']}{Colors.ENDC}")
        print("-" * 60)

        if result['matches']:
            print(f"{Colors.GREEN}[+] POTENTIAL ALGORITHMS:{Colors.ENDC}\n")
            print(f"{'Algorithm Name':<30} {'Hashcat':<10} {'John The Ripper':<15}")
            print("-" * 60)
            
            for m in result['matches']:
                print(f"{Colors.BOLD}{m['algorithm']:<30}{Colors.ENDC} {m['hashcat']:<10} {m['john']:<15}")
                
            print("\n" + Colors.WARNING + "[!] Recommendation:" + Colors.ENDC)
            best_match = result['matches'][0]
            if best_match['hashcat'] != "Unknown" and best_match['hashcat'] != "N/A":
                print(f"    hashcat -m {best_match['hashcat']} hash.txt wordlist.txt")
            else:
                 print("    Try using 'HashID' or online decoders for complex formats.")
        else:
            print(f"{Colors.FAIL}[-] No standard database matches found.{Colors.ENDC}")
            self.heuristic_analysis(result['hash'])

    def heuristic_analysis(self, hash_str):
        print("\n" + Colors.CYAN + "[?] Heuristic Analysis:" + Colors.ENDC)
        
        # Check Base64
        try:
            decoded = base64.b64decode(hash_str).decode('utf-8')
            if decoded.isprintable():
                print(f"    -> Base64 Decoded: {decoded}")
        except:
            pass
            
        # Check JWT
        if hash_str.count('.') == 2 and hash_str.startswith('eyJ'):
            print("    -> Looks like a JWT (JSON Web Token). Use jwt_tool.")
            
        # Check Salts
        if ":" in hash_str:
            parts = hash_str.split(':')
            print(f"    -> Detected delimiter ':'. Possible Salted Hash.")
            print(f"       Part 1 ({len(parts[0])} chars): {parts[0]}")
            print(f"       Part 2 ({len(parts[1])} chars): {parts[1]}")

    def run(self):
        self.print_banner()
        
        if self.is_file:
            print(f"{Colors.BLUE}[*] Bulk Mode: Analyzing {len(self.file_content)} hashes from file.{Colors.ENDC}")
            for h in self.file_content:
                res = self.analyze_single(h)
                self.print_analysis(res)
                # Small pause for readability
                # time.sleep(0.1) 
        else:
            res = self.analyze_single(self.hash_input)
            self.print_analysis(res)

# ==============================================================================
# MAIN ENTRY
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"CryptID v{VERSION} | Hash Analyzer",
        epilog="Identify, Analyze, Crack."
    )
    
    parser.add_argument("input", help="Hash string OR File containing hashes")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    identifier = CryptID(args.input, args.verbose)
    
    try:
        identifier.run()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
