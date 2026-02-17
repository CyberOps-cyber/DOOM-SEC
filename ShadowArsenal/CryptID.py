
import sys
import re

# CryptID - Hash Type Identifier
# Part of DOOM-SEC ShadowArsenal

def banner():
    print("""
     ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗██████╗ 
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔══██╗
    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║██║  ██║
    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██║  ██║
    ╚██████╗██║  ██║   ██║   ██║        ██║   ██║██████╔╝
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝╚═════╝ 
    
    [ CryptID v1.0 | Hash Algorithm Identifier ]
    [ Part of DOOM-SEC | ShadowArsenal ]
    """)

PATTERNS = [
    (r"^[a-fA-F0-9]{32}$", "MD5 / NTLM / LM"),
    (r"^[a-fA-F0-9]{40}$", "SHA-1 / MySQL5"),
    (r"^[a-fA-F0-9]{56}$", "SHA-224"),
    (r"^[a-fA-F0-9]{64}$", "SHA-256"),
    (r"^[a-fA-F0-9]{96}$", "SHA-384"),
    (r"^[a-fA-F0-9]{128}$", "SHA-512"),
    (r"^\$2[ayb]\$.{56}$", "Bcrypt"),
    (r"^\$1\$.{22}$", "MD5-Crypt (Unix)"),
    (r"^\$5\$.{43}$", "SHA-256-Crypt"),
    (r"^\$6\$.{86}$", "SHA-512-Crypt"),
    (r"^\$P\$.{31}$", "WordPress / PHPass"),
]

def identify_hash(hash_str):
    print(f"[*] Analyzing Hash: {hash_str}")
    print(f"[*] Length: {len(hash_str)}")
    print("-" * 40)
    
    found = False
    for pattern, name in PATTERNS:
        if re.match(pattern, hash_str):
            print(f"[+] Possible Algorithm: {name}")
            found = True
            
    if not found:
        print("[-] No common patterns matched.")
        print("    Could be a salted hash, custom format, or JWT.")

def main():
    banner()
    if len(sys.argv) < 2:
        print("Usage: python CryptID.py <Hash_String>")
        sys.exit(1)
        
    target_hash = sys.argv[1].strip()
    identify_hash(target_hash)

if __name__ == "__main__":
    main()
