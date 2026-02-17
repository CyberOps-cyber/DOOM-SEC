
import dns.resolver
import sys
import requests

# CloudJack - Subdomain Takeover Scanner
# Part of DOOM-SEC ShadowArsenal

def banner():
    print("""
     ██████╗██╗      ██████╗ ██╗   ██╗██████╗      ██╗ █████╗  ██████╗██╗  ██╗
    ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗     ██║██╔══██╗██╔════╝██║ ██╔╝
    ██║     ██║     ██║   ██║██║   ██║██║  ██║     ██║███████║██║     █████╔╝ 
    ██║     ██║     ██║   ██║██║   ██║██║  ██║██   ██║██╔══██║██║     ██╔═██╗ 
    ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝╚█████╔╝██║  ██║╚██████╗██║  ██╗
     ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝  ╚════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    
    [ CloudJack v1.0 | Subdomain Takeover Scanner ]
    [ Part of DOOM-SEC | ShadowArsenal ]
    """)

# Common Signatures for Abandoned Services
SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "amazonaws.com": "The specified bucket does not exist",
    "azurewebsites.net": "404 Web Site not found",
    "bitbucket.org": "Repository not found",
    "ghost.io": "The thing you are looking for is no longer here",
    "wordpress.com": "Do you want to register"
}

def check_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target).rstrip('.')
            print(f"[*] Found CNAME for {domain}: {cname}")
            return cname
    except dns.resolver.NoAnswer:
        print(f"[-] No CNAME found for {domain}")
    except Exception as e:
        print(f"[-] Error resolving {domain}: {e}")
    return None

def check_takeover(domain, cname):
    if not cname:
        return

    vulnerable = False
    
    for service, signature in SIGNATURES.items():
        if service in cname:
            print(f"[*] CNAME {cname} matches known service: {service}")
            print(f"[*] Checking HTTP response for takeover signature...")
            try:
                # Try HTTP and HTTPS
                try:
                    resp = requests.get(f"http://{domain}", timeout=5)
                except:
                    resp = requests.get(f"https://{domain}", timeout=5, verify=False)
                
                if signature in resp.text:
                    print(f"\n[!!!] POTENTIAL TAKEOVER DETECTED ON {domain} [!!!]")
                    print(f"      Service: {service}")
                    print(f"      CNAME: {cname}")
                    print(f"      Signature Found: '{signature}'")
                    vulnerable = True
                    break
                else:
                    print("[-] Signature match failed. Likely claimed or custom page.")
            except Exception as e:
                print(f"[-] Could not connect to {domain}: {e}")

    if not vulnerable:
        print("[-] No common takeover signatures detected.")

def main():
    banner()
    if len(sys.argv) < 2:
        print("Usage: python CloudJack.py <Subdomain/List>")
        print("       python CloudJack.py targets.txt")
        sys.exit(1)
        
    target_input = sys.argv[1]
    
    targets = []
    
    if "." in target_input and not target_input.endswith(".txt"):
         targets.append(target_input)
    else:
        try:
            with open(target_input, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
        except:
             print("[-] File not found.")
             sys.exit(1)

    print(f"[*] Loading {len(targets)} targets...\n")
    
    for t in targets:
        print(f"--- Checking {t} ---")
        cname = check_cname(t)
        check_takeover(t, cname)
        print("")

if __name__ == "__main__":
    main()
