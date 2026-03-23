"""
Basic reconnaissance tool for domains.
Performs IP resolution, DNS record lookup, subdomain checking, and website fingerprinting.
"""

import sys
import socket
import dns.resolver
import requests
from bs4 import BeautifulSoup


def get_ip(domain):
    """
    Resolve the IP address of a given domain.

    Args:
        domain (str): The domain name to resolve.

    Returns:
        str or None: The IP address if resolved, None otherwise.
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return ["No records found"]


def check_common_subdomains(domain):
    """
    Check for common subdomains of a domain.

    Args:
        domain (str): The domain name.

    Returns:
        list: List of found subdomains with their IPs.
    """
    common_subs = [
        "www", "mail", "vpn", "admin", "dev", "test", "staging",
        "api", "app", "portal", "login", "remote", "webmail"
    ]
    found = []
    for sub in common_subs:
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            found.append(f"{full} → {ip}")
        except socket.gaierror:
            pass
    return found


def get_title_and_server(url):
    """
    Fetch the title and server header from a URL.

    Args:
        url (str): The URL to check.

    Returns:
        tuple: (title, server, status_code)
    """
    try:
        r = requests.get(url, timeout=8, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
        server = r.headers.get('Server', 'Not disclosed')
        return title, server, r.status_code
    except (requests.exceptions.RequestException, ValueError) as e:
        return "Error", str(e), None


def main():
    """
    Main function to perform reconnaissance on a target domain.
    """
    if len(sys.argv) != 2:
        print("Usage: python3 recon.py <domain>")
        sys.exit(1)

    target = sys.argv[1].strip()
    print(f"\n[+] Starting basic recon on: {target}\n{'='*60}")

    # IP
    ip = get_ip(target)
    print(f"Main IP:          {ip or 'Not resolved'}")

    # DNS records
    for rtype in ['A', 'MX', 'NS', 'TXT']:
        records = get_dns_records(target, rtype)
        print(f"{rtype} records:     {', '.join(records[:3])}{' ...' if len(records)>3 else ''}")

    # Common subdomains
    print("\nPossible interesting subdomains:")
    subs = check_common_subdomains(target)
    if subs:
        for s in subs[:8]:  # limit output
            print(f"  - {s}")
        if len(subs) > 8:
            print(f"  ... and {len(subs)-8} more")
    else:
        print("  None found in quick scan")

    # Website fingerprint
    print("\nMain website fingerprint:")
    urls_to_check = [f"http://{target}", f"https://{target}"]
    for url in urls_to_check:
        title, server, code = get_title_and_server(url)
        print(f"  {url}")
        print(f"    Status: {code or 'Failed'}")
        print(f"    Title:  {title}")
        print(f"    Server: {server}")

    print("\n[+] Recon finished. Next steps?")
    print("   • Check subdomains manually with dnsdumpster / subfinder")
    print("   • Look for exposed panels (admin/, login/, etc)")
    print("   • Try whatweb / wappalyzer for tech stack")


if __name__ == "__main__":
    main()
