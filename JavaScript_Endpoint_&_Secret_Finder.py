import re
import requests
from urllib.parse import urljoin

JS_REGEX = r'src=["\'](.*?\.js)["\']'
ENDPOINT_REGEX = r'(/api/[^"\']+|/v[0-9]+/[^"\']+)'
SECRET_REGEX = r'(apiKey|token|secret)["\']?\s*[:=]\s*["\']([^"\']+)'

def get_js_files(url):
    r = requests.get(url, timeout=10)
    return re.findall(JS_REGEX, r.text)

def analyze_js(js_url):
    data = requests.get(js_url, timeout=10).text
    endpoints = re.findall(ENDPOINT_REGEX, data)
    secrets = re.findall(SECRET_REGEX, data)
    return set(endpoints), secrets

def main(target):
    js_files = get_js_files(target)
    for js in js_files:
        full_url = urljoin(target, js)
        endpoints, secrets = analyze_js(full_url)

        print(f"\n[+] JS File: {full_url}")
        for e in endpoints:
            print(f"  API Endpoint: {e}")

        for s in secrets:
            print(f"  Possible Secret: {s}")

if __name__ == "__main__":
    target_url = input("Target URL: ")
    main(target_url)
