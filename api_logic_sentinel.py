import requests
import json
import time
import sys
import uuid
from typing import Dict, List

BANNER = r"""
   ___    ____  ____    _      ____   ____ ___  _   _ _____ _     
  / _ \  |  _ \|  _ \  | |    / ___| / ___/ _ \| \ | |_   _| |    
 | | | | | |_) | |_) | | |    \___ \| |  | | | |  \| | | | | |    
 | |_| | |  __/|  __/  | |___  ___) | |__| |_| | |\  | | | | |___ 
  \___/  |_|   |_|     |_____| |____/ \____\___/|_| \_| |_| |_____|
"""

class APILogicSentinel:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "API-Logic-Sentinel/1.0"
        }
        self.results = []

    def request(self, method: str, endpoint: str, data=None):
        url = f"{self.base_url}{endpoint}"
        try:
            r = requests.request(
                method,
                url,
                headers=self.headers,
                json=data,
                timeout=10
            )
            return {
                "status": r.status_code,
                "length": len(r.text),
                "body": r.text
            }
        except Exception as e:
            return {"error": str(e)}

    def baseline(self, endpoint: str):
        return self.request("GET", endpoint)

    def idor_test(self, endpoint: str, obj_id: int):
        findings = []
        original = self.request("GET", endpoint.format(id=obj_id))

        for delta in [-2, -1, 1, 2]:
            test_id = obj_id + delta
            test = self.request("GET", endpoint.format(id=test_id))

            if test.get("status") == original.get("status") \
               and test.get("length") == original.get("length"):
                findings.append({
                    "type": "Possible IDOR",
                    "tested_id": test_id,
                    "status": test.get("status")
                })
        return findings

    def role_confusion_test(self, endpoint: str):
        alt_headers = self.headers.copy()
        alt_headers["Authorization"] = "Bearer " + str(uuid.uuid4())

        try:
            r = requests.get(
                f"{self.base_url}{endpoint}",
                headers=alt_headers,
                timeout=10
            )
            if r.status_code == 200:
                return "Endpoint accessible with invalid token"
        except:
            pass
        return None

    def method_tampering(self, endpoint: str):
        results = []
        for method in ["POST", "PUT", "DELETE", "PATCH"]:
            r = self.request(method, endpoint, {})
            if r.get("status") not in [401, 403, 405]:
                results.append({
                    "method": method,
                    "status": r.get("status")
                })
        return results

    def rate_limit_test(self, endpoint: str, count=10):
        statuses = []
        for _ in range(count):
            r = self.request("GET", endpoint)
            statuses.append(r.get("status"))
            time.sleep(0.2)

        if len(set(statuses)) == 1:
            return "No visible rate limiting detected"
        return None

    def analyze_endpoint(self, endpoint: str, sample_id=None):
        print(f"[+] Testing {endpoint}")
        report = {"endpoint": endpoint}

        report["baseline"] = self.baseline(endpoint)

        if sample_id is not None:
            report["idor"] = self.idor_test(endpoint, sample_id)

        report["method_tampering"] = self.method_tampering(endpoint)

        role_issue = self.role_confusion_test(endpoint)
        if role_issue:
            report["role_confusion"] = role_issue

        rate = self.rate_limit_test(endpoint)
        if rate:
            report["rate_limit"] = rate

        self.results.append(report)

    def save_report(self):
        fname = f"api_logic_report_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Report saved: {fname}")

def main():
    if len(sys.argv) < 4:
        print("Usage:")
        print("python3 api_logic_sentinel.py <BASE_URL> <TOKEN> <ENDPOINT>")
        print("Example:")
        print("python3 api_logic_sentinel.py https://api.site.com eyJ... /api/users/{id}")
        sys.exit(1)

    print(BANNER)

    base = sys.argv[1]
    token = sys.argv[2]
    endpoint = sys.argv[3]

    sentinel = APILogicSentinel(base, token)

    sample_id = None
    if "{id}" in endpoint:
        sample_id = int(input("Enter a valid object ID to test IDOR: "))

    sentinel.analyze_endpoint(endpoint, sample_id)
    sentinel.save_report()

if __name__ == "__main__":
    main()
    