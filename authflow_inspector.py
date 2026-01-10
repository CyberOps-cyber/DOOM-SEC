import base64
import json
import sys
import time

def decode_jwt(token):
    try:
        header, payload, _ = token.split(".")
        header += "=" * (-len(header) % 4)
        payload += "=" * (-len(payload) % 4)

        decoded_header = json.loads(base64.urlsafe_b64decode(header))
        decoded_payload = json.loads(base64.urlsafe_b64decode(payload))

        return decoded_header, decoded_payload
    except Exception as e:
        return None, None

def analyze(header, payload):
    findings = []

    if not header or not payload:
        findings.append("Invalid JWT structure")
        return findings

    alg = header.get("alg", "")
    if alg.lower() == "none":
        findings.append("JWT uses 'none' algorithm")

    if "exp" not in payload:
        findings.append("No expiration (exp) claim found")
    else:
        if payload["exp"] > time.time() + 31536000:
            findings.append("Token expiration is excessively long")

    if "role" in payload:
        findings.append("Role claim found — test for privilege escalation")

    if "sub" not in payload:
        findings.append("No subject (sub) claim")

    if payload.get("iss") is None:
        findings.append("Missing issuer (iss) claim")

    if payload.get("aud") is None:
        findings.append("Missing audience (aud) claim")

    return findings

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 authflow_inspector.py <JWT_TOKEN>")
        sys.exit(1)

    token = sys.argv[1]
    header, payload = decode_jwt(token)

    print("\n[+] JWT Header:")
    print(json.dumps(header, indent=2))

    print("\n[+] JWT Payload:")
    print(json.dumps(payload, indent=2))

    print("\n[+] Analysis:")
    findings = analyze(header, payload)
    if findings:
        for f in findings:
            print(" -", f)
    else:
        print(" No obvious logic issues detected")

if __name__ == "__main__":
    main()
