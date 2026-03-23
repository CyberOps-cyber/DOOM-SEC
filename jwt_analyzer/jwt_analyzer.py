import jwt
import base64
import json

def decode_jwt(token):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload
    except Exception as e:
        print("Error decoding token:", e)
        return None, None

def analyze(header, payload):
    print("\n[+] JWT Header:")
    print(json.dumps(header, indent=2))

    print("\n[+] JWT Payload:")
    print(json.dumps(payload, indent=2))

    print("\n[!] Analysis:")

    alg = header.get("alg", "")
    if alg.lower() == "none":
        print("- Token uses alg:none (CRITICAL)")

    if alg.startswith("HS"):
        print("- Symmetric algorithm detected (check key handling)")

    required_claims = ["exp", "iat", "iss", "aud"]
    for claim in required_claims:
        if claim not in payload:
            print(f"- Missing claim: {claim}")

if __name__ == "__main__":
    token = input("Paste JWT token: ").strip()
    header, payload = decode_jwt(token)
    if header and payload:
        analyze(header, payload)
