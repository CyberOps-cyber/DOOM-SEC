#!/usr/bin/env python3
"""
TokenProbe - Advanced JWT Token Analysis and Vulnerability Detection Utility
Analyzes JWT tokens for weak algorithms, sensitive claims, and signature risks.
"""

import argparse
import base64
import json
import sys
import logging
from typing import Dict, List, Any, Tuple
from datetime import datetime, timezone
import hashlib
import hmac

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class TokenProbe:
    """Advanced JWT analysis and token auditing engine."""
    KNOWN_ALGORITHMS = {
        'HS256': 'HMAC with SHA-256 (symmetric)',
        'HS384': 'HMAC with SHA-384 (symmetric)',
        'HS512': 'HMAC with SHA-512 (symmetric)',
        'RS256': 'RSA with SHA-256 (asymmetric)',
        'RS384': 'RSA with SHA-384 (asymmetric)',
        'RS512': 'RSA with SHA-512 (asymmetric)',
        'ES256': 'ECDSA with SHA-256 (asymmetric)',
        'ES384': 'ECDSA with SHA-384 (asymmetric)',
        'ES512': 'ECDSA with SHA-512 (asymmetric)',
        'PS256': 'RSA PSS with SHA-256 (asymmetric)',
        'PS384': 'RSA PSS with SHA-384 (asymmetric)',
        'PS512': 'RSA PSS with SHA-512 (asymmetric)',
        'none': 'No signature (CRITICAL vulnerability)',
    }

    REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat']
    SENSITIVE_KEYWORDS = ['password', 'secret', 'key', 'token', 'auth', 'private', 'credential']

    def __init__(self, token: str):
        self.token = token
        self.header: Dict[str, Any] = {}
        self.payload: Dict[str, Any] = {}
        self.signature: str = ''
        self.vulnerabilities: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []

    def split_token(self) -> Tuple[str, str, str]:
        """Split JWT into header, payload, and signature sections."""
        parts = self.token.strip().split('.')
        if len(parts) != 3:
            raise ValueError('JWT must contain exactly 3 parts separated by dots')
        return parts[0], parts[1], parts[2]

    def decode_base64url(self, data: str) -> str:
        """Decode base64url encoded data, adding padding when required."""
        raw = data + '=' * ((4 - len(data) % 4) % 4)
        try:
            return base64.urlsafe_b64decode(raw).decode('utf-8')
        except Exception as exc:
            raise ValueError(f'Base64URL decode failed: {exc}')

    def decode_header(self) -> Dict[str, Any]:
        """Decode JWT header and parse JSON."""
        header_b64, _, _ = self.split_token()
        decoded = self.decode_base64url(header_b64)
        self.header = json.loads(decoded)
        return self.header

    def decode_payload(self) -> Dict[str, Any]:
        """Decode JWT payload and parse claims."""
        _, payload_b64, _ = self.split_token()
        decoded = self.decode_base64url(payload_b64)
        self.payload = json.loads(decoded)
        return self.payload

    def get_signature(self) -> str:
        """Extract JWT signature."""
        _, _, signature_b64 = self.split_token()
        self.signature = signature_b64
        return signature_b64

    def analyze_algorithm(self):
        """Analyze algorithm metadata for insecure or weak signing methods."""
        alg = self.header.get('alg', 'unknown')
        self.info.append(f'Algorithm: {alg}')
        if alg == 'none':
            self.vulnerabilities.append("CRITICAL: 'none' algorithm used, signature verification bypass possible")
        elif alg not in self.KNOWN_ALGORITHMS:
            self.warnings.append(f"Unknown algorithm '{alg}' - check implementation")
        else:
            self.info.append(self.KNOWN_ALGORITHMS[alg])
            if alg.startswith('HS'):
                self.warnings.append('Symmetric HMAC algorithm in use - secret sharing risks exist')

    def analyze_timestamps(self):
        """Analyze token timestamp claims for expiration and lifetime.
        """
        now = datetime.now(timezone.utc)
        if 'exp' in self.payload:
            exp = self.payload['exp']
            if isinstance(exp, str) and exp.isdigit():
                exp = int(exp)
            try:
                expiration = datetime.fromtimestamp(exp, tz=timezone.utc)
                if expiration < now:
                    self.vulnerabilities.append(f'Token expired at {expiration.isoformat()}')
                else:
                    delta = expiration - now
                    self.info.append(f'Token expires in {delta.total_seconds() / 3600:.2f} hours')
            except Exception as exc:
                self.warnings.append(f'Cannot parse exp claim: {exc}')
        else:
            self.warnings.append('Missing exp claim')

        if 'iat' in self.payload:
            iat = self.payload['iat']
            if isinstance(iat, str) and iat.isdigit():
                iat = int(iat)
            try:
                issued = datetime.fromtimestamp(iat, tz=timezone.utc)
                self.info.append(f'Token issued at {issued.isoformat()}')
            except Exception as exc:
                self.warnings.append(f'Cannot parse iat claim: {exc}')
        else:
            self.warnings.append('Missing iat claim')

        if 'exp' in self.payload and 'iat' in self.payload:
            try:
                life = int(self.payload['exp']) - int(self.payload['iat'])
                if life > 86400 * 90:
                    self.warnings.append(f'Long token validity window: {life/86400:.1f} days')
            except Exception:
                pass

    def analyze_claims(self):
        """Analyze payload claims for privacy and security issues."""
        claims = set(self.payload.keys())
        missing = [claim for claim in self.REQUIRED_CLAIMS if claim not in claims]
        if missing:
            self.warnings.append(f'Missing required claims: {", ".join(missing)}')

        for key, value in self.payload.items():
            if isinstance(value, str) and any(kw in key.lower() for kw in self.SENSITIVE_KEYWORDS):
                self.warnings.append(f"Sensitive claim name detected: {key}")
            if isinstance(value, (dict, list)):
                self._search_nested_claims(key, value)

    def _search_nested_claims(self, parent_key: str, value: Any):
        """Recursively search nested claims for sensitive keys."""
        if isinstance(value, dict):
            for key, nested in value.items():
                combined = f'{parent_key}.{key}'
                if any(kw in key.lower() for kw in self.SENSITIVE_KEYWORDS):
                    self.warnings.append(f'Sensitive nested claim detected: {combined}')
                self._search_nested_claims(combined, nested)
        elif isinstance(value, list):
            for item in value:
                self._search_nested_claims(parent_key, item)

    def analyze_signature(self):
        """Analyze signature entropy and decode signature bytes."""
        sig = self.signature
        if not sig:
            self.warnings.append('No signature part found in token')
            return
        try:
            decoded = base64.urlsafe_b64decode(sig + '=' * ((4 - len(sig) % 4) % 4))
            self.info.append(f'Signature length: {len(decoded)} bytes')
            if len(decoded) < 16:
                self.warnings.append('Signature appears unusually short')
        except Exception as exc:
            self.warnings.append(f'Signature decode failed: {exc}')

    def analyze_vulnerabilities(self):
        """Run all analysis checks against the token."""
        self.decode_header()
        self.decode_payload()
        self.get_signature()
        self.analyze_algorithm()
        self.analyze_timestamps()
        self.analyze_claims()
        self.analyze_signature()

        token_text = json.dumps(self.payload)
        if any(keyword in token_text.lower() for keyword in ['password', 'secret', 'private', 'key', 'token']):
            self.vulnerabilities.append('Potential sensitive data exposure in payload claims')

    def verify_signature(self, secret: str) -> bool:
        """Verify JWT signature using a shared secret for HS* algorithms."""
        alg = self.header.get('alg', 'none')
        if alg not in ['HS256', 'HS384', 'HS512']:
            logger.warning(f'Signature verification only supported for HS-based algorithms, not {alg}')
            return False
        header_b64, payload_b64, signature_b64 = self.split_token()
        message = f'{header_b64}.{payload_b64}'.encode('utf-8')
        hash_map = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        digest = hmac.new(secret.encode('utf-8'), message, hash_map[alg]).digest()
        computed = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        return computed == signature_b64

    def print_analysis(self):
        """Render analysis results to the console."""
        print('\n' + '='*90)
        print('TokenProbe - JWT Token Analysis')
        print('='*90)
        print('\n[HEADER]')
        print(json.dumps(self.header, indent=2))
        print('\n[PAYLOAD]')
        print(json.dumps(self.payload, indent=2))
        if self.vulnerabilities:
            print(f"\n[VULNERABILITIES] ({len(self.vulnerabilities)})")
            for vuln in self.vulnerabilities:
                print(f'  [!] {vuln}')
        if self.warnings:
            print(f"\n[WARNINGS] ({len(self.warnings)})")
            for warning in self.warnings:
                print(f'  [*] {warning}')
        if self.info:
            print(f"\n[INFO] ({len(self.info)})")
            for item in self.info:
                print(f'  [+] {item}')
        severity = 'CRITICAL' if self.vulnerabilities else ('MEDIUM' if self.warnings else 'CLEAN')
        print(f"\n[SEVERITY] {severity}")
        print('='*90 + '\n')

    def export_json(self, output_path: str):
        """Export parsed token data and findings to a JSON file."""
        json_payload = {
            'header': self.header,
            'payload': self.payload,
            'vulnerabilities': self.vulnerabilities,
            'warnings': self.warnings,
            'info': self.info,
        }
        try:
            with open(output_path, 'w', encoding='utf-8') as handle:
                json.dump(json_payload, handle, indent=2)
            logger.info(f'Results written to {output_path}')
        except Exception as exc:
            logger.error(f'Failed to write JSON results: {exc}')

    def export_text(self, output_path: str):
        """Export analysis summary to a plain text file."""
        try:
            with open(output_path, 'w', encoding='utf-8') as handle:
                handle.write('TokenProbe Report\n')
                handle.write('='*60 + '\n')
                handle.write('Header:\n')
                handle.write(json.dumps(self.header, indent=2) + '\n')
                handle.write('Payload:\n')
                handle.write(json.dumps(self.payload, indent=2) + '\n')
                if self.vulnerabilities:
                    handle.write('Vulnerabilities:\n')
                    handle.write('\n'.join(self.vulnerabilities) + '\n')
                if self.warnings:
                    handle.write('Warnings:\n')
                    handle.write('\n'.join(self.warnings) + '\n')
                if self.info:
                    handle.write('Info:\n')
                    handle.write('\n'.join(self.info) + '\n')
            logger.info(f'Text report written to {output_path}')
        except Exception as exc:
            logger.error(f'Failed to write text report: {exc}')

    def validate_token_format(self) -> bool:
        """Validate whether the token loosely matches a JWT structure."""
        parts = self.token.strip().split('.')
        return len(parts) == 3

    @staticmethod
    def decode_segment(segment: str) -> str:
        """Decode a base64url segment and return a decoded UTF-8 string."""
        data = segment + '=' * ((4 - len(segment) % 4) % 4)
        return base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')


def main():
    parser = argparse.ArgumentParser(
        description='TokenProbe - Advanced JWT Token Analysis and Vulnerability Detection',
        epilog='Examples:\n'
               '  python tokenprobe.py eyJhbGci...\n'
               '  python tokenprobe.py -t token.txt\n'
               '  python tokenprobe.py -t token.txt --verify secret123',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('token', nargs='?', help='JWT token string to analyze')
    parser.add_argument('-t', '--token-file', help='Read JWT token from file')
    parser.add_argument('--verify', help='Verify token signature with a shared secret')
    parser.add_argument('--export-json', help='Export analysis report to JSON file')
    parser.add_argument('--export-text', help='Export analysis report to plain text file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    token = args.token
    if not token and args.token_file:
        try:
            with open(args.token_file, 'r', encoding='utf-8') as handle:
                token = handle.read().strip()
        except Exception as exc:
            logger.error(f'Unable to read token file: {exc}')
            sys.exit(1)

    if not token:
        parser.print_help()
        sys.exit(1)

    probe = TokenProbe(token)
    try:
        if not probe.validate_token_format():
            raise ValueError('Token does not appear to be a valid JWT structure')
        probe.analyze_vulnerabilities()
        probe.print_analysis()

        if args.verify:
            valid = probe.verify_signature(args.verify)
            status = 'VALID' if valid else 'INVALID'
            print(f'[+] Signature verification result: {status}')

        if args.export_json:
            probe.export_json(args.export_json)
        if args.export_text:
            probe.export_text(args.export_text)
    except KeyboardInterrupt:
        logger.warning('\n[!] Analysis interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'[!] Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()

