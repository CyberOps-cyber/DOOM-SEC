#!/usr/bin/env python3
"""
TraceGhost - HTTP Response Header Trace and Infrastructure Analysis Utility
Extracts HTTP headers, traces proxy paths, and identifies CDN/WAF/infrastructure clues.
"""

import argparse
import logging
import sys
import socket
import ssl
from typing import Dict, List, Optional, Any
import requests
from urllib.parse import urljoin, urlparse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class TraceGhost:
    """HTTP header analysis engine with redirect and infrastructure tracing."""
    HEADER_KEYS = ['Server', 'X-Powered-By', 'Via', 'X-Forwarded-For', 'X-Frame-Options', 'Strict-Transport-Security', 'Content-Security-Policy', 'Referrer-Policy', 'X-Content-Type-Options']
    WAF_SIGNATURES = {
        'Cloudflare': ['cloudflare', 'cf-ray'],
        'Akamai': ['akamai', 'akamaiedge'],
        'F5 BIG-IP': ['bigip', 'f5', 'x-cdn'],
        'AWS WAF': ['aws', 'amazon'],
        'Sucuri': ['sucuri', 'sucuri/cloudproxy']
    }
    CDN_SIGNATURES = {
        'Cloudflare': ['cloudflare'],
        'Fastly': ['fastly'],
        'Akamai': ['akamai'],
        'Google': ['google'],
        'Amazon CloudFront': ['cloudfront']
    }

    def __init__(self, url: str, timeout: int = 10, max_redirects: int = 10):
        self.url = url
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.chain: List[Dict[str, Optional[str]]] = []
        self.report: Dict[str, any] = {}

    def trace_headers(self):
        """Follow redirects and collect headers from each stage."""
        current_url = self.url
        session = requests.Session()
        session.max_redirects = self.max_redirects
        visited = 0

        while current_url and visited < self.max_redirects:
            logger.info(f'Tracing URL: {current_url}')
            try:
                response = session.get(current_url, timeout=self.timeout, allow_redirects=False)
                headers = {k: v for k, v in response.headers.items()}
                entry = {
                    'url': current_url,
                    'status_code': str(response.status_code),
                    'location': response.headers.get('Location'),
                    'headers': headers
                }
                self.chain.append(entry)
                if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                    current_url = urljoin(current_url, response.headers.get('Location', ''))
                    visited += 1
                    continue
                break
            except requests.RequestException as exc:
                self.chain.append({'url': current_url, 'status_code': 'ERROR', 'location': None, 'headers': {}, 'error': str(exc)})
                break

    def detect_infrastructure(self):
        """Detect CDN and WAF fingerprints from collected headers."""
        wafs = set()
        cdns = set()
        for stage in self.chain:
            headers = stage.get('headers', {})
            for signature, markers in self.WAF_SIGNATURES.items():
                if any(marker.lower() in ''.join(headers.values()).lower() for marker in markers):
                    wafs.add(signature)
            for signature, markers in self.CDN_SIGNATURES.items():
                if any(marker.lower() in ''.join(headers.values()).lower() for marker in markers):
                    cdns.add(signature)
        self.report['waf'] = sorted(wafs)
        self.report['cdn'] = sorted(cdns)

    def summarize_headers(self):
        """Summarize key headers from the final stage."""
        if not self.chain:
            return
        final = self.chain[-1]
        headers = final.get('headers', {})
        summary = {key: headers.get(key, '') for key in self.HEADER_KEYS}
        self.report['final_headers'] = summary
        self.report['server'] = headers.get('Server', '')
        self.report['powered_by'] = headers.get('X-Powered-By', '')
        self.report['via'] = headers.get('Via', '')
        self.report['x_forwarded_for'] = headers.get('X-Forwarded-For', '')

    def print_report(self):
        """Print detailed trace and infrastructure analysis."""
        print('\n' + '='*90)
        print('TraceGhost - HTTP Header Trace and Infrastructure Analysis')
        print('='*90)
        for stage in self.chain:
            print(f"\n[Stage] {stage.get('url')}")
            print(f"  Status: {stage.get('status_code')}")
            if stage.get('location'):
                print(f"  Location: {stage.get('location')}")
            if stage.get('error'):
                print(f"  Error: {stage.get('error')}")
            print('  Headers:')
            for key, value in stage.get('headers', {}).items():
                if key in self.HEADER_KEYS or key.lower().startswith('x-'):
                    print(f'    {key}: {value}')
        print('\n[INFRASTRUCTURE]')
        print(f"  Detected CDN: {', '.join(self.report.get('cdn', [])) or 'None'}")
        print(f"  Detected WAF: {', '.join(self.report.get('waf', [])) or 'None'}")
        print('\n[FINAL HEADER SUMMARY]')
        for key, value in self.report.get('final_headers', {}).items():
            print(f'  {key}: {value}')
        print('='*90 + '\n')

    def detect_redirect_loops(self) -> bool:
        """Detect redirect loops in the trace chain."""
        seen = set()
        for stage in self.chain:
            url = stage.get('url')
            if url in seen:
                return True
            seen.add(url)
        return False

    def fetch_tls_info(self) -> Dict[str, Any]:
        """Fetch TLS certificate details for the target host."""
        url_data = urlparse(self.url)
        host = url_data.hostname
        port = url_data.port or (443 if url_data.scheme == 'https' else 80)
        result = {'host': host, 'port': port, 'subject': '', 'issuer': '', 'not_before': '', 'not_after': '', 'error': None}
        if url_data.scheme != 'https':
            result['error'] = 'TLS info only available for HTTPS targets'
            return result
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    result['subject'] = cert.get('subject', '')
                    result['issuer'] = cert.get('issuer', '')
                    result['not_before'] = cert.get('notBefore', '')
                    result['not_after'] = cert.get('notAfter', '')
        except Exception as exc:
            result['error'] = str(exc)
        return result

    def export_text(self, filename: str):
        """Export trace analysis to plain text."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('TraceGhost Report\n')
                fh.write('='*90 + '\n')
                fh.write(f'URL: {self.url}\n')
                fh.write(f'Detected CDN: {", ".join(self.report.get("cdn", [])) or "None"}\n')
                fh.write(f'Detected WAF: {", ".join(self.report.get("waf", [])) or "None"}\n')
                fh.write(f'Redirect loop: {self.detect_redirect_loops()}\n')
                fh.write('\nTrace chain:\n')
                for stage in self.chain:
                    fh.write(f'* {stage.get("url")} - {stage.get("status_code")}\n')
                tls_info = self.fetch_tls_info()
                fh.write('\nTLS Info:\n')
                for key, value in tls_info.items():
                    fh.write(f'  {key}: {value}\n')
            logger.info(f'Results exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export text report: {exc}')

    def export_json(self, filename: str):
        """Export trace report to JSON."""
        import json
        payload = {
            'url': self.url,
            'trace_chain': self.chain,
            'report': self.report,
            'redirect_loop': self.detect_redirect_loops(),
            'tls_info': self.fetch_tls_info()
        }
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Results exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def export_markdown(self, filename: str):
        """Export trace results to markdown."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write(f'# TraceGhost Report for {self.url}\n\n')
                fh.write(f'* Detected CDN: {", ".join(self.report.get("cdn", [])) or "None"}\n')
                fh.write(f'* Detected WAF: {", ".join(self.report.get("waf", [])) or "None"}\n')
                fh.write(f'* Redirect loop: {self.detect_redirect_loops()}\n\n')
                fh.write('## Trace Chain\n')
                for stage in self.chain:
                    fh.write(f'* {stage.get("url")} - {stage.get("status_code")}\n')
                tls_info = self.fetch_tls_info()
                fh.write('\n## TLS Info\n')
                for key, value in tls_info.items():
                    fh.write(f'* {key}: {value}\n')
            logger.info(f'Markdown report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write markdown report: {exc}')

    def print_full_report(self):
        """Print a detailed trace report including TLS and redirect analysis."""
        self.print_report()
        print('Detailed infrastructure analysis:')
        print(f'  Redirect loop detected: {self.detect_redirect_loops()}')
        tls_info = self.fetch_tls_info()
        print('  TLS certificate info:')
        for key, value in tls_info.items():
            print(f'    {key}: {value}')


def main():
    parser = argparse.ArgumentParser(
        description='TraceGhost - HTTP header tracing and infrastructure analysis tool',
        epilog='Examples:\n'
               '  python traceghost.py https://example.com\n'
               '  python traceghost.py https://example.com --json trace.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL to analyze')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--json', help='Export trace data to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tracer = TraceGhost(args.url, timeout=args.timeout)
    try:
        tracer.trace_headers()
        tracer.detect_infrastructure()
        tracer.summarize_headers()
        tracer.print_report()
        if args.json:
            tracer.export_json(args.json)
    except KeyboardInterrupt:
        logger.warning('Trace interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
