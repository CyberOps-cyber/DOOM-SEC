#!/usr/bin/env python3
"""
AuthCrawler - Authentication Endpoint Discovery and Analysis Utility
Probes authentication endpoints, session routes, and token exchange paths for reconnaissance.
"""

import argparse
import requests
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Dict
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class AuthCrawler:
    """Authentication endpoint crawler with path analysis and response scoring."""
    COMMON_ENDPOINTS = [
        '/login', '/logout', '/auth', '/session', '/token', '/api/token', '/signin', '/signout',
        '/oauth/token', '/oauth/authorize', '/user/login', '/user/logout', '/account/login',
        '/v1/auth', '/v1/session', '/v1/login', '/v1/logout'
    ]

    def __init__(self, target_url: str, endpoints: List[str] = None, threads: int = 8, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.endpoints = endpoints or self.COMMON_ENDPOINTS
        self.threads = threads
        self.timeout = timeout
        self.results: Dict[str, Dict[str, Any]] = {}
        self.session = requests.Session()
        self.stats = {
            'checked': 0,
            'success': 0,
            'redirects': 0,
            'errors': 0,
            'timeouts': 0
        }

    def normalize_endpoints(self, endpoints: List[str]) -> List[str]:
        """Normalize and deduplicate endpoint paths."""
        normalized = set()
        for endpoint in endpoints:
            if not endpoint.startswith('/'):
                endpoint = '/' + endpoint
            normalized.add(endpoint.strip())
        return sorted(normalized)

    def build_urls(self) -> List[str]:
        """Build full URLs from target host and endpoint list."""
        return [f'{self.target_url}{endpoint}' for endpoint in self.normalize_endpoints(self.endpoints)]

    def probe_endpoint(self, url: str) -> Dict[str, Any]:
        """Probe a single authentication endpoint."""
        self.stats['checked'] += 1
        result = {
            'url': url,
            'status_code': None,
            'content_length': None,
            'redirect': None,
            'reason': None,
            'headers': {},
            'error': None,
            'duration_ms': None
        }

        try:
            start = time.time()
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            elapsed = (time.time() - start) * 1000
            result['status_code'] = response.status_code
            result['content_length'] = len(response.text)
            result['redirect'] = response.history[-1].status_code if response.history else None
            result['headers'] = dict(response.headers)
            result['duration_ms'] = round(elapsed, 2)
            if response.history:
                self.stats['redirects'] += 1
            if response.status_code < 400:
                self.stats['success'] += 1
            else:
                self.stats['errors'] += 1
        except requests.exceptions.Timeout:
            self.stats['timeouts'] += 1
            result['error'] = 'timeout'
        except requests.exceptions.RequestException as exc:
            self.stats['errors'] += 1
            result['error'] = str(exc)
        return result

    def run(self):
        """Execute endpoint probes concurrently."""
        urls = self.build_urls()
        logger.info(f'Starting auth probe against {len(urls)} endpoints')
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.probe_endpoint, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    self.results[result['url']] = result
                except Exception as exc:
                    logger.debug(f'Probe failure: {exc}')

    def categorize_response(self, status_code: int) -> str:
        """Categorize HTTP status codes for reports."""
        if status_code < 300:
            return 'success'
        if 300 <= status_code < 400:
            return 'redirect'
        if 400 <= status_code < 500:
            return 'client_error'
        return 'server_error'

    def print_report(self):
        """Print auth endpoint report."""
        print('\n' + '='*90)
        print(f'AuthCrawler - Authentication Endpoint Report for {self.target_url}')
        print('='*90)
        print('\n[STATISTICS]')
        print(f'  Endpoints scanned: {self.stats["checked"]}')
        print(f'  Successful responses: {self.stats["success"]}')
        print(f'  Redirects: {self.stats["redirects"]}')
        print(f'  Errors: {self.stats["errors"]}')
        print(f'  Timeouts: {self.stats["timeouts"]}')

        print('\n[ENDPOINT RESULTS]')
        for url, entry in sorted(self.results.items()):
            print(f'\n  URL: {url}')
            print(f'    Status: {entry["status_code"]}')
            print(f'    Length: {entry["content_length"]} bytes')
            if entry['redirect'] is not None:
                print(f'    Redirect chain ends at: {entry["redirect"]}')
            if entry['duration_ms'] is not None:
                print(f'    Response time: {entry["duration_ms"]} ms')
            if entry['error']:
                print(f'    Error: {entry["error"]}')
            print('    Headers:')
            for header, value in entry['headers'].items():
                print(f'      {header}: {value}')

        print('\n' + '='*90 + '\n')

    def export_json(self, filename: str):
        """Export endpoint results to JSON."""
        import json
        payload = {
            'target_url': self.target_url,
            'statistics': self.stats,
            'results': self.results,
        }
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Exported results to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def score_endpoint(self, result: Dict[str, str]) -> int:
        """Assign a score to an endpoint based on status code and exposure patterns."""
        score = 0
        status = result.get('status_code') or 0
        error = result.get('error')
        if status and int(status) < 300:
            score += 10
        if status and 300 <= int(status) < 400:
            score += 5
        if error:
            score -= 5
        headers = result.get('headers', {})
        if headers.get('WWW-Authenticate'):
            score += 5
        return score

    def analyze_endpoints(self):
        """Analyze each endpoint result and add a score or flag."""
        for url, result in self.results.items():
            result['score'] = self.score_endpoint(result)
            result['contains_auth_header'] = bool(result.get('headers', {}).get('WWW-Authenticate'))
            result['has_cookie'] = 'Set-Cookie' in result.get('headers', {})

    def export_text(self, filename: str):
        """Export endpoint results to a text summary."""
        try:
            self.analyze_endpoints()
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('AuthCrawler Report\n')
                fh.write('='*80 + '\n')
                fh.write(f'Target: {self.target_url}\n')
                fh.write(f'Checked: {self.stats["checked"]}\n')
                for url, entry in self.results.items():
                    fh.write(f'\nURL: {url}\n')
                    fh.write(f'  Status: {entry["status_code"]}\n')
                    fh.write(f'  Length: {entry.get("content_length", 0)} bytes\n')
                    fh.write(f'  Redirect: {entry.get("redirect")}\n')
                    fh.write(f'  Score: {entry.get("score")}\n')
                    fh.write(f'  Error: {entry.get("error")}\n')
            logger.info(f'Text report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text report: {exc}')

    def export_markdown(self, filename: str):
        """Export endpoint results to a markdown report."""
        try:
            self.analyze_endpoints()
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write(f'# AuthCrawler Report\n\n')
                fh.write(f'**Target:** {self.target_url}\n\n')
                fh.write(f'**Checked:** {self.stats["checked"]}\n\n')
                for url, entry in self.results.items():
                    fh.write(f'## {url}\n')
                    fh.write(f'* Status: {entry["status_code"]}\n')
                    fh.write(f'* Length: {entry.get("content_length", 0)} bytes\n')
                    fh.write(f'* Redirect: {entry.get("redirect")}\n')
                    fh.write(f'* Score: {entry.get("score")}\n')
                    fh.write(f'* Error: {entry.get("error")}\n\n')
            logger.info(f'Markdown report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write markdown report: {exc}')

    def export_csv(self, filename: str):
        """Export endpoint results to CSV."""
        import csv
        try:
            with open(filename, 'w', encoding='utf-8', newline='') as fh:
                writer = csv.writer(fh)
                writer.writerow(['url', 'status_code', 'duration_ms', 'redirect', 'score', 'error'])
                for url, entry in self.results.items():
                    writer.writerow([
                        url,
                        entry.get('status_code'),
                        entry.get('duration_ms'),
                        entry.get('redirect'),
                        entry.get('score'),
                        entry.get('error')
                    ])
            logger.info(f'CSV report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write CSV report: {exc}')

    def summarize_security_headers(self) -> Dict[str, int]:
        """Count security-related headers observed across endpoints."""
        summary = {}
        for result in self.results.values():
            headers = result.get('headers', {})
            for header in ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
                if headers.get(header):
                    summary[header] = summary.get(header, 0) + 1
        return summary

    def export_html(self, filename: str):
        """Export endpoint results as a simple HTML report."""
        try:
            security_summary = self.summarize_security_headers()
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('<html><body>\n')
                fh.write(f'<h1>AuthCrawler Report for {self.target_url}</h1>\n')
                fh.write(f'<p>Checked: {self.stats["checked"]}</p>\n')
                fh.write('<h2>Security Headers</h2>\n')
                fh.write('<ul>\n')
                for header, count in security_summary.items():
                    fh.write(f'<li>{header}: {count}</li>\n')
                fh.write('</ul>\n')
                fh.write('<h2>Endpoints</h2>\n')
                fh.write('<ul>\n')
                for url, entry in self.results.items():
                    fh.write(f'<li>{url} - {entry.get("status_code")} - Score: {entry.get("score")}</li>\n')
                fh.write('</ul>\n')
                fh.write('</body></html>\n')
            logger.info(f'HTML report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write HTML report: {exc}')


def main():
    parser = argparse.ArgumentParser(
        description='AuthCrawler - Authentication endpoint discovery and analysis tool',
        epilog='Examples:\n'
               '  python authcrawler.py https://target.com\n'
               '  python authcrawler.py https://target.com -e /login /logout /token\n'
               '  python authcrawler.py https://target.com --json report.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Base target URL to probe')
    parser.add_argument('-e', '--endpoints', nargs='+', help='Custom authentication endpoints to probe')
    parser.add_argument('-t', '--threads', type=int, default=8, help='Number of concurrent probes')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--text', help='Export results to plain text file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    endpoints = args.endpoints if args.endpoints else AuthCrawler.COMMON_ENDPOINTS
    crawler = AuthCrawler(args.target, endpoints=endpoints, threads=args.threads, timeout=args.timeout)

    try:
        crawler.run()
        crawler.print_report()
        if args.json:
            crawler.export_json(args.json)
        if args.text:
            crawler.export_text(args.text)
    except KeyboardInterrupt:
        logger.warning('Scan interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
