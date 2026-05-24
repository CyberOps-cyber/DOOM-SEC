#!/usr/bin/env python3
"""
WebFlood - HTTP Request Flooding and Stress Testing Utility
Performs configurable HTTP request storms with concurrency, metrics, and custom payloads.
"""

import argparse
import json
import logging
import sys
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class WebFlood:
    """High-volume HTTP flood engine with metrics and request profiling."""
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'keep-alive'
    }

    def __init__(self, target_url: str, method: str = 'GET', threads: int = 20, requests_per_thread: int = 10, timeout: int = 10, payload: str = '', headers: Dict[str, str] = None):
        self.target_url = target_url
        self.method = method.upper()
        self.threads = threads
        self.requests_per_thread = requests_per_thread
        self.timeout = timeout
        self.payload = payload
        self.headers = headers or self.DEFAULT_HEADERS.copy()
        self.session = requests.Session()
        self.stats = {
            'started': 0,
            'completed': 0,
            'success': 0,
            'client_error': 0,
            'server_error': 0,
            'timeout': 0,
            'exceptions': 0,
            'bytes': 0,
            'duration': 0.0,
            'min_time': None,
            'max_time': None
        }
        self.responses: Dict[int, int] = {}

    def _random_payload(self, length: int = 32) -> str:
        """Generate random payload text for POST requests."""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

    def prepare_payload(self):
        """Prepare the payload for the request body."""
        if not self.payload and self.method in ['POST', 'PUT', 'PATCH']:
            self.payload = self._random_payload(64)

    def execute_request(self) -> None:
        """Execute one HTTP request and update metrics."""
        self.stats['started'] += 1
        try:
            start = time.time()
            response = self.session.request(self.method, self.target_url, headers=self.headers, timeout=self.timeout, data=self.payload if self.method in ['POST', 'PUT', 'PATCH'] else None, allow_redirects=True)
            latency = time.time() - start
            self.stats['completed'] += 1
            self.stats['bytes'] += len(response.content)
            self.stats['duration'] += latency
            self.stats['min_time'] = min(self.stats['min_time'], latency) if self.stats['min_time'] is not None else latency
            self.stats['max_time'] = max(self.stats['max_time'], latency) if self.stats['max_time'] is not None else latency

            status_group = response.status_code // 100
            self.responses[response.status_code] = self.responses.get(response.status_code, 0) + 1
            if status_group == 2:
                self.stats['success'] += 1
            elif status_group == 4:
                self.stats['client_error'] += 1
            elif status_group == 5:
                self.stats['server_error'] += 1

            logger.debug(f'{self.method} {self.target_url} -> {response.status_code} in {latency:.3f}s')
        except requests.exceptions.Timeout:
            self.stats['timeout'] += 1
            self.stats['exceptions'] += 1
            logger.debug(f'Request timeout for {self.target_url}')
        except requests.exceptions.RequestException as exc:
            self.stats['exceptions'] += 1
            logger.debug(f'Request error: {exc}')

    def thread_worker(self, thread_id: int) -> None:
        """Worker that issues requests in a loop."""
        logger.debug(f'Thread {thread_id} starting')
        for _ in range(self.requests_per_thread):
            self.execute_request()
        logger.debug(f'Thread {thread_id} finished')

    def launch(self):
        """Launch concurrent request workers."""
        self.prepare_payload()
        logger.info(f'Starting WebFlood against {self.target_url} with {self.threads} threads, {self.requests_per_thread} requests each')
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.thread_worker, i) for i in range(self.threads)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    logger.debug(f'Worker failure: {exc}')
        self.stats['duration'] = time.time() - start

    def get_report(self) -> Dict[str, Any]:
        """Generate a structured report of flood metrics."""
        avg_latency = self.stats['duration'] / self.stats['completed'] if self.stats['completed'] else 0.0
        return {
            'target_url': self.target_url,
            'method': self.method,
            'threads': self.threads,
            'requests_per_thread': self.requests_per_thread,
            'started': self.stats['started'],
            'completed': self.stats['completed'],
            'success': self.stats['success'],
            'client_error': self.stats['client_error'],
            'server_error': self.stats['server_error'],
            'timeouts': self.stats['timeout'],
            'exceptions': self.stats['exceptions'],
            'bytes_transferred': self.stats['bytes'],
            'duration_seconds': self.stats['duration'],
            'avg_latency_seconds': avg_latency,
            'min_latency_seconds': self.stats['min_time'],
            'max_latency_seconds': self.stats['max_time'],
            'status_codes': self.responses,
        }

    def print_report(self):
        """Print attack summary and status metrics."""
        report = self.get_report()
        print('\n' + '='*90)
        print('WebFlood - HTTP Stress Testing Report')
        print('='*90)
        print(f"Target: {report['target_url']}")
        print(f"Method: {report['method']}")
        print(f"Threads: {report['threads']}")
        print(f"Requests per thread: {report['requests_per_thread']}")
        print(f"Total requests attempted: {report['started']}")
        print(f"Completed requests: {report['completed']}")
        print(f"Successful 2xx: {report['success']}")
        print(f"Client errors: {report['client_error']}")
        print(f"Server errors: {report['server_error']}")
        print(f"Timeouts: {report['timeouts']}")
        print(f"Exceptions: {report['exceptions']}")
        print(f"Bytes transferred: {report['bytes_transferred']}")
        print(f"Duration: {report['duration_seconds']:.2f}s")
        print(f"Average latency: {report['avg_latency_seconds']:.3f}s")
        print(f"Min latency: {report['min_latency_seconds']}")
        print(f"Max latency: {report['max_latency_seconds']}")
        print('\nStatus code distribution:')
        for code, count in sorted(report['status_codes'].items()):
            print(f'  {code}: {count}')
        print('\n' + '='*90 + '\n')

    def export_json(self, filename: str):
        """Export results to JSON."""
        import json
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                json.dump(self.get_report(), fh, indent=2)
            logger.info(f'Results exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def get_report(self) -> Dict[str, Any]:
        """Generate a structured report of flood metrics."""
        avg_latency = self.stats['duration'] / self.stats['completed'] if self.stats['completed'] else 0.0
        efficiency = (self.stats['success'] / self.stats['started'] * 100) if self.stats['started'] else 0.0
        return {
            'target_url': self.target_url,
            'method': self.method,
            'threads': self.threads,
            'requests_per_thread': self.requests_per_thread,
            'started': self.stats['started'],
            'completed': self.stats['completed'],
            'success': self.stats['success'],
            'client_error': self.stats['client_error'],
            'server_error': self.stats['server_error'],
            'timeouts': self.stats['timeout'],
            'exceptions': self.stats['exceptions'],
            'bytes_transferred': self.stats['bytes'],
            'duration_seconds': self.stats['duration'],
            'avg_latency_seconds': avg_latency,
            'efficiency_pct': efficiency,
            'status_codes': self.responses,
        }

    def export_markdown(self, filename: str):
        """Export a markdown version of the flood report."""
        report = self.get_report()
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('# WebFlood Report\n\n')
                for key, value in report.items():
                    if isinstance(value, dict):
                        fh.write(f'## {key}\n')
                        for subkey, subvalue in value.items():
                            fh.write(f'* {subkey}: {subvalue}\n')
                    else:
                        fh.write(f'* {key}: {value}\n')
                fh.write('\n')
            logger.info(f'Markdown report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write markdown export: {exc}')

    def export_text(self, filename: str):
        """Export results to plain text."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                report = self.get_report()
                fh.write('WebFlood Report\n')
                fh.write('='*90 + '\n')
                for key, value in report.items():
                    fh.write(f'{key}: {value}\n')
            logger.info(f'Text report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text export: {exc}')

    def export_html(self, filename: str):
        """Export flood metrics as a simple HTML page."""
        report = self.get_report()
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('<html><body>\n')
                fh.write('<h1>WebFlood Report</h1>\n')
                fh.write('<ul>\n')
                for key, value in report.items():
                    if isinstance(value, dict):
                        fh.write(f'<li>{key}:<ul>')
                        for subkey, subvalue in value.items():
                            fh.write(f'<li>{subkey}: {subvalue}</li>')
                        fh.write('</ul></li>')
                    else:
                        fh.write(f'<li>{key}: {value}</li>')
                fh.write('</ul>\n')
                fh.write('</body></html>\n')
            logger.info(f'HTML report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write HTML export: {exc}')

    def success_rate(self) -> float:
        """Return the percentage of successful requests."""
        if self.stats['started'] == 0:
            return 0.0
        return (self.stats['success'] / self.stats['started']) * 100.0


def main():
    parser = argparse.ArgumentParser(
        description='WebFlood - HTTP flooding and stress testing utility',
        epilog='Examples:\n'
               '  python webflood.py https://target.com -t 50 -n 20\n'
               '  python webflood.py https://target.com --method POST --payload "{\"data\":\"fuzz\"}"\n'
               '  python webflood.py https://target.com --json attack.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--method', choices=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'], default='GET', help='HTTP method')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Concurrent worker threads')
    parser.add_argument('-n', '--number', type=int, default=10, help='Requests per thread')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--payload', help='Request payload for methods with a body')
    parser.add_argument('--header', action='append', help='Additional headers (Header: Value)')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--text', help='Export results to plain text file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    headers = WebFlood.DEFAULT_HEADERS.copy()
    if args.header:
        for header_line in args.header:
            if ':' in header_line:
                name, value = header_line.split(':', 1)
                headers[name.strip()] = value.strip()

    flood = WebFlood(target_url=args.url, method=args.method, threads=args.threads, requests_per_thread=args.number, timeout=args.timeout, payload=args.payload or '')
    flood.headers = headers

    try:
        flood.launch()
        flood.print_report()
        if args.json:
            flood.export_json(args.json)
        if args.text:
            flood.export_text(args.text)
    except KeyboardInterrupt:
        logger.warning('Flood interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
