#!/usr/bin/env python3
"""
HTTPStorm - Advanced HTTP Request Flood and Stress Testing Utility
Performs high-volume HTTP requests with concurrent threading and detailed statistics
"""

import argparse
import requests
import threading
import time
import sys
import logging
import random
import string
from typing import Dict, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

class HTTPStorm:
    """Advanced HTTP flood and stress testing engine with comprehensive metrics."""
    
    def __init__(self, url: str, threads: int = 4, timeout: int = 5):
        self.url = url
        self.threads = threads
        self.timeout = timeout
        self.stats = {
            'total': 0,
            'success': 0,
            'timeout': 0,
            'error': 0,
            'status_codes': {},
            'response_times': [],
            'bytes_transferred': 0
        }
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15'
        ]
    
    def generate_payload(self) -> Dict:
        """Generate random POST payload for testing."""
        return {
            'test_id': ''.join(random.choices(string.ascii_letters + string.digits, k=16)),
            'timestamp': int(time.time() * 1000),
            'random_data': ''.join(random.choices(string.ascii_letters, k=32))
        }
    
    def send_request(self, method: str = 'GET', data: Dict = None, headers: Dict = None) -> Tuple[int, float, int]:
        """Send a single HTTP request and return status, response time, and bytes."""
        try:
            user_agent = random.choice(self.user_agents)
            req_headers = headers or {}
            req_headers['User-Agent'] = user_agent
            
            start = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(
                    self.url,
                    headers=req_headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    self.url,
                    json=data or self.generate_payload(),
                    headers=req_headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            elif method.upper() == 'HEAD':
                response = self.session.head(
                    self.url,
                    headers=req_headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            else:
                response = self.session.request(
                    method,
                    self.url,
                    headers=req_headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
            
            elapsed = time.time() - start
            content_length = len(response.content) if hasattr(response, 'content') else 0
            
            with self.lock:
                self.stats['total'] += 1
                self.stats['success'] += 1
                self.stats['response_times'].append(elapsed)
                self.stats['bytes_transferred'] += content_length
                
                status = response.status_code
                if status not in self.stats['status_codes']:
                    self.stats['status_codes'][status] = 0
                self.stats['status_codes'][status] += 1
            
            return status, elapsed, content_length
        
        except requests.exceptions.Timeout:
            with self.lock:
                self.stats['total'] += 1
                self.stats['timeout'] += 1
            return 0, self.timeout, 0
        
        except requests.exceptions.ConnectionError:
            with self.lock:
                self.stats['total'] += 1
                self.stats['error'] += 1
            logger.debug("Connection error")
            return -1, 0, 0
        
        except Exception as exc:
            with self.lock:
                self.stats['total'] += 1
                self.stats['error'] += 1
            logger.debug(f"Request error: {exc}")
            return -1, 0, 0
    
    def flood(self, count: int, method: str = 'GET', data: Dict = None, headers: Dict = None):
        """Execute flood with specified number of requests."""
        logger.info(f"[+] Starting HTTP flood: {count} requests to {self.url}")
        logger.info(f"[+] Threads: {self.threads}, Method: {method}, Timeout: {self.timeout}s")
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self.send_request, method, data, headers)
                for _ in range(count)
            ]
            
            completed = 0
            for future in as_completed(futures):
                try:
                    status, elapsed, bytes_sent = future.result()
                    completed += 1
                    
                    progress_pct = (completed / count) * 100
                    if completed % max(1, count // 20) == 0 or completed == count:
                        logger.info(f"[*] Progress: {completed}/{count} ({progress_pct:.1f}%)")
                
                except Exception as exc:
                    logger.error(f"[!] Error in request: {exc}")
        
        elapsed_total = time.time() - start_time
        logger.info(f"[+] Flood completed in {elapsed_total:.2f}s")
    
    def sustained_flood(self, duration: int, rps: float = 10.0, method: str = 'GET'):
        """Execute sustained flood for specified duration at target RPS."""
        logger.info(f"[+] Starting sustained flood for {duration}s at {rps:.1f} RPS")
        logger.info(f"[+] Target: {self.url}")
        
        interval = 1.0 / rps
        start_time = time.time()
        request_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while time.time() - start_time < duration:
                elapsed_in_loop = time.time() - start_time
                next_request_time = request_count * interval
                
                if elapsed_in_loop >= next_request_time:
                    executor.submit(self.send_request, method, None, None)
                    request_count += 1
                
                time.sleep(0.001)
            
            logger.info(f"[+] Waiting for {request_count} requests to complete...")
            executor.shutdown(wait=True)
    
    def print_stats(self):
        """Print comprehensive statistics report."""
        print("\n" + "="*70)
        print("HTTPStorm - Statistics Report")
        print("="*70)
        
        print(f"\n[REQUEST STATISTICS]")
        print(f"  Total Requests:        {self.stats['total']}")
        print(f"  Successful:            {self.stats['success']}")
        print(f"  Timeouts:              {self.stats['timeout']}")
        print(f"  Errors:                {self.stats['error']}")
        
        if self.stats['total'] > 0:
            success_rate = (self.stats['success'] / self.stats['total']) * 100
            print(f"  Success Rate:          {success_rate:.1f}%")
        
        print(f"\n[RESPONSE METRICS]")
        if self.stats['response_times']:
            avg_time = sum(self.stats['response_times']) / len(self.stats['response_times'])
            min_time = min(self.stats['response_times'])
            max_time = max(self.stats['response_times'])
            print(f"  Avg Response Time:     {avg_time*1000:.2f}ms")
            print(f"  Min Response Time:     {min_time*1000:.2f}ms")
            print(f"  Max Response Time:     {max_time*1000:.2f}ms")
        
        print(f"  Total Data Transferred: {self.stats['bytes_transferred']} bytes ({self.stats['bytes_transferred']/1024:.2f}KB)")
        
        print(f"\n[STATUS CODE DISTRIBUTION]")
        for status, count in sorted(self.stats['status_codes'].items()):
            pct = (count / self.stats['success'] * 100) if self.stats['success'] > 0 else 0
            print(f"  {status}: {count:6d} ({pct:5.1f}%)")
        
        print("\n" + "="*70 + "\n")

    def calculate_latency_percentiles(self, percentiles=(50, 90, 95, 99)):
        """Calculate latency percentiles from collected response times."""
        if not self.stats['response_times']:
            return {}
        sorted_times = sorted(self.stats['response_times'])
        results = {}
        for percentile in percentiles:
            idx = int(len(sorted_times) * percentile / 100) - 1
            idx = max(0, min(idx, len(sorted_times) - 1))
            results[percentile] = sorted_times[idx]
        return results

    def get_report(self):
        """Build a structured report dictionary for export."""
        percentiles = self.calculate_latency_percentiles()
        avg_time = (sum(self.stats['response_times']) / len(self.stats['response_times'])) if self.stats['response_times'] else 0.0
        return {
            'target_url': self.url,
            'threads': self.threads,
            'timeout': self.timeout,
            'total_requests': self.stats['total'],
            'success': self.stats['success'],
            'timeouts': self.stats['timeout'],
            'errors': self.stats['error'],
            'response_times': {
                'avg': avg_time,
                'min': min(self.stats['response_times']) if self.stats['response_times'] else 0.0,
                'max': max(self.stats['response_times']) if self.stats['response_times'] else 0.0,
                'percentiles': percentiles
            },
            'bytes_transferred': self.stats['bytes_transferred'],
            'status_codes': self.stats['status_codes']
        }

    def export_json(self, output_file: str):
        """Export flood metrics to a JSON file."""
        import json
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                json.dump(self.get_report(), fh, indent=2)
            logger.info(f'Exported metrics to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def export_text(self, output_file: str):
        """Export flood metrics to a plain text report."""
        report = self.get_report()
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                fh.write('HTTPStorm Report\n')
                fh.write('='*80 + '\n')
                for key, value in report.items():
                    if isinstance(value, dict):
                        fh.write(f'{key}:\n')
                        for sub_key, sub_value in value.items():
                            fh.write(f'  {sub_key}: {sub_value}\n')
                    else:
                        fh.write(f'{key}: {value}\n')
            logger.info(f'Text report written to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to write text report: {exc}')


def main():
    parser = argparse.ArgumentParser(
        description="HTTPStorm - Advanced HTTP Request Flood and Stress Testing",
        epilog="Examples:\n"
               "  python httpstorm.py https://example.com -n 1000 -t 8\n"
               "  python httpstorm.py https://example.com --sustained 60 --rps 50 -m POST\n"
               "  python httpstorm.py https://api.example.com -n 500 --timeout 10",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', help='Target URL to flood')
    parser.add_argument('-n', '--number', type=int, default=100, help='Total number of requests (default: 100)')
    parser.add_argument('-t', '--threads', type=int, default=4, help='Number of concurrent threads (default: 4)')
    parser.add_argument('-m', '--method', type=str, default='GET', choices=['GET', 'POST', 'HEAD', 'PUT', 'DELETE'],
                        help='HTTP method (default: GET)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--sustained', type=int, help='Sustained flood duration in seconds')
    parser.add_argument('--rps', type=float, default=10.0, help='Requests per second for sustained mode (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        storm = HTTPStorm(args.url, threads=args.threads, timeout=args.timeout)
        
        if args.sustained:
            storm.sustained_flood(args.sustained, args.rps, args.method)
        else:
            storm.flood(args.number, args.method)
        
        storm.print_stats()
    
    except KeyboardInterrupt:
        logger.warning("\n[!] Flood interrupted by user")
        if 'storm' in locals():
            storm.print_stats()
        sys.exit(1)
    
    except Exception as exc:
        logger.error(f"[!] Fatal error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
