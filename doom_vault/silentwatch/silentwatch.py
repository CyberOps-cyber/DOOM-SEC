#!/usr/bin/env python3
"""
SilentWatch - Continuous URL Monitoring and Uptime Checking Utility
Monitors target URLs continuously, tracks response times, status codes, and alerts on failures.
"""

import argparse
import logging
import sys
import time
from datetime import datetime
from typing import List, Dict, Optional

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class SilentWatch:
    """URL monitoring engine with history, alerting, and reporting."""
    def __init__(self, url: str, interval: int = 15, timeout: int = 10, max_checks: int = 0):
        self.url = url
        self.interval = interval
        self.timeout = timeout
        self.max_checks = max_checks
        self.history: List[Dict[str, Optional[str]]] = []
        self.start_time = datetime.utcnow()
        self.status_counts = {'ok': 0, 'warning': 0, 'error': 0}
        self.failures: List[Dict[str, str]] = []

    def check_url(self) -> Dict[str, Optional[str]]:
        """Perform a single HTTP request and collect metrics."""
        try:
            response = requests.get(self.url, timeout=self.timeout, allow_redirects=True)
            status_category = 'ok' if response.status_code < 400 else 'warning'
            latency_ms = round(response.elapsed.total_seconds() * 1000, 2)
            result = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'status_code': str(response.status_code),
                'latency_ms': str(latency_ms),
                'content_type': response.headers.get('Content-Type', ''),
                'location': response.headers.get('Location', ''),
                'error': None
            }
            self.status_counts[status_category] += 1
            return result
        except requests.exceptions.RequestException as exc:
            self.status_counts['error'] += 1
            error_msg = str(exc)
            self.failures.append({'timestamp': datetime.utcnow().isoformat() + 'Z', 'error': error_msg})
            return {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'status_code': 'ERROR',
                'latency_ms': None,
                'content_type': None,
                'location': None,
                'error': error_msg
            }

    def monitor(self):
        """Continuously monitor the target URL."""
        checks = 0
        logger.info(f'Starting monitoring for {self.url} every {self.interval}s')
        while self.max_checks <= 0 or checks < self.max_checks:
            result = self.check_url()
            self.history.append(result)
            checks += 1
            self.print_check(result, checks)
            if self.max_checks > 0 and checks >= self.max_checks:
                break
            time.sleep(self.interval)

    def print_check(self, result: Dict[str, Optional[str]], count: int):
        """Print the latest monitoring result."""
        prefix = f'[{count}]'
        if result['status_code'] == 'ERROR':
            logger.warning(f"{prefix} ERROR - {result['error']}")
        else:
            logger.info(f"{prefix} {result['status_code']} {result['latency_ms']}ms {result['content_type']}")
        if result['location']:
            logger.info(f"{prefix} Location: {result['location']}")

    def print_summary(self):
        """Print monitoring summary statistics."""
        elapsed = datetime.utcnow() - self.start_time
        print('\n' + '='*90)
        print('SilentWatch - Monitoring Summary')
        print('='*90)
        print(f'URL: {self.url}')
        print(f'Started: {self.start_time.isoformat()}Z')
        print(f'Elapsed: {elapsed}')
        print(f'Checks performed: {len(self.history)}')
        print('Status counts:')
        for status, count in self.status_counts.items():
            print(f'  {status}: {count}')
        if self.failures:
            print('\nFailures:')
            for failure in self.failures[-5:]:
                print(f"  {failure['timestamp']}: {failure['error']}")
        print('='*90 + '\n')

    def uptime_percentage(self) -> float:
        """Compute the percentage of successful checks."""
        total = len(self.history)
        if total == 0:
            return 0.0
        successful = self.status_counts.get('ok', 0)
        return successful / total * 100.0

    def downtime_summary(self) -> Dict[str, int]:
        """Return a summary of downtime and warnings."""
        return {
            'warnings': self.status_counts.get('warning', 0),
            'errors': self.status_counts.get('error', 0)
        }

    def export_text(self, filename: str):
        """Export monitoring results to a plain text report."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('SilentWatch Report\n')
                fh.write('='*90 + '\n')
                fh.write(f'URL: {self.url}\n')
                fh.write(f'Interval: {self.interval}s\n')
                fh.write(f'Checks: {len(self.history)}\n')
                fh.write(f'Uptime: {self.uptime_percentage():.2f}%\n')
                fh.write(f'Warnings: {self.status_counts.get("warning",0)}\n')
                fh.write(f'Errors: {self.status_counts.get("error",0)}\n\n')
                for entry in self.history:
                    fh.write(f"{entry['timestamp']} {entry['status_code']} {entry.get('latency_ms')}ms\n")
            logger.info(f'Text report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text report: {exc}')

    def export_markdown(self, filename: str):
        """Export monitoring results to markdown."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('# SilentWatch Report\n\n')
                fh.write(f'* URL: {self.url}\n')
                fh.write(f'* Interval: {self.interval}s\n')
                fh.write(f'* Checks: {len(self.history)}\n')
                fh.write(f'* Uptime: {self.uptime_percentage():.2f}%\n')
                fh.write(f'* Warnings: {self.status_counts.get("warning",0)}\n')
                fh.write(f'* Errors: {self.status_counts.get("error",0)}\n\n')
                fh.write('## History\n')
                for entry in self.history:
                    fh.write(f'* {entry["timestamp"]} - {entry["status_code"]} - {entry.get("latency_ms")}ms\n')
            logger.info(f'Markdown report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write markdown report: {exc}')

    def detect_trend(self) -> str:
        """Analyze the monitoring history for a status trend."""
        if len(self.history) < 2:
            return 'insufficient data'
        last = self.history[-1]['status_code']
        previous = self.history[-2]['status_code']
        if last == previous:
            return 'stable'
        if last == 'ERROR':
            return 'degrading'
        return 'improving'

    def error_rate(self) -> float:
        """Return the percentage of checks that failed."""
        total = len(self.history)
        if total == 0:
            return 0.0
        return (self.status_counts.get('error', 0) / total) * 100.0

    def export_csv(self, filename: str):
        """Export monitoring history to CSV."""
        import csv
        try:
            with open(filename, 'w', encoding='utf-8', newline='') as fh:
                writer = csv.writer(fh)
                writer.writerow(['timestamp', 'status_code', 'latency_ms', 'content_type', 'location', 'error'])
                for entry in self.history:
                    writer.writerow([
                        entry.get('timestamp'),
                        entry.get('status_code'),
                        entry.get('latency_ms'),
                        entry.get('content_type'),
                        entry.get('location'),
                        entry.get('error')
                    ])
            logger.info(f'CSV report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write CSV report: {exc}')

    def print_detail_report(self):
        """Print a detailed failure and latency report."""
        print('\n' + '='*90)
        print('SilentWatch - Detailed Failure Report')
        print('='*90)
        for entry in self.history:
            print(f"{entry['timestamp']} status={entry['status_code']} latency={entry.get('latency_ms')}ms error={entry.get('error')}")
        print('='*90 + '\n')

    def export_html(self, filename: str):
        """Export monitoring results to an HTML report."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('<html><body>\n')
                fh.write(f'<h1>SilentWatch Report for {self.url}</h1>\n')
                fh.write(f'<p>Checks: {len(self.history)}</p>\n')
                fh.write(f'<p>Uptime: {self.uptime_percentage():.2f}%</p>\n')
                fh.write(f'<p>Error rate: {self.error_rate():.2f}%</p>\n')
                fh.write('<h2>History</h2>\n<ul>\n')
                for entry in self.history:
                    fh.write(f'<li>{entry["timestamp"]} - {entry["status_code"]} - {entry.get("latency_ms")}ms</li>\n')
                fh.write('</ul>\n</body></html>\n')
            logger.info(f'HTML report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write HTML report: {exc}')


def main():
    parser = argparse.ArgumentParser(
        description='SilentWatch - Continuous URL monitoring and uptime checking',
        epilog='Examples:\n'
               '  python silentwatch.py https://target.com\n'
               '  python silentwatch.py https://target.com --interval 30 --max-checks 20\n'
               '  python silentwatch.py https://target.com --json monitor.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('url', help='URL to monitor')
    parser.add_argument('--interval', type=int, default=15, help='Seconds between checks')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout seconds')
    parser.add_argument('--max-checks', type=int, default=0, help='Maximum number of checks (0 for unlimited)')
    parser.add_argument('--json', help='Export history to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    watcher = SilentWatch(url=args.url, interval=args.interval, timeout=args.timeout, max_checks=args.max_checks)
    try:
        watcher.monitor()
        watcher.print_summary()
        if args.json:
            watcher.export_json(args.json)
    except KeyboardInterrupt:
        logger.warning('Monitoring stopped by user')
        watcher.print_summary()
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
