#!/usr/bin/env python3
"""
StealthPing - Covert Reachability and Latency Assessment Tool
Executes stealthy ping tests, tracks jitter, and reports reachability for hosts and networks.
"""

import argparse
import platform
import subprocess
import logging
import sys
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class StealthPing:
    """Stealthy ICMP reachability and latency measurement engine."""
    def __init__(self, targets: List[str], count: int = 4, interval: int = 1, timeout: int = 2):
        self.targets = targets
        self.count = count
        self.interval = interval
        self.timeout = timeout
        self.results: Dict[str, Dict[str, Optional[float]]] = {}
        self.platform = platform.system().lower()
        self.ping_command = self.get_ping_command()

    def get_ping_command(self) -> List[str]:
        """Determine correct ping command syntax for the current platform."""
        if 'windows' in self.platform:
            return ['ping', '-n', str(self.count), '-w', str(self.timeout * 1000)]
        else:
            return ['ping', '-c', str(self.count), '-W', str(self.timeout)]

    def run_ping(self, host: str) -> Dict[str, Optional[float]]:
        """Run a ping command for a single host and parse metrics."""
        command = self.ping_command + [host]
        logger.info(f'Pinging {host} with {self.count} packets')
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout * self.count + 5)
            output = result.stdout
            if result.returncode == 0 or 'ttl=' in output.lower():
                parsed = self.parse_ping_output(output)
                metrics = {
                    'reachable': True,
                    'transmitted': parsed.get('transmitted'),
                    'received': parsed.get('received'),
                    'loss_pct': parsed.get('loss_pct'),
                    'min_ms': parsed.get('min_ms'),
                    'avg_ms': parsed.get('avg_ms'),
                    'max_ms': parsed.get('max_ms'),
                    'stddev_ms': parsed.get('stddev_ms')
                }
                logger.debug(f'Ping results for {host}: {metrics}')
                return metrics
            else:
                return {'reachable': False, 'transmitted': self.count, 'received': 0, 'loss_pct': 100.0, 'min_ms': None, 'avg_ms': None, 'max_ms': None, 'stddev_ms': None}
        except subprocess.TimeoutExpired:
            logger.warning(f'Ping timed out for {host}')
            return {'reachable': False, 'transmitted': self.count, 'received': 0, 'loss_pct': 100.0, 'min_ms': None, 'avg_ms': None, 'max_ms': None, 'stddev_ms': None}
        except Exception as exc:
            logger.error(f'Ping failed for {host}: {exc}')
            return {'reachable': False, 'transmitted': self.count, 'received': 0, 'loss_pct': 100.0, 'min_ms': None, 'avg_ms': None, 'max_ms': None, 'stddev_ms': None}

    def parse_ping_output(self, output: str) -> Dict[str, Optional[float]]:
        """Parse output from the ping command for latency metrics."""
        metrics: Dict[str, Optional[float]] = {
            'transmitted': None,
            'received': None,
            'loss_pct': None,
            'min_ms': None,
            'avg_ms': None,
            'max_ms': None,
            'stddev_ms': None
        }
        loss_match = re.search(r'(?P<tx>\d+) packets transmitted, (?P<rx>\d+) (?:packets )?received, (?P<loss>[0-9.]+)% packet loss', output)
        if loss_match:
            metrics['transmitted'] = int(loss_match.group('tx'))
            metrics['received'] = int(loss_match.group('rx'))
            metrics['loss_pct'] = float(loss_match.group('loss'))
        else:
            loss_match = re.search(r'(?P<rx>\d+) received, (?P<loss>[0-9.]+)% packet loss', output)
            if loss_match:
                metrics['transmitted'] = self.count
                metrics['received'] = int(loss_match.group('rx'))
                metrics['loss_pct'] = float(loss_match.group('loss'))

        stats_match = re.search(r'(?P<min>[0-9.]+)/(?P<avg>[0-9.]+)/(?P<max>[0-9.]+)(?:/(?P<stddev>[0-9.]+))?', output)
        if stats_match:
            metrics['min_ms'] = float(stats_match.group('min'))
            metrics['avg_ms'] = float(stats_match.group('avg'))
            metrics['max_ms'] = float(stats_match.group('max'))
            if stats_match.group('stddev'):
                metrics['stddev_ms'] = float(stats_match.group('stddev'))

        return metrics

    def sweep_network(self, base_ip: str, start: int = 1, end: int = 254) -> Dict[str, Dict[str, Optional[float]]]:
        """Perform a ping sweep across an IPv4 subnet prefix."""
        if not base_ip.endswith('.'):
            base_ip = base_ip.rsplit('.', 1)[0] + '.'
        results: Dict[str, Dict[str, Optional[float]]] = {}
        for last_octet in range(start, end + 1):
            ip = f'{base_ip}{last_octet}'
            metrics = self.run_ping(ip)
            results[ip] = metrics
            time.sleep(self.interval)
        return results

    def run(self):
        """Run reachability tests for configured targets."""
        for host in self.targets:
            result = self.run_ping(host)
            self.results[host] = result
            time.sleep(self.interval)

    def get_summary(self) -> Dict[str, Any]:
        """Build a summary of ping outcomes."""
        summary = {'reachable': 0, 'unreachable': 0, 'hosts': len(self.targets)}
        for host, result in self.results.items():
            if result.get('reachable'):
                summary['reachable'] += 1
            else:
                summary['unreachable'] += 1
        return summary

    def print_report(self):
        """Print the full ping assessment report."""
        print('\n' + '='*90)
        print('StealthPing - Reachability and Latency Report')
        print('='*90)
        for host, metrics in self.results.items():
            status = 'REACHABLE' if metrics.get('reachable') else 'UNREACHABLE'
            print(f'\nHost: {host} -- {status}')
            print(f'  Sent: {metrics.get("transmitted")}, Received: {metrics.get("received")}, Loss: {metrics.get("loss_pct")}%')
            print(f'  Min: {metrics.get("min_ms")}, Avg: {metrics.get("avg_ms")}, Max: {metrics.get("max_ms")}, Stddev: {metrics.get("stddev_ms")}')
        print('\n' + '='*90 + '\n')

    def export_json(self, filename: str):
        """Export results to JSON file."""
        import json
        try:
            with open(filename, 'w', encoding='utf-8') as handle:
                json.dump({'results': self.results, 'summary': self.get_summary()}, handle, indent=2)
            logger.info(f'Results exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def classify_hosts(self) -> Dict[str, List[str]]:
        """Classify hosts based on reachability and latency."""
        groups = {'reachable': [], 'unreachable': [], 'high_latency': []}
        for host, metrics in self.results.items():
            if metrics.get('reachable'):
                groups['reachable'].append(host)
                if metrics.get('avg_ms') and metrics['avg_ms'] > (self.timeout * 1000 / 2):
                    groups['high_latency'].append(host)
            else:
                groups['unreachable'].append(host)
        return groups

    def run_sweep(self, base_ip: str, start: int = 1, end: int = 254) -> Dict[str, Dict[str, Optional[float]]]:
        """Perform a network ping sweep over a /24 range."""
        if not base_ip.endswith('.'):
            base_ip = base_ip.rsplit('.', 1)[0] + '.'
        results: Dict[str, Dict[str, Optional[float]]] = {}
        with ThreadPoolExecutor(max_workers=self.count) as executor:
            futures = {executor.submit(self.run_ping, f'{base_ip}{octet}'): f'{base_ip}{octet}' for octet in range(start, min(end, 254) + 1)}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    results[host] = future.result()
                except Exception as exc:
                    logger.debug(f'Sweep error for {host}: {exc}')
                    results[host] = {'reachable': False, 'transmitted': self.count, 'received': 0, 'loss_pct': 100.0, 'min_ms': None, 'avg_ms': None, 'max_ms': None, 'stddev_ms': None}
        self.results.update(results)
        return results

    def print_summary(self):
        """Print an aggregated summary of stealth ping results."""
        groups = self.classify_hosts()
        print('\n' + '='*90)
        print('StealthPing - Summary Report')
        print('='*90)
        print(f"Targets: {len(self.targets)}")
        print(f"Reachable: {len(groups['reachable'])}")
        print(f"Unreachable: {len(groups['unreachable'])}")
        print(f"High latency: {len(groups['high_latency'])}")
        print('='*90 + '\n')

    def export_json(self, filename: str):
        """Export results to JSON file."""
        import json
        try:
            with open(filename, 'w', encoding='utf-8') as handle:
                json.dump({'results': self.results, 'summary': self.classify_hosts()}, handle, indent=2)
            logger.info(f'Results exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def export_text(self, filename: str):
        """Export results to plain text file."""
        try:
            with open(filename, 'w', encoding='utf-8') as handle:
                handle.write('StealthPing Report\n')
                handle.write('='*90 + '\n')
                for host, metrics in self.results.items():
                    handle.write(f'Host: {host}\n')
                    handle.write(f'  Reachable: {metrics.get("reachable")}\n')
                    handle.write(f'  Loss: {metrics.get("loss_pct")}%\n')
                    handle.write(f'  Avg latency: {metrics.get("avg_ms")} ms\n\n')
                handle.write('Summary:\n')
                summary = self.classify_hosts()
                for category, hosts in summary.items():
                    handle.write(f'  {category}: {len(hosts)}\n')
            logger.info(f'Text report exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text export: {exc}')


def main():
    parser = argparse.ArgumentParser(
        description='StealthPing - Covert reachability and latency assessment tool',
        epilog='Examples:\n'
               '  python stealthping.py 10.0.0.1\n'
               '  python stealthping.py host.example.com --count 6 --interval 2\n'
               '  python stealthping.py 10.0.0.1 10.0.0.2 --json report.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', nargs='+', help='Target hostnames or IP addresses to ping')
    parser.add_argument('-c', '--count', type=int, default=4, help='Number of ICMP requests to send')
    parser.add_argument('-i', '--interval', type=int, default=1, help='Seconds between ping attempts')
    parser.add_argument('--timeout', type=int, default=2, help='Per-packet timeout in seconds')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--text', help='Export results to plain text file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    ping_tool = StealthPing(targets=args.targets, count=args.count, interval=args.interval, timeout=args.timeout)
    try:
        ping_tool.run()
        ping_tool.print_report()
        if args.json:
            ping_tool.export_json(args.json)
        if args.text:
            ping_tool.export_text(args.text)
    except KeyboardInterrupt:
        logger.warning('Scan interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
