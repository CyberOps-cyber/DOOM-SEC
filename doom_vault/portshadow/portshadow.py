#!/usr/bin/env python3
"""
PortShadow - TCP Port Scanner and Service Enumeration Utility
Performs fast TCP scanning, banner grabbing, and service discovery with concurrency.
"""

import argparse
import logging
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class PortShadow:
    """TCP port scanning and service enumeration engine."""
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445, 465, 587, 631, 8080, 8443]

    def __init__(self, target: str, ports: List[int] = None, timeout: float = 1.0, threads: int = 50):
        self.target = target
        self.ports = ports or self.COMMON_PORTS
        self.timeout = timeout
        self.threads = threads
        self.results: Dict[int, Dict[str, str]] = {}
        self.stats = {
            'scanned': 0,
            'open': 0,
            'closed': 0,
            'errors': 0,
            'duration': 0.0
        }

    def build_port_list(self, port_args: List[int]) -> List[int]:
        """Normalize and deduplicate port list."""
        unique_ports = sorted(set(port_args))
        return [port for port in unique_ports if 0 < port < 65536]

    def scan_port(self, port: int) -> Tuple[int, Dict[str, str]]:
        """Scan a single TCP port and optionally grab banners."""
        self.stats['scanned'] += 1
        data = {
            'port': port,
            'state': 'closed',
            'banner': '',
            'service': ''
        }

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    data['state'] = 'open'
                    self.stats['open'] += 1
                    data['banner'] = self.grab_banner(sock)
                    data['service'] = self.identify_service(port, data['banner'])
                else:
                    data['state'] = 'closed'
                    self.stats['closed'] += 1
        except Exception as exc:
            self.stats['errors'] += 1
            data['state'] = 'error'
            data['banner'] = str(exc)
        return port, data

    def grab_banner(self, sock: socket.socket) -> str:
        """Attempt to retrieve a service banner from an open socket."""
        try:
            sock.settimeout(self.timeout)
            banner = sock.recv(1024)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
            return ''
        except Exception:
            return ''

    def identify_service(self, port: int, banner: str) -> str:
        """Guess service name based on port and banner content."""
        guesses = {
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
        }
        banner_lower = banner.lower()
        for signature, name in [('ssh', 'SSH'), ('http', 'HTTP'), ('smtp', 'SMTP'), ('mysql', 'MySQL'), ('vnc', 'VNC')]:
            if signature in banner_lower:
                return name
        return guesses.get(port, 'Unknown')

    def run_scan(self, ports: List[int]):
        """Run port scanning concurrently."""
        self.ports = self.build_port_list(ports)
        logger.info(f'Scanning {len(self.ports)} ports on {self.target} with {self.threads} threads')
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            for future in as_completed(futures):
                try:
                    port, result = future.result()
                    self.results[port] = result
                except Exception as exc:
                    logger.debug(f'Error scanning port: {exc}')
        self.stats['duration'] = time.time() - start

    def print_report(self):
        """Print scan summary and open port details."""
        print('\n' + '='*90)
        print(f'PortShadow - TCP Port Scan Report for {self.target}')
        print('='*90)
        print(f'  Total ports scanned: {self.stats["scanned"]}')
        print(f'  Open ports: {self.stats["open"]}')
        print(f'  Closed ports: {self.stats["closed"]}')
        print(f'  Errors: {self.stats["errors"]}')
        print(f'  Duration: {self.stats["duration"]:.2f}s')

        print('\n[OPEN PORTS]')
        for port in sorted(self.results):
            result = self.results[port]
            if result['state'] == 'open':
                print(f'  {port}/tcp - {result["service"]} - Banner: {result["banner"] or "(none)"}')

        print('\n' + '='*90 + '\n')

    def export_json(self, filename: str):
        """Export the scan results to JSON."""
        import json
        payload = {
            'target': self.target,
            'ports': self.results,
            'stats': self.stats,
        }
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Exported scan results to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def format_open_ports(self) -> List[str]:
        """Build a list of formatted open port summary lines."""
        lines = []
        for port in sorted(self.results):
            result = self.results[port]
            if result['state'] == 'open':
                lines.append(f'{port}/tcp - {result["service"]} - Banner: {result["banner"] or "(none)"}')
        return lines

    def export_markdown(self, filename: str):
        """Export a markdown version of the port scan report."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('# PortShadow Scan Report\n\n')
                fh.write(f'* Target: {self.target}\n')
                fh.write(f'* Ports scanned: {self.stats["scanned"]}\n')
                fh.write(f'* Open: {self.stats["open"]}\n')
                fh.write(f'* Closed: {self.stats["closed"]}\n')
                fh.write(f'* Errors: {self.stats["errors"]}\n\n')
                fh.write('## Open Ports\n')
                for line in self.format_open_ports():
                    fh.write(f'* {line}\n')
            logger.info(f'Markdown report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write markdown export: {exc}')

    def scan_port_range(self, start: int, end: int):
        """Scan a contiguous range of TCP ports."""
        self.run_scan(list(range(start, min(end, 65535) + 1)))

    def get_service_summary(self) -> Dict[str, int]:
        """Return counts of discovered service names."""
        summary = {}
        for result in self.results.values():
            if result['state'] == 'open':
                summary[result['service']] = summary.get(result['service'], 0) + 1
        return summary

    def export_text(self, filename: str):
        """Export scan report to plain text."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('PortShadow Report\n')
                fh.write('='*90 + '\n')
                fh.write(f'Target: {self.target}\n')
                fh.write(f'Ports scanned: {self.stats["scanned"]}\n')
                fh.write(f'Open: {self.stats["open"]}, Closed: {self.stats["closed"]}, Errors: {self.stats["errors"]}\n')
                fh.write('\nOpen ports:\n')
                for port, result in self.results.items():
                    if result['state'] == 'open':
                        fh.write(f'  {port}/tcp - {result["service"]} - Banner: {result["banner"] or "(none)"}\n')
                fh.write('\nService summary:\n')
                for service, count in self.get_service_summary().items():
                    fh.write(f'  {service}: {count}\n')
            logger.info(f'Plain text report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text export: {exc}')

    def export_html(self, filename: str):
        """Export the port scan report as an HTML page."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('<html><body>\n')
                fh.write(f'<h1>PortShadow Report for {self.target}</h1>\n')
                fh.write(f'<p>Ports scanned: {self.stats["scanned"]}</p>\n')
                fh.write(f'<p>Open: {self.stats["open"]}, Closed: {self.stats["closed"]}, Errors: {self.stats["errors"]}</p>\n')
                fh.write('<h2>Open Ports</h2>\n<ul>\n')
                for line in self.format_open_ports():
                    fh.write(f'<li>{line}</li>\n')
                fh.write('</ul>\n')
                fh.write('<h2>Service Summary</h2>\n<ul>\n')
                for service, count in self.get_service_summary().items():
                    fh.write(f'<li>{service}: {count}</li>\n')
                fh.write('</ul>\n')
                fh.write('</body></html>\n')
            logger.info(f'HTML report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write HTML export: {exc}')

    def get_port_map(self) -> Dict[str, List[int]]:
        """Return a mapping of service names to open port lists."""
        mapping: Dict[str, List[int]] = {}
        for port, result in self.results.items():
            if result['state'] == 'open':
                mapping.setdefault(result['service'], []).append(port)
        return mapping

    def print_service_map(self):
        """Print the discovered service-to-port mapping."""
        print('\n' + '='*90)
        print('PortShadow - Service Map')
        print('='*90)
        for service, ports in self.get_port_map().items():
            print(f'  {service}: {sorted(ports)}')
        print('='*90 + '\n')


def main():
    parser = argparse.ArgumentParser(
        description='PortShadow - TCP port scanner and service enumeration utility',
        epilog='Examples:\n'
               '  python portshadow.py 192.168.1.10\n'
               '  python portshadow.py example.com -p 22 80 443\n'
               '  python portshadow.py 10.0.0.5 -o results.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Target host or IP address')
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=[22, 80, 443, 8080], help='Ports to scan')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of concurrent threads')
    parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout in seconds')
    parser.add_argument('--json', help='Export results to JSON')
    parser.add_argument('--text', help='Export results to plain text')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase log verbosity')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    scanner = PortShadow(args.target, timeout=args.timeout, threads=args.threads)
    try:
        scanner.run_scan(args.ports)
        scanner.print_report()
        if args.json:
            scanner.export_json(args.json)
        if args.text:
            scanner.export_text(args.text)
    except KeyboardInterrupt:
        logger.warning('Scan interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
