#!/usr/bin/env python3
"""
ServiceJoker - Service Banner Grabbing and Enumeration Utility
Probes TCP services and HTTP endpoints to fingerprint service types and versions.
"""

import argparse
import socket
import logging
import sys
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Any
import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class ServiceJoker:
    """Banner grabbing engine with service heuristics and HTTP probing."""
    HTTP_PORTS = {80, 443, 8080, 8443}
    DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 3306, 3389, 5900, 8080, 8443]

    def __init__(self, host: str, ports: List[int] = None, timeout: float = 3.0, threads: int = 20):
        self.host = host
        self.ports = ports or self.DEFAULT_PORTS
        self.timeout = timeout
        self.threads = threads
        self.results: Dict[int, Dict[str, Any]] = {}

    def normalize_ports(self, ports: List[int]) -> List[int]:
        """Clean up and deduplicate requested port list."""
        return sorted(set([p for p in ports if 1 <= p <= 65535]))

    def banner_probe(self, port: int) -> Dict[str, Any]:
        """Probe banner for a TCP service on a specific port."""
        result = {
            'port': port,
            'open': False,
            'banner': '',
            'service': '',
            'http_headers': {},
            'protocol': 'tcp',
            'error': None
        }
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                result['open'] = True
                if port in self.HTTP_PORTS:
                    result['protocol'] = 'http'
                    result['http_headers'] = self.probe_http(sock, port)
                else:
                    sock.settimeout(self.timeout)
                    banner = sock.recv(2048)
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                result['service'] = self.guess_service(port, result['banner'])
        except Exception as exc:
            result['error'] = str(exc)
        return result

    def probe_http(self, sock: socket.socket, port: int) -> Dict[str, str]:
        """Send a simple HTTP request and capture response headers."""
        headers = {}
        request = 'HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n'.format(self.host)
        try:
            sock.sendall(request.encode('utf-8'))
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            for line in response.splitlines():
                if ':' in line:
                    name, value = line.split(':', 1)
                    headers[name.strip()] = value.strip()
        except Exception:
            pass
        return headers

    def guess_service(self, port: int, banner: str) -> str:
        """Guess service type based on port and banner contents."""
        banner_text = banner.lower()
        if 'ssh' in banner_text:
            return 'SSH'
        if 'smtp' in banner_text:
            return 'SMTP'
        if 'ftp' in banner_text:
            return 'FTP'
        if 'imap' in banner_text:
            return 'IMAP'
        if 'mysql' in banner_text:
            return 'MySQL'
        if 'microsoft' in banner_text or 'rdp' in banner_text:
            return 'RDP'
        if any(term in banner_text for term in ['http', 'apache', 'nginx', 'iis', 'tomcat']):
            return 'HTTP'
        if port == 80:
            return 'HTTP'
        if port == 443:
            return 'HTTPS'
        return 'Unknown'

    def run(self):
        """Run banner and header probing across all ports."""
        self.ports = self.normalize_ports(self.ports)
        logger.info(f'Probing {len(self.ports)} ports on {self.host} with {self.threads} threads')
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.banner_probe, port): port for port in self.ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    result = future.result()
                    self.results[port] = result
                except Exception as exc:
                    self.results[port] = {'port': port, 'open': False, 'error': str(exc)}

    def probe_http_full(self, port: int) -> Dict[str, Any]:
        """Probe an HTTP(S) endpoint for titles, headers, and security fingerprints."""
        scheme = 'https' if port == 443 else 'http'
        url = f'{scheme}://{self.host}'
        if port not in (80, 443):
            url += f':{port}'
        result = {'url': url, 'status_code': None, 'headers': {}, 'title': '', 'error': None}
        try:
            response = requests.head(url, timeout=self.timeout, allow_redirects=True, verify=False)
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['title'] = self.extract_title(response.text if hasattr(response, 'text') else '')
        except requests.RequestException as exc:
            result['error'] = str(exc)
        return result

    def extract_title(self, html: str) -> str:
        """Extract HTML title from response content."""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ''

    def print_report(self):
        """Print service enumeration report."""
        print('\n' + '='*90)
        print(f'ServiceJoker - Service Enumeration Report for {self.host}')
        print('='*90)
        for port in sorted(self.results):
            entry = self.results[port]
            state = 'OPEN' if entry.get('open') else 'CLOSED'
            print(f'\nPort {port}: {state}')
            if entry.get('error'):
                print(f'  Error: {entry["error"]}')
                continue
            if entry.get('banner'):
                print(f'  Banner: {entry["banner"]}')
            if entry.get('service'):
                print(f'  Service: {entry["service"]}')
            if entry.get('http_headers'):
                print('  HTTP headers:')
                for header, value in entry['http_headers'].items():
                    print(f'    {header}: {value}')
        print('\n' + '='*90 + '\n')

    def probe_ssl(self, port: int) -> Dict[str, str]:
        """Probe SSL/TLS certificate details for HTTPS services."""
        result = {'port': port, 'certificate': '', 'issuer': '', 'subject': '', 'error': None}
        try:
            with socket.create_connection((self.host, port), timeout=self.timeout) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    result['certificate'] = cert.get('subject', '')
                    result['issuer'] = cert.get('issuer', '')
                    result['subject'] = cert.get('subject', '')
        except Exception as exc:
            result['error'] = str(exc)
        return result

    def export_text(self, filename: str):
        """Export results to plain text."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('ServiceJoker Report\n')
                fh.write('='*90 + '\n')
                for port in sorted(self.results):
                    entry = self.results[port]
                    fh.write(f'Port {port}: {"OPEN" if entry.get("open") else "CLOSED"}\n')
                    if entry.get('error'):
                        fh.write(f'  Error: {entry["error"]}\n')
                        continue
                    if entry.get('banner'):
                        fh.write(f'  Banner: {entry["banner"]}\n')
                    if entry.get('service'):
                        fh.write(f'  Service: {entry["service"]}\n')
                    if entry.get('http_headers'):
                        fh.write('  HTTP headers:\n')
                        for header, value in entry['http_headers'].items():
                            fh.write(f'    {header}: {value}\n')
                fh.write('\n')
            logger.info(f'Text report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text report: {exc}')

    def export_markdown(self, filename: str):
        """Export enumeration results to markdown."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write(f'# ServiceJoker Report for {self.host}\n\n')
                for port in sorted(self.results):
                    entry = self.results[port]
                    fh.write(f'## Port {port}\n')
                    fh.write(f'* Open: {entry.get("open")}\n')
                    if entry.get('error'):
                        fh.write(f'* Error: {entry["error"]}\n')
                        continue
                    fh.write(f'* Service: {entry.get("service")}\n')
                    if entry.get('banner'):
                        fh.write(f'* Banner: {entry.get("banner")}\n')
                    if entry.get('http_headers'):
                        fh.write('* HTTP headers:\n')
                        for header, value in entry['http_headers'].items():
                            fh.write(f'  * {header}: {value}\n')
                logger.info(f'Markdown report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write markdown report: {exc}')

    def export_csv(self, filename: str):
        """Export probe results to a CSV file."""
        import csv
        try:
            with open(filename, 'w', encoding='utf-8', newline='') as fh:
                writer = csv.writer(fh)
                writer.writerow(['port', 'open', 'service', 'banner', 'error'])
                for port in sorted(self.results):
                    entry = self.results[port]
                    writer.writerow([
                        port,
                        entry.get('open'),
                        entry.get('service'),
                        entry.get('banner'),
                        entry.get('error')
                    ])
            logger.info(f'CSV report written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write CSV report: {exc}')

    def probe_ssl_metadata(self, port: int) -> Dict[str, Any]:
        """Probe SSL metadata if HTTPS is available."""
        return self.probe_ssl(port) if port == 443 else {'port': port, 'error': 'SSL metadata only available on port 443'}


def main():
    parser = argparse.ArgumentParser(
        description='ServiceJoker - service banner grabbing and enumeration tool',
        epilog='Examples:\n'
               '  python servicejoker.py example.com\n'
               '  python servicejoker.py example.com -p 21 22 80 443\n'
               '  python servicejoker.py target.host --json output.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('host', help='Target host to probe')
    parser.add_argument('-p', '--ports', nargs='+', type=int, default=[21, 22, 23, 25, 53, 80, 110, 143, 443, 8080], help='Ports to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent probes')
    parser.add_argument('--timeout', type=float, default=3.0, help='Connection timeout in seconds')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    joker = ServiceJoker(args.host, ports=args.ports, timeout=args.timeout, threads=args.threads)
    try:
        joker.run()
        joker.print_report()
        if args.json:
            joker.export_json(args.json)
    except KeyboardInterrupt:
        logger.warning('Probe interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
