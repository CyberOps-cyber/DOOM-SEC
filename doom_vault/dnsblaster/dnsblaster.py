#!/usr/bin/env python3
"""
DNSBlaster - Advanced DNS Enumeration and Reconnaissance Engine
Performs high-volume DNS discovery, mail server extraction, CAA analysis, reverse lookups, and zone intelligence.
"""

import argparse
import logging
import sys
import dns.resolver
import dns.reversename
import dns.exception
import dns.rdatatype
import dns.query
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class DNSBlaster:
    """DNS enumeration engine with threaded record collection and analysis."""
    DEFAULT_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV', 'CAA', 'PTR']

    def __init__(self, domain: str, record_types: List[str] = None, timeout: int = 5, threads: int = 12):
        self.domain = domain.strip().lower()
        self.record_types = record_types or self.DEFAULT_RECORD_TYPES
        self.timeout = timeout
        self.threads = threads
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        self.results: Dict[str, Any] = {}
        self.stats = {
            'queried': 0,
            'successful': 0,
            'failed': 0,
            'timeouts': 0,
            'records': 0
        }

    def query_record(self, record_type: str) -> Dict[str, Any]:
        """Perform a single DNS query for a given record type."""
        query_name = self.domain
        record_type = record_type.upper()
        self.stats['queried'] += 1
        record_data = {
            'type': record_type,
            'answers': [],
            'ttl': None,
            'error': None
        }

        try:
            answers = self.resolver.resolve(query_name, record_type)
            for answer in answers:
                record_data['answers'].append(answer.to_text())
            if answers.rrset is not None:
                record_data['ttl'] = answers.rrset.ttl
            self.stats['successful'] += 1
            self.stats['records'] += len(record_data['answers'])
        except dns.resolver.NXDOMAIN:
            record_data['error'] = 'NXDOMAIN'
            self.stats['failed'] += 1
        except dns.exception.Timeout:
            record_data['error'] = 'TIMEOUT'
            self.stats['timeouts'] += 1
        except dns.resolver.NoAnswer:
            record_data['error'] = 'NOANSWER'
            self.stats['failed'] += 1
        except Exception as exc:
            record_data['error'] = str(exc)
            self.stats['failed'] += 1

        return record_type, record_data

    def reverse_lookup(self, address: str) -> str:
        """Perform a reverse DNS lookup for an IP address."""
        try:
            rev_name = dns.reversename.from_address(address)
            answers = self.resolver.resolve(rev_name, 'PTR')
            return '; '.join([str(ans) for ans in answers])
        except Exception as exc:
            return f'failed ({exc})'

    def enumerate(self):
        """Enumerate all configured DNS records using concurrent requests."""
        logger.info(f"Starting DNS enumeration for {self.domain} with {self.threads} threads")
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.query_record, record_type): record_type for record_type in self.record_types}
            for future in as_completed(futures):
                rec_type, data = future.result()
                self.results[rec_type] = data
        elapsed = time.time() - start
        logger.info(f"DNS enumeration completed in {elapsed:.2f}s")

    def find_mx_hosts(self) -> List[Dict[str, Any]]:
        """Extract and normalize MX records for mail server discovery."""
        output = []
        mx = self.results.get('MX', {}).get('answers', [])
        for entry in mx:
            try:
                priority, host = entry.split(None, 1)
                output.append({'priority': int(priority), 'host': host.strip('.')})
            except ValueError:
                output.append({'priority': None, 'host': entry.strip('.')})
        output.sort(key=lambda x: (x['priority'] if x['priority'] is not None else 9999, x['host']))
        return output

    def extract_nameservers(self) -> List[str]:
        """Collect NS records from enumeration results."""
        return [ns.strip('.') for ns in self.results.get('NS', {}).get('answers', [])]

    def analyze_caa(self) -> List[Dict[str, Any]]:
        """Analyze CAA records for certificate authority restrictions."""
        caas = []
        for entry in self.results.get('CAA', {}).get('answers', []):
            parts = entry.split()
            if len(parts) >= 3:
                caas.append({'flags': parts[0], 'tag': parts[1], 'value': ' '.join(parts[2:])})
            else:
                caas.append({'raw': entry})
        return caas

    def print_report(self):
        """Print a detailed DNS reconnaissance report."""
        print('\n' + '='*90)
        print(f'DNSBlaster - Reconnaissance Report for {self.domain}')
        print('='*90)
        print('\n[SUMMARY]')
        print(f'  Queried record types: {len(self.record_types)}')
        print(f'  Total records found: {self.stats["records"]}')
        print(f'  Successful queries: {self.stats["successful"]}')
        print(f'  Failed queries: {self.stats["failed"]}')
        print(f'  Timeouts: {self.stats["timeouts"]}')

        print('\n[RECORD DETAILS]')
        for record_type in sorted(self.record_types):
            data = self.results.get(record_type, {})
            print(f'\n  {record_type}:')
            if not data:
                print('    no data collected')
                continue
            if data['answers']:
                print(f'    TTL: {data.get("ttl", "N/A")}')
                for answer in data['answers']:
                    print(f'      - {answer}')
            else:
                print(f'    error: {data.get("error", "no answer")})')

        nameservers = self.extract_nameservers()
        if nameservers:
            print('\n[NAME SERVERS]')
            for ns in nameservers:
                print(f'  - {ns}')

        mx_hosts = self.find_mx_hosts()
        if mx_hosts:
            print('\n[MAIL SERVERS]')
            for mx in mx_hosts:
                pr = mx['priority'] if mx['priority'] is not None else 'unknown'
                print(f'  - {mx["host"]} (priority {pr})')

        caa = self.analyze_caa()
        if caa:
            print('\n[CAA RECORDS]')
            for entry in caa:
                print(f'  - {entry}')

        ptr_answers = self.perform_ptr_discovery()
        if ptr_answers:
            print('\n[PTR LOOKUPS]')
            for item in ptr_answers:
                print(f'  - {item["ip"]} -> {item["ptr"]}')

        print('\n' + '='*90 + '\n')

    def perform_ptr_discovery(self) -> List[Dict[str, str]]:
        """Perform reverse DNS lookups for all discovered A/AAAA addresses."""
        answers = []
        addresses = []
        for rec_type in ['A', 'AAAA']:
            addresses.extend(self.results.get(rec_type, {}).get('answers', []))
        unique_addresses = sorted(set(addresses))
        for address in unique_addresses:
            result = self.reverse_lookup(address)
            answers.append({'ip': address, 'ptr': result})
        return answers

    def export_json(self, filename: str):
        """Export reconnaissance results to a JSON file."""
        import json
        payload = {
            'domain': self.domain,
            'records': self.results,
            'mx_hosts': self.find_mx_hosts(),
            'name_servers': self.extract_nameservers(),
            'caa': self.analyze_caa(),
            'spf': self.query_spf(),
            'dmarc': self.query_dmarc(),
            'zone_transfer': self.attempt_zone_transfer()
        }
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Results exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export results: {exc}')

    def query_spf(self) -> str:
        """Query the SPF record for the target domain."""
        try:
            answers = self.resolver.resolve(self.domain, 'TXT')
            for answer in answers:
                text = answer.to_text().strip('"')
                if text.lower().startswith('v=spf1'):
                    return text
        except Exception:
            pass
        return 'not found'

    def query_dmarc(self) -> str:
        """Query the DMARC record for the target domain."""
        try:
            dmarc_domain = f'_dmarc.{self.domain}'
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for answer in answers:
                text = answer.to_text().strip('"')
                if text.lower().startswith('v=dmarc1'):
                    return text
        except Exception:
            pass
        return 'not found'

    def attempt_zone_transfer(self) -> Dict[str, List[str]]:
        """Try to perform a DNS zone transfer against name servers."""
        result = {}
        nameservers = self.extract_nameservers()
        for ns in nameservers:
            try:
                transfer = dns.query.xfr(ns, self.domain, lifetime=self.timeout)
                records = []
                for response in transfer:
                    for answer in response.answer:
                        records.extend([r.to_text() for r in answer])
                result[ns] = records or ['no data']
            except Exception as exc:
                result[ns] = [f'failed: {exc}']
        return result

    def export_text(self, filename: str):
        """Export reconnaissance results to a plain text file."""
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                fh.write('DNSBlaster Report\n')
                fh.write('='*90 + '\n')
                for record_type in sorted(self.record_types):
                    data = self.results.get(record_type, {})
                    fh.write(f'\n{record_type}:\n')
                    if data.get('answers'):
                        for answer in data['answers']:
                            fh.write(f'  - {answer}\n')
                    else:
                        fh.write(f'  Error: {data.get("error", "no data")}\n')
                fh.write('\nSPF: ' + self.query_spf() + '\n')
                fh.write('DMARC: ' + self.query_dmarc() + '\n')
            logger.info(f'Text results written to {filename}')
        except Exception as exc:
            logger.error(f'Failed to write text results: {exc}')

    @staticmethod
    def normalize_record_types(record_types: List[str]) -> List[str]:
        """Normalize record type list to standard uppercase values."""
        normalized = []
        for record in record_types:
            normalized.append(record.upper().strip())
        return sorted(set(normalized))


def main():
    parser = argparse.ArgumentParser(
        description='DNSBlaster - Advanced DNS enumeration and reconnaissance engine',
        epilog='Examples:\n'
               '  python dnsblaster.py example.com\n'
               '  python dnsblaster.py example.com -r A AAAA MX NS TXT CAA\n'
               '  python dnsblaster.py example.com --json output.json',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('domain', help='Target domain for DNS enumeration')
    parser.add_argument('-r', '--records', nargs='+', default=['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA'], help='Record types to query')
    parser.add_argument('-t', '--threads', type=int, default=12, help='Number of concurrent query threads')
    parser.add_argument('--timeout', type=int, default=5, help='DNS query timeout in seconds')
    parser.add_argument('--json', type=str, help='Export full results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    record_types = DNSBlaster.normalize_record_types(args.records)
    blaster = DNSBlaster(args.domain, record_types=record_types, timeout=args.timeout, threads=args.threads)
    try:
        blaster.enumerate()
        blaster.print_report()
        if args.json:
            blaster.export_json(args.json)
    except KeyboardInterrupt:
        logger.warning('Enumeration interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
