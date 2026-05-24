#!/usr/bin/env python3
"""
APIKeyHunter - Comprehensive API Key and Secret Detection Utility
Scans source code, configuration files, and directories for exposed credentials.
"""

import argparse
import logging
import math
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple
import mimetypes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class APIKeyHunter:
    """API key detection engine with recursive scanning and summary reporting."""
    PATTERNS = {
        'api_key': [
            r'api[_-]?key[\s:=]+["\']?([A-Za-z0-9_\-]{16,128})',
            r'key[\s:=]+["\']?([A-Za-z0-9_\-]{16,128})',
            r'apiKey[\s:=]+["\']?([A-Za-z0-9_\-]{16,128})'
        ],
        'secret': [
            r'secret[\s:=]+["\']?([A-Za-z0-9_\-]{16,128})',
            r'SECRET[\s:=]+["\']?([A-Za-z0-9_\-]{16,128})'
        ],
        'token': [
            r'token[\s:=]+["\']?([A-Za-z0-9_\-.]{16,128})',
            r'auth[\s:=]+["\']?([A-Za-z0-9_\-.]{16,128})'
        ],
        'aws': [
            r'AKIA[0-9A-Z]{16}',
            r'aws_access_key_id[\s:=]+["\']?([A-Z0-9]{20})',
            r'aws_secret_access_key[\s:=]+["\']?([A-Za-z0-9/+=]{40})'
        ],
        'stripe': [
            r'sk_live_[A-Za-z0-9]{24}',
            r'pk_live_[A-Za-z0-9]{24}'
        ],
        'github': [
            r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            r'github[_-]?token[\s:=]+["\']?([A-Za-z0-9_\-]{40,})'
        ],
        'database': [
            r'db[_-]?pass(word)?[\s:=]+["\']?([^\s"\']+)',
            r'password[\s:=]+["\']?([^\s"\']+)'
        ],
    }

    TEXT_EXTENSIONS = {'.txt', '.py', '.js', '.java', '.go', '.c', '.cpp', '.sh', '.env', '.conf', '.config',
                       '.json', '.yaml', '.yml', '.xml', '.ini', '.sql', '.php', '.rb', '.html', '.log'}

    def __init__(self, paths: List[str], recursive: bool = False):
        self.paths = paths
        self.recursive = recursive
        self.findings: Dict[str, Dict[str, List[Tuple[int, str, str]]]] = {}
        self.files_scanned = 0
        self.total_hits = 0
        self.skipped = 0

    def is_text_file(self, path: Path) -> bool:
        """Determine whether a file looks like a text file."""
        if path.suffix.lower() in self.TEXT_EXTENSIONS:
            return True
        mime_type, _ = mimetypes.guess_type(str(path))
        return bool(mime_type and 'text' in mime_type)

    def collect_files(self) -> List[Path]:
        """Collect paths for scanning, honoring recursion settings."""
        result = []
        for path in self.paths:
            current = Path(path)
            if current.is_file():
                result.append(current)
            elif current.is_dir():
                if self.recursive:
                    for child in current.rglob('*'):
                        if child.is_file() and self.is_text_file(child):
                            result.append(child)
                else:
                    for child in current.iterdir():
                        if child.is_file() and self.is_text_file(child):
                            result.append(child)
        return sorted(result)

    def compile_patterns(self):
        """Compile regex patterns for detection."""
        compiled = {}
        for label, patterns in self.PATTERNS.items():
            compiled[label] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        return compiled

    def scan_file(self, path: Path) -> Dict[str, List[Tuple[int, str, str]]]:
        """Scan a single file for API keys and secret patterns."""
        findings: Dict[str, List[Tuple[int, str, str]]] = {}
        compiled = self.compile_patterns()
        try:
            with path.open('r', encoding='utf-8', errors='ignore') as fh:
                for lineno, line in enumerate(fh, start=1):
                    for label, patterns in compiled.items():
                        for pattern in patterns:
                            for match in pattern.finditer(line):
                                findings.setdefault(label, []).append((lineno, line.strip(), match.group(0)))
        except (FileNotFoundError, PermissionError) as exc:
            logger.debug(f'Cannot scan {path}: {exc}')
            return {}
        except Exception as exc:
            logger.debug(f'Unexpected scan error for {path}: {exc}')
            return {}
        return findings

    def scan_all(self):
        """Scan all target files and summarize findings."""
        files = self.collect_files()
        if not files:
            logger.warning('No files found to scan')
            return
        logger.info(f'Scanning {len(files)} files for API keys and secrets')
        for path in files:
            self.files_scanned += 1
            findings = self.scan_file(path)
            if findings:
                self.findings[str(path)] = findings
                self.total_hits += sum(len(matches) for matches in findings.values())

    def get_summary(self) -> Dict[str, int]:
        """Generate a summary of pattern hits by type."""
        summary = {}
        for file_findings in self.findings.values():
            for label, matches in file_findings.items():
                summary[label] = summary.get(label, 0) + len(matches)
        return summary

    def print_report(self):
        """Print the aggregated scan results."""
        print('\n' + '='*90)
        print('APIKeyHunter - Secret Discovery Report')
        print('='*90)
        print(f'Files scanned: {self.files_scanned}')
        print(f'Total exposures found: {self.total_hits}')
        print('')
        summary = self.get_summary()
        for label, total in sorted(summary.items(), key=lambda x: x[1], reverse=True):
            print(f'  {label}: {total}')

        for path, findings in self.findings.items():
            print(f'\n[FILE] {path}')
            for label, items in sorted(findings.items(), key=lambda x: x[0]):
                print(f'  {label.upper()} ({len(items)})')
                for lineno, line, match in items[:5]:
                    shortened = line if len(line) < 80 else line[:77] + '...'
                    print(f'    {lineno}: {shortened}')
                if len(items) > 5:
                    print(f'    ...and {len(items) - 5} more matches')
        print('\n' + '='*90 + '\n')

    def export_json(self, output_file: str):
        """Export findings as structured JSON."""
        import json
        payload = {
            'files_scanned': self.files_scanned,
            'total_hits': self.total_hits,
            'summary': self.get_summary(),
            'findings': self.findings,
        }
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Exported findings to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def calculate_entropy(self, candidate: str) -> float:
        """Estimate the entropy of a candidate secret string."""
        counts = {}
        for ch in candidate:
            counts[ch] = counts.get(ch, 0) + 1
        entropy = 0.0
        length = len(candidate)
        for count in counts.values():
            p = count / length
            entropy -= p * (0 if p == 0 else math.log2(p))
        return entropy

    def classify_findings(self) -> Dict[str, int]:
        """Summarize findings by label category."""
        summary = {}
        for findings in self.findings.values():
            for label, items in findings.items():
                summary[label] = summary.get(label, 0) + len(items)
        return summary

    def export_csv(self, output_file: str):
        """Export scan results to CSV."""
        import csv
        try:
            with open(output_file, 'w', encoding='utf-8', newline='') as fh:
                writer = csv.writer(fh)
                writer.writerow(['file', 'type', 'line', 'match', 'snippet'])
                for path, findings in self.findings.items():
                    for label, items in findings.items():
                        for lineno, line, match in items:
                            snippet = line if len(line) < 120 else line[:117] + '...'
                            writer.writerow([path, label, lineno, match, snippet])
            logger.info(f'CSV export written to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to export CSV: {exc}')

    def export_plaintext(self, output_file: str):
        """Export findings to a plain text report."""
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                fh.write('APIKeyHunter Report\n')
                fh.write('='*90 + '\n')
                fh.write(f'Files scanned: {self.files_scanned}\n')
                fh.write(f'Total hits: {self.total_hits}\n\n')
                for path, findings in self.findings.items():
                    fh.write(f'FILE: {path}\n')
                    for label, items in findings.items():
                        fh.write(f'  {label.upper()} ({len(items)})\n')
                        for lineno, line, match in items:
                            line_display = line if len(line) <= 120 else line[:117] + '...'
                            fh.write(f'    {lineno}: {line_display}\n')
                    fh.write('\n')
            logger.info(f'Plain text report written to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to write plaintext report: {exc}')

    def export_html(self, output_file: str):
        """Export findings to HTML."""
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                fh.write('<html><body>\n')
                fh.write('<h1>APIKeyHunter Report</h1>\n')
                fh.write(f'<p>Files scanned: {self.files_scanned}</p>\n')
                fh.write(f'<p>Total hits: {self.total_hits}</p>\n')
                fh.write('<ul>\n')
                for path, findings in self.findings.items():
                    fh.write(f'<li>{path}<ul>\n')
                    for label, items in findings.items():
                        fh.write(f'<li>{label.upper()} ({len(items)})<ul>\n')
                        for lineno, line, match in items[:10]:
                            snippet = line if len(line) <= 120 else line[:117] + '...'
                            fh.write(f'<li>{lineno}: {snippet}</li>\n')
                        fh.write('</ul></li>\n')
                    fh.write('</ul></li>\n')
                fh.write('</ul>\n')
                fh.write('</body></html>\n')
            logger.info(f'HTML report written to {output_file}')
        except Exception as exc:
            logger.error(f'Failed to write HTML report: {exc}')

    def risk_profile(self) -> Dict[str, int]:
        """Return a risk summary for discovered credentials."""
        summary = self.get_summary()
        return {key: min(val, 100) for key, val in summary.items()}


def main():
    parser = argparse.ArgumentParser(
        description='APIKeyHunter - API key discovery and secret scanning utility',
        epilog='Examples:\n'
               '  python apikeyhunter.py . -r\n'
               '  python apikeyhunter.py /project --json results.json\n'
               '  python apikeyhunter.py secrets.txt',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('paths', nargs='+', help='File or directory paths to scan')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan directories')
    parser.add_argument('--json', help='Export results to JSON file')
    parser.add_argument('--text', help='Export results to plain text file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    hunter = APIKeyHunter(args.paths, recursive=args.recursive)
    try:
        hunter.scan_all()
        hunter.print_report()
        if args.json:
            hunter.export_json(args.json)
        if args.text:
            hunter.export_plaintext(args.text)
    except KeyboardInterrupt:
        logger.warning('Scan interrupted by user')
        sys.exit(1)
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
