#!/usr/bin/env python3
"""
CredSniffer - Advanced Credential and Secret Pattern Detection Utility
Scans files and directories for exposed credentials, API keys, tokens, and sensitive data
"""

import argparse
import os
import re
import sys
import logging
from typing import List, Dict, Tuple, Set
from pathlib import Path
import mimetypes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class CredSniffer:
    """Advanced credential and sensitive data detection engine."""
    
    PATTERNS = {
        'api_key': [
            r'api[_-]?key[\s:="\']([A-Za-z0-9_\-]{16,128})',
            r'apikey[\s:="\']([A-Za-z0-9_\-]{16,128})',
            r'api_token[\s:="\']([A-Za-z0-9_\-]{16,128})',
            r'API[_-]?KEY[\s:="\']([A-Za-z0-9_\-]{16,128})'
        ],
        'aws': [
            r'AKIA[0-9A-Z]{16}',
            r'aws_access_key_id[\s:="\']([A-Z0-9]{20})',
            r'aws_secret_access_key[\s:="\']([A-Za-z0-9/+=]{40})',
            r'aws[_-]?secret[\s:="\']([A-Za-z0-9/+=]{40})'
        ],
        'jwt': [
            r'eyJ[A-Za-z0-9_\-.]+\.eyJ[A-Za-z0-9_\-.]+\.[A-Za-z0-9_\-.]+'  
        ],
        'password': [
            r'password[\s:="\']([^\s"\n]{8,})',
            r'passwd[\s:="\']([^\s"\n]{8,})',
            r'pwd[\s:="\']([^\s"\n]{8,})',
            r'pass[\s:="\']([^\s"\n]{8,})'
        ],
        'private_key': [
            r'-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY',
            r'-----BEGIN PRIVATE KEY',
            r'-----BEGIN ENCRYPTED PRIVATE KEY',
            r'private[_-]?key[\s:="\']'
        ],
        'github_token': [
            r'gh[pousr]_[A-Za-z0-9_]{36,255}',
            r'github[_-]?token[\s:="\']([A-Za-z0-9_\-]{40,})',
            r'GITHUB[_-]?TOKEN[\s:="\']([A-Za-z0-9_\-]{40,})'
        ],
        'slack_token': [
            r'xox[baprs]-[A-Za-z0-9_\-]{10,}',
            r'slack[_-]?token[\s:="\']([A-Za-z0-9_\-]{40,})'
        ],
        'database': [
            r'(mongodb|mysql|postgres|mariadb):[//]*[^:]+:[^@]+@[^/]+',
            r'DB_PASSWORD[\s:="\']([^\s"\n]*)',
            r'database[_-]?password[\s:="\']([^\s"\n]*)',
            r'db[_-]?pass[\s:="\']([^\s"\n]*)'
        ],
        'bearer_token': [
            r'Bearer[\s]+([A-Za-z0-9_\-.]{20,})',
            r'bearer[\s:="\']([A-Za-z0-9_\-.]{20,})'
        ],
        'ssh_key': [
            r'ssh[_-]?key[\s:="\']',
            r'-----BEGIN OPENSSH PRIVATE KEY',
            r'ssh[_-]?private[_-]?key[\s:="\']'
        ],
        'encryption_key': [
            r'encryption[_-]?key[\s:="\']([A-Za-z0-9_\-]{16,})',
            r'secret[_-]?key[\s:="\']([A-Za-z0-9_\-]{16,})',
            r'SECRET[_-]?KEY[\s:="\']([A-Za-z0-9_\-]{16,})'
        ],
        'stripe_key': [
            r'sk_live_[A-Za-z0-9]{24}',
            r'pk_live_[A-Za-z0-9]{24}'
        ],
        'oauth': [
            r'oauth[_-]?token[\s:="\']([A-Za-z0-9_\-.]{20,})',
            r'access[_-]?token[\s:="\']([A-Za-z0-9_\-.]{20,})'
        ]
    }
    
    def __init__(self, paths: List[str], recursive: bool = False):
        self.paths = paths
        self.recursive = recursive
        self.findings = {}
        self.files_scanned = 0
        self.total_findings = 0
        self.skipped_files = 0
    
    def is_text_file(self, filepath: str) -> bool:
        """Check if file is likely text-based."""
        text_extensions = {'.txt', '.py', '.js', '.java', '.go', '.c', '.cpp', '.sh', '.env', '.conf', '.config', 
                          '.json', '.xml', '.yaml', '.yml', '.sql', '.html', '.php', '.pl', '.rb', '.log'}
        
        ext = Path(filepath).suffix.lower()
        if ext in text_extensions:
            return True
        
        mime_type, _ = mimetypes.guess_type(filepath)
        if mime_type and 'text' in mime_type:
            return True
        
        return False
    
    def get_files_to_scan(self) -> List[str]:
        """Get list of files to scan based on paths and recursion setting."""
        files = []
        
        for path in self.paths:
            path_obj = Path(path)
            
            if path_obj.is_file():
                files.append(str(path_obj))
            elif path_obj.is_dir():
                if self.recursive:
                    for f in path_obj.rglob('*'):
                        if f.is_file() and self.is_text_file(str(f)):
                            files.append(str(f))
                else:
                    for f in path_obj.glob('*'):
                        if f.is_file() and self.is_text_file(str(f)):
                            files.append(str(f))
        
        return files
    
    def scan_file(self, filepath: str) -> Dict[str, List[Tuple[int, str, str]]]:
        """Scan a file for credential patterns."""
        file_findings = {}
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for lineno, line in enumerate(f, start=1):
                    for pattern_type, patterns in self.PATTERNS.items():
                        for pattern in patterns:
                            try:
                                matches = re.finditer(pattern, line, re.IGNORECASE)
                                for match in matches:
                                    if pattern_type not in file_findings:
                                        file_findings[pattern_type] = []
                                    
                                    file_findings[pattern_type].append((
                                        lineno,
                                        line.strip(),
                                        match.group(0)
                                    ))
                            except re.error as exc:
                                logger.debug(f"Regex error in pattern {pattern}: {exc}")
        
        except (FileNotFoundError, IsADirectoryError):
            logger.debug(f"Could not read file: {filepath}")
            return {}
        
        except Exception as exc:
            logger.debug(f"Error scanning {filepath}: {exc}")
            return {}
        
        return file_findings
    
    def scan_all(self):
        """Scan all files in specified paths."""
        files = self.get_files_to_scan()
        
        if not files:
            logger.warning("No files found to scan")
            return
        
        logger.info(f"[+] Scanning {len(files)} files...")
        
        for filepath in files:
            self.files_scanned += 1
            findings = self.scan_file(filepath)
            
            if findings:
                self.findings[filepath] = findings
                self.total_findings += sum(len(v) for v in findings.values())
                logger.debug(f"Found {sum(len(v) for v in findings.values())} items in {filepath}")
    
    def print_results(self):
        """Print detailed scan results."""
        print("\n" + "="*90)
        print("CredSniffer - Credential Detection Results")
        print("="*90)
        print(f"\nFiles Scanned: {self.files_scanned}")
        print(f"Total Findings: {self.total_findings}\n")
        
        if not self.findings:
            print("[+] No credentials or sensitive data detected.")
            print("="*90 + "\n")
            return
        
        for filepath in sorted(self.findings.keys()):
            print(f"\n[*] {filepath}")
            print("-" * 90)
            
            for pattern_type, matches in sorted(self.findings[filepath].items()):
                print(f"\n  [{pattern_type.upper()}]")
                for lineno, line, match in matches[:5]:
                    line_display = line[:70] + "..." if len(line) > 70 else line
                    match_display = match[:50] + "..." if len(match) > 50 else match
                    print(f"    Line {lineno}: {line_display}")
                    print(f"      Match: {match_display}")
                
                if len(matches) > 5:
                    print(f"    ... and {len(matches) - 5} more matches")
        
        print("\n" + "="*90 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="CredSniffer - Advanced Credential and Secret Pattern Detection",
        epilog="Examples:\n"
               "  python credsniffer.py ./config.txt\n"
               "  python credsniffer.py /project -r\n"
               "  python credsniffer.py file1.py file2.py file3.py",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('paths', nargs='+', help='File or directory paths to scan')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan directories')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    sniffer = CredSniffer(args.paths, recursive=args.recursive)
    
    try:
        sniffer.scan_all()
        sniffer.print_results()
    
    def export_json(self, output_file: str):
        """Export findings to JSON format."""
        import json
        json_findings = {}
        for filepath, types in self.findings.items():
            json_findings[filepath] = {}
            for pattern_type, matches in types.items():
                json_findings[filepath][pattern_type] = [
                    {'line': lineno, 'context': line, 'match': match}
                    for lineno, line, match in matches
                ]
        
        try:
            with open(output_file, 'w') as f:
                json.dump(json_findings, f, indent=2)
            logger.info(f"[+] Results exported to {output_file}")
        except Exception as exc:
            logger.error(f"[!] Failed to export JSON: {exc}")
    
    def export_csv(self, output_file: str):
        """Export findings to CSV format."""
        import csv
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['File', 'Pattern Type', 'Line Number', 'Context', 'Match'])
                
                for filepath in sorted(self.findings.keys()):
                    for pattern_type, matches in self.findings[filepath].items():
                        for lineno, line, match in matches:
                            writer.writerow([filepath, pattern_type, lineno, line[:100], match[:100]])
            
            logger.info(f"[+] Results exported to {output_file}")
        except Exception as exc:
            logger.error(f"[!] Failed to export CSV: {exc}")
    
    def get_severity_rating(self) -> str:
        """Calculate overall severity based on findings."""
        if self.total_findings == 0:
            return "CLEAN"
        elif self.total_findings < 5:
            return "LOW"
        elif self.total_findings < 20:
            return "MEDIUM"
        elif self.total_findings < 50:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def get_pattern_summary(self) -> Dict[str, int]:
        """Get summary of findings by pattern type."""
        summary = {}
        for file_findings in self.findings.values():
            for pattern_type, matches in file_findings.items():
                if pattern_type not in summary:
                    summary[pattern_type] = 0
                summary[pattern_type] += len(matches)
        return summary
    
    def filter_by_pattern(self, pattern_type: str) -> Dict:
        """Filter findings by specific pattern type."""
        filtered = {}
        for filepath, types in self.findings.items():
            if pattern_type in types:
                if filepath not in filtered:
                    filtered[filepath] = {}
                filtered[filepath][pattern_type] = types[pattern_type]
        return filtered
    
    def filter_by_file(self, filename_pattern: str) -> Dict:
        """Filter findings by filename pattern."""
        filtered = {}
        for filepath, types in self.findings.items():
            if filename_pattern.lower() in filepath.lower():
                filtered[filepath] = types
        return filtered

    except KeyboardInterrupt:
        logger.warning("\n[!] Scan interrupted by user")
        sniffer.print_results()
        sys.exit(1)
    except Exception as exc:
        logger.error(f"[!] Fatal error: {exc}")
        sys.exit(1)

if __name__ == "__main__":
    main()
