
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DOOM-SEC | VoidScythe | NetWraith
Author: CyberOps
Version: 3.0.0
"""

import socket
import threading
import sys
import queue
import argparse
import time
import os
import json
import random
from datetime import datetime

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

VERSION = "3.0.0"
TOOL_NAME = "NetWraith"

# Common ports dictionary for smarter reporting
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt"
}

# ==============================================================================
# LOGGING FRAMEWORK
# ==============================================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'

class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, msg):
        print(f"{Colors.BLUE}[*]{Colors.ENDC} {msg}")

    def success(self, msg):
        print(f"{Colors.GREEN}[+]{Colors.ENDC} {msg}")

    def error(self, msg):
        print(f"{Colors.FAIL}[-]{Colors.ENDC} {msg}")

    def warning(self, msg):
        print(f"{Colors.WARNING}[!]{Colors.ENDC} {msg}")
    
    def section(self, msg):
        print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== {msg} ==={Colors.ENDC}")

# ==============================================================================
# CORE TOOL LOGIC
# ==============================================================================

class NetWraith:
    def __init__(self, target, ports, threads=50, timeout=1.0, output=None, verbose=False):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        
        self.queue = queue.Queue()
        self.results = []
        self.lock = threading.Lock()
        self.logger = Logger(verbose)
        
        # Determine if target is a hostname or IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.logger.error(f"Could not resolve hostname: {target}")
            sys.exit(1)

    def print_banner(self):
        banner = f"""{Colors.HEADER}
        ███╗   ██╗███████╗████████╗██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
        ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
        ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
        ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
        ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
        ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
        {Colors.ENDC}{Colors.BOLD}
        [ VoidScythe: NetWraith v{VERSION} ]
        [ Multi-Threaded Port Scanner & Service Detector ]
        {Colors.ENDC}"""
        print(banner)

    def grab_banner(self, port, sock):
        """
        Attempts to grab a banner from the open socket.
        """
        try:
            # Send specific probes based on port
            if port == 80 or port == 8080 or port == 443:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            else:
                # Generic trigger
                sock.send(b'Hello\r\n')
                
            banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner_data
        except:
            return None

    def scan_port(self, port):
        """
        Scans a single port and handles banner grabbing.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            
            # Connect
            result = s.connect_ex((self.target_ip, port))
            
            if result == 0:
                service_known = COMMON_PORTS.get(port, "Unknown")
                
                # Banner Grabbing attempt
                banner = self.grab_banner(port, s)
                
                with self.lock:
                    service_display = f"{Colors.BOLD}{service_known}{Colors.ENDC}"
                    
                    if banner:
                        # Clean banner for display
                        clean_banner = banner.replace('\n', ' ').replace('\r', '')[:50]
                        print(f"{Colors.GREEN}[+] Port {port:<5} | OPEN | {service_display:<12} | {clean_banner}{Colors.ENDC}")
                        self.results.append({
                            "port": port,
                            "state": "open",
                            "service": service_known,
                            "banner": banner
                        })
                    else:
                        print(f"{Colors.GREEN}[+] Port {port:<5} | OPEN | {service_display:<12}{Colors.ENDC}")
                        self.results.append({
                            "port": port,
                            "state": "open",
                            "service": service_known,
                            "banner": None
                        })
            elif self.verbose:
                 # In very verbose mode, debug closed ports? Usually not needed.
                 pass
            
            s.close()
        except socket.error:
            pass
        except Exception as e:
            if self.verbose:
                 print(f"{Colors.FAIL}[!] Error on port {port}: {e}{Colors.ENDC}")

    def worker(self):
        """
        Thread worker function.
        """
        while True:
            try:
                port = self.queue.get(timeout=0.1)
                self.scan_port(port)
                self.queue.task_done()
            except queue.Empty:
                break

    def save_report(self):
        if not self.output:
            return

        self.logger.section("Generating Report")
        report_data = {
            "target": self.target,
            "ip": self.target_ip,
            "scan_time": str(datetime.now()),
            "open_ports": len(self.results),
            "results": self.results
        }
        
        try:
            with open(self.output, "w") as f:
                json.dump(report_data, f, indent=4)
            self.logger.success(f"Report saved to {self.output}")
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")

    def run(self):
        self.print_banner()
        self.logger.info(f"Target: {self.target} ({self.target_ip})")
        
        # Populate queue
        self.logger.info(f"Queueing {len(self.ports)} ports...")
        for port in self.ports:
            self.queue.put(port)
        
        self.logger.info(f"Moblizing {self.threads} threads for rapid scanning...")
        self.logger.section("Scan Results")
        
        start_time = time.time()
        
        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker)
            threads_list.append(t)
            t.start()
        
        for t in threads_list:
            t.join()
            
        duration = time.time() - start_time
        
        print("\n")
        self.logger.info(f"Scan completed in {duration:.2f} seconds.")
        self.logger.success(f"Found {len(self.results)} open ports.")
        
        self.save_report()

# ==============================================================================
# UTILITIES
# ==============================================================================

def parse_ports(port_arg):
    """
    Parses port arguments like "80", "1-1000", "80,443,8080".
    """
    ports = []
    try:
        if '-' in port_arg:
            parts = port_arg.split('-')
            start = int(parts[0])
            end = int(parts[1])
            if start < 1 or end > 65535:
                raise ValueError("Port range out of bounds.")
            return list(range(start, end + 1))
        elif ',' in port_arg:
            parts = port_arg.split(',')
            return [int(p) for p in parts]
        else:
            return [int(port_arg)]
    except Exception as e:
        print(f"{Colors.FAIL}[!] Invalid port format: {e}{Colors.ENDC}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description=f"NetWraith v{VERSION} | Advanced Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python NetWraith.py 192.168.1.1 -p 1-1000\n  python NetWraith.py google.com -p 80,443"
    )
    
    parser.add_argument("target", help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of concurrent threads (default: 100)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    ports = parse_ports(args.ports)
    
    try:
        scanner = NetWraith(
            target=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            output=args.output,
            verbose=args.verbose
        )
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user. Cleanup and exit.{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Critical Exception: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
