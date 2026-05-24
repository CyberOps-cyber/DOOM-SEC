#!/usr/bin/env python3
"""
MIMTunnel - Man-in-the-Middle Tunnel Simulator and Traffic Analysis Foundation
Establishes a simple TCP proxy with connection tracking and request inspection hooks.
"""

import argparse
import logging
import socket
import sys
import threading
from typing import Tuple, Dict, Optional
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger(__name__)

class MIMTunnel:
    """Man-in-the-middle tunnel engine with connection logging and payload capture."""
    def __init__(self, listen_host: str, listen_port: int, target_host: str, target_port: int, backlog: int = 50):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.backlog = backlog
        self.active_connections: Dict[Tuple[str, int], Dict[str, float]] = {}
        self.server_socket: Optional[socket.socket] = None
        self._stop_event = threading.Event()

    def start(self):
        """Start the proxy listener."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.listen_host, self.listen_port))
        self.server_socket.listen(self.backlog)
        logger.info(f'Proxy listening on {self.listen_host}:{self.listen_port}, forwarding to {self.target_host}:{self.target_port}')

        try:
            while not self._stop_event.is_set():
                client_sock, client_addr = self.server_socket.accept()
                logger.info(f'Accepted connection from {client_addr[0]}:{client_addr[1]}')
                handler = threading.Thread(target=self.handle_connection, args=(client_sock, client_addr), daemon=True)
                handler.start()
        except KeyboardInterrupt:
            logger.info('Stopping proxy due to keyboard interrupt')
        finally:
            self.stop()

    def stop(self):
        """Stop the proxy and close sockets."""
        self._stop_event.set()
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
        logger.info('Proxy shut down')

    def handle_connection(self, client_sock: socket.socket, client_addr: Tuple[str, int]):
        """Proxy a client connection to the target host."""
        connection_id = client_addr
        self.active_connections[connection_id] = {'start_time': time.time(), 'bytes_in': 0, 'bytes_out': 0}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
                server_sock.settimeout(10)
                server_sock.connect((self.target_host, self.target_port))
                logger.debug(f'Connected to upstream {self.target_host}:{self.target_port}')
                
                client_to_server = threading.Thread(target=self.relay, args=(client_sock, server_sock, connection_id, True), daemon=True)
                server_to_client = threading.Thread(target=self.relay, args=(server_sock, client_sock, connection_id, False), daemon=True)
                client_to_server.start()
                server_to_client.start()
                client_to_server.join()
                server_to_client.join()
        except Exception as exc:
            logger.error(f'Connection proxy error: {exc}')
        finally:
            client_sock.close()
            if connection_id in self.active_connections:
                self.active_connections[connection_id]['end_time'] = time.time()
                logger.info(f'Closed connection {client_addr[0]}:{client_addr[1]}')
                del self.active_connections[connection_id]

    def inspect_payload(self, data: bytes, inbound: bool):
        """Inspect the traffic payload for keywords or interesting headers."""
        try:
            text = data.decode('utf-8', errors='ignore')
            direction = 'INBOUND' if inbound else 'OUTBOUND'
            if 'Authorization:' in text or 'Set-Cookie:' in text:
                logger.info(f'[{direction}] Sensitive header observed')
                for line in text.splitlines():
                    if 'Authorization:' in line or 'Set-Cookie:' in line:
                        logger.info(f'  {line.strip()}')
        except Exception:
            pass

    def list_connections(self):
        """Return a summary of active proxy connections."""
        lines = []
        for (host, port), info in self.active_connections.items():
            duration = time.time() - info['start_time']
            lines.append(f'{host}:{port} - {duration:.1f}s in={info["bytes_in"]} out={info["bytes_out"]}')
        return lines

    def get_connection_summary(self) -> Dict[str, int]:
        """Return a summary of connection metrics."""
        summary = {'active_connections': len(self.active_connections), 'total_bytes_in': 0, 'total_bytes_out': 0}
        for info in self.active_connections.values():
            summary['total_bytes_in'] += info.get('bytes_in', 0)
            summary['total_bytes_out'] += info.get('bytes_out', 0)
        return summary

    def export_json(self, filename: str):
        """Export active connection summary to a JSON file."""
        import json
        payload = {
            'listen_host': self.listen_host,
            'listen_port': self.listen_port,
            'target_host': self.target_host,
            'target_port': self.target_port,
            'connections': self.active_connections,
            'summary': self.get_connection_summary()
        }
        try:
            with open(filename, 'w', encoding='utf-8') as fh:
                json.dump(payload, fh, indent=2)
            logger.info(f'Connection summary exported to {filename}')
        except Exception as exc:
            logger.error(f'Failed to export JSON: {exc}')

    def capture_payload_summary(self, payload: bytes) -> Dict[str, int]:
        """Analyze payload size and control characters for interesting content."""
        return {
            'length': len(payload),
            'line_breaks': payload.count(b'\n'),
            'null_bytes': payload.count(b'\x00'),
            'keywords': sum(1 for token in [b'Authorization', b'Set-Cookie', b'Bearer'] if token in payload)
        }

    def log_traffic(self, direction: str, data: bytes):
        """Log and inspect traffic details for each relay event."""
        summary = self.capture_payload_summary(data)
        logger.debug(f'[{direction}] {summary["length"]} bytes, keywords={summary["keywords"]}')

    def relay(self, source: socket.socket, destination: socket.socket, connection_id: Tuple[str, int], inbound: bool):
        """Relay traffic between source and destination sockets."""
        direction = 'client->server' if inbound else 'server->client'
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)
                if connection_id in self.active_connections:
                    if inbound:
                        self.active_connections[connection_id]['bytes_in'] += len(data)
                    else:
                        self.active_connections[connection_id]['bytes_out'] += len(data)
                logger.debug(f'{direction}: {len(data)} bytes')
                self.inspect_payload(data, inbound)
                self.log_traffic(direction, data)
        except Exception as exc:
            logger.debug(f'Relay stopped: {exc}')

    def pretty_print_connections(self):
        """Print formatted connection details and metrics."""
        print('\n' + '='*90)
        print('MIMTunnel - Detailed Connection Metrics')
        print('='*90)
        for conn_id, details in self.active_connections.items():
            print(f'{conn_id[0]}:{conn_id[1]} started={details["start_time"]:.2f} in={details["bytes_in"]} out={details["bytes_out"]}')
        print('='*90 + '\n')

    def print_summary(self):
        """Print a summary of current active connections."""
        summary = self.get_connection_summary()
        print('\n' + '='*90)
        print('MIMTunnel - Connection Summary')
        print('='*90)
        if not self.active_connections:
            print('No active connections')
        else:
            for entry in self.list_connections():
                print(f'  {entry}')
        print(f"Total active connections: {summary['active_connections']}")
        print(f"Total bytes in: {summary['total_bytes_in']}")
        print(f"Total bytes out: {summary['total_bytes_out']}")
        print('='*90 + '\n')


def main():
    parser = argparse.ArgumentParser(
        description='MIMTunnel - MITM tunnel and traffic inspection utility',
        epilog='Examples:\n'
               '  python mimtunnel.py --listen-host 0.0.0.0 --listen-port 8080 --target host.local --target-port 80\n'
               '  python mimtunnel.py --listen-port 9000 --target 10.0.0.5 --target-port 22',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--listen-host', default='0.0.0.0', help='Local address to bind the proxy')
    parser.add_argument('--listen-port', type=int, default=8080, help='Local proxy port')
    parser.add_argument('--target-host', required=True, help='Remote target host')
    parser.add_argument('--target-port', type=int, required=True, help='Remote target port')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tunnel = MIMTunnel(args.listen_host, args.listen_port, args.target_host, args.target_port)
    try:
        tunnel.start()
    except KeyboardInterrupt:
        logger.info('Keyboard interrupt received, shutting down proxy')
        tunnel.stop()
    except Exception as exc:
        logger.error(f'Fatal error: {exc}')
        sys.exit(1)

if __name__ == '__main__':
    main()
