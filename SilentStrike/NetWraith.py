
import socket
import threading
import sys
import queue
from datetime import datetime

# NetWraith - Multi-threaded Port Scanner
# Part of DOOM-SEC SilentStrike Toolkit

target_ip = ""
queue = queue.Queue()
open_ports = []

def banner():
    print("""
    ███╗   ██╗███████╗████████╗██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
    
    [ NetWraith v1.0 | Multi-threaded Port Scanner & Banner Grabber ]
    [ Part of DOOM-SEC | SilentStrike ]
    """)

def portscan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        res = s.connect_ex((target_ip, port))
        if res == 0:
            return True
        s.close()
    except:
        pass
    return False

def get_banner(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, port))
        try:
            banner = s.recv(1024).decode().strip()
            return banner
        except:
            return "No Banner"
    except:
        return "N/A"

def worker():
    while not queue.empty():
        port = queue.get()
        if portscan(port):
            try:
                # Grab banner if open
                service = socket.getservbyport(port)
                b = get_banner(port)
                print(f"[+] Port {port} is OPEN ({service}) | Banner: {b}")
                open_ports.append(port)
            except:
                print(f"[+] Port {port} is OPEN (Unknown)")
                open_ports.append(port)
        queue.task_done()

def main():
    global target_ip
    banner()
    
    if len(sys.argv) < 2:
        print("Usage: python NetWraith.py <Target IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    print(f"[*] Scanning Target: {target_ip}")
    print(f"[*] Scan started at: {datetime.now()}")
    print("-" * 50)
    
    # Standard 1000 ports or 1-1024 + commons
    ports = list(range(1, 1025)) + [3389, 8080, 8443, 8000, 5000, 27017, 6379]
    
    for port in ports:
        queue.put(port)
        
    thread_list = []
    
    # 50 Threads for speed
    for t in range(50):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)
        
    for thread in thread_list:
        thread.start()
        
    for thread in thread_list:
        thread.join()
        
    print("-" * 50)
    print(f"[*] Scan Complete. Found {len(open_ports)} open ports.")

if __name__ == "__main__":
    main()
