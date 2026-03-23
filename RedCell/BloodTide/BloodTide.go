package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BloodTide - Internal Network Sweeper
// Capabilities: Ping Sweep (ICMP logic simulated via TCP connect or actual Ping if privileged), Port Scan

func main() {
	target := flag.String("target", "", "Target IP or Subnet (e.g., 192.168.1.1)")
	ports := flag.String("ports", "21,22,80,443,445,3389", "Comma-separated ports")
	flag.Parse()

	if *target == "" {
		fmt.Println("BloodTide - High Speed Network Sweeper")
		fmt.Println("Usage: BloodTide.exe --target 192.168.1.10 --ports 22,80,445")
		return
	}

	portList := strings.Split(*ports, ",")
	fmt.Printf("[*] Starting sweep on %s for ports %s...\n", *target, *ports)

	var wg sync.WaitGroup

	for _, portStr := range portList {
		port, _ := strconv.Atoi(portStr)
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			scanPort(*target, p)
		}(port)
	}

	wg.Wait()
	fmt.Println("[*] Sweep complete.")
}

func scanPort(ip string, port int) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 2000*time.Millisecond)
	if err == nil {
		fmt.Printf("[+] OPEN: %s\n", address)
		conn.Close()
	}
}
