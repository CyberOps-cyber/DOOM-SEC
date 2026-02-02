package main

import (
	"fmt"
	"time"
	// In a real weaponized tool, we'd use 'gopacket' and 'pcap'.
	// For this PoC/Core-Only version, we simulate the logic or use raw sockets if possible.
	// Importing 'net' for standard operations.
)

// LanShark - Passive Credential Sniffer
// Educational PoC - Logic structure for promiscuous mode sniffing

func main() {
	fmt.Println("LanShark - Passive Network Sniffer")
	fmt.Println("[*] Warning: Requires Npcap/Libpcap installed on target.")
	fmt.Println("[*] Initializing capture on default interface...")

	// Simulation of capture loop
	// Real implementation requires CGo/libpcap binding which is complex for a single file drop.
	// We will demonstrate the parser logic.

	keywords := []string{"Authorization: Basic", "PASS ", "USER ", "password="}

	fmt.Println("[*] Sniffing for keywords: ", keywords)

	// Mock incoming packets
	mockPackets := []string{
		"GET / HTTP/1.1\r\nHost: example.com",
		"POST /login HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQxMjM=",
		"USER admin\r\n",
		"PASS secret123\r\n",
	}

	for _, pkt := range mockPackets {
		analyzePacket(pkt, keywords)
		time.Sleep(500 * time.Millisecond)
	}
}

func analyzePacket(payload string, terms []string) {
	for _, term := range terms {
		if contains(payload, term) {
			fmt.Printf("[!] CREDENTIAL CAPTURED:\n%s\n------------------\n", payload)
		}
	}
}

func contains(s, substr string) bool {
	// simple contains check
	return len(s) >= len(substr) && (s[0:len(substr)] == substr || len(s) > len(substr))
	// real implementation would use strings.Contains
}
