package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// RegHunter - Registry Credential Scanner
// Uses standard library + OS commands to avoid external dependencies.

var sensitiveKeywords = []string{
	"password",
	"pass",
	"pwd",
	"secret",
	"key",
	"token",
	"auth",
}

func main() {
	if len(os.Args) < 2 {
		printBanner()
		return
	}

	arg := os.Args[1]
	if arg == "--scan" {
		fmt.Println("[*] Starting Registry Scan for sensitive terms...")
		scanRegistryInfo()
	} else {
		printBanner()
	}
}

func printBanner() {
	fmt.Println("RegHunter - Registry Sensitive Data Scanner")
	fmt.Println("Usage: go run RegHunter.go --scan")
}

func scanRegistryInfo() {
	// Common interesting locations
	paths := []string{
		"HKCU\\Software\\OpenSSH",
		"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions",
		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", // AutoAdminLogon
		"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\TrapConfiguration",
		"HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions",
	}

	for _, path := range paths {
		queryRegistry(path)
	}

	fmt.Println("[*] Scan complete.")
}

func queryRegistry(path string) {
	fmt.Printf("[-] Checking: %s\n", path)
	// Execute 'reg query' command
	cmd := exec.Command("reg", "query", path, "/s")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Only print error if verbose or just ignore 'ERROR: The system was unable to find...'
		return 
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(lowerLine, keyword) {
				fmt.Printf("[!] POTENTIAL HIT found in %s:\n    %s\n", path, strings.TrimSpace(line))
				break
			}
		}
		// Also check specific values like "DefaultPassword" regardless of line case
		if strings.Contains(lowerLine, "defaultpassword") || strings.Contains(lowerLine, "autoadminlogon") {
             // Already caught by keywords likely, but good to be sure
		}
	}
}
