package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
)

var payloads = []string{
	"https://evil.com",
	"//evil.com",
	"/\\evil.com",
	"%2F%2Fevil.com",
}

func testRedirect(target string) {
	for _, p := range payloads {
		u := target + "?redirect=" + url.QueryEscape(p)
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		if loc != "" {
			fmt.Println("[+] Redirect found:", loc)
		}
	}
}

func main() {
	target := flag.String("u", "", "Target URL")
	flag.Parse()

	if *target == "" {
		fmt.Println("Usage: ./redirector -u https://target.com/login")
		return
	}

	testRedirect(*target)
}
