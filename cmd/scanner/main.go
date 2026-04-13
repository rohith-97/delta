package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

type ScanResult struct {
	Port    int
	Open    bool
	Service string
	Latency time.Duration
}

var commonServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	465:   "SMTPS",
	587:   "SMTP",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	9090:  "HTTP-Alt",
	9200:  "Elasticsearch",
	27017: "MongoDB",
}

func scan(host string, port int, timeout time.Duration, results chan<- ScanResult, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	start := time.Now()
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	latency := time.Since(start)

	if err != nil {
		results <- ScanResult{Port: port, Open: false}
		return
	}
	conn.Close()

	service := commonServices[port]
	if service == "" {
		service = "unknown"
	}

	results <- ScanResult{
		Port:    port,
		Open:    true,
		Service: service,
		Latency: latency,
	}
}

func main() {
	host := flag.String("host", "localhost", "target host")
	startPort := flag.Int("start", 1, "start port")
	endPort := flag.Int("end", 1024, "end port")
	concurrency := flag.Int("concurrency", 100, "concurrent scanners")
	timeout := flag.Duration("timeout", 1*time.Second, "connection timeout")
	flag.Parse()

	if *host == "" {
		fmt.Println("error: host is required")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("        DELTA PORT SCANNER")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Host        : %s\n", *host)
	fmt.Printf("  Port range  : %d-%d\n", *startPort, *endPort)
	fmt.Printf("  Concurrency : %d\n", *concurrency)
	fmt.Printf("  Timeout     : %v\n", *timeout)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	start := time.Now()

	total := *endPort - *startPort + 1
	results := make(chan ScanResult, total)
	sem := make(chan struct{}, *concurrency)

	var wg sync.WaitGroup
	for port := *startPort; port <= *endPort; port++ {
		wg.Add(1)
		go scan(*host, port, *timeout, results, &wg, sem)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []ScanResult
	for result := range results {
		if result.Open {
			open = append(open, result)
		}
	}

	sort.Slice(open, func(i, j int) bool {
		return open[i].Port < open[j].Port
	})

	elapsed := time.Since(start)

	fmt.Printf("\n  Scanned %d ports in %v\n\n", total, elapsed)

	if len(open) == 0 {
		fmt.Println("  No open ports found.")
	} else {
		fmt.Printf("  %-8s %-16s %s\n", "PORT", "SERVICE", "LATENCY")
		fmt.Println("  ────────────────────────────────")
		for _, r := range open {
			fmt.Printf("  %-8d %-16s %v\n", r.Port, r.Service, r.Latency)
		}
	}

	fmt.Println("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}
