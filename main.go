package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36"

// ---------------- Banner ----------------

func banner() {
	fmt.Println(`
  ____        _         _                       _      __  __
 / ___| _   _| |__   __| | ___  _ __ ___   __ _(_)_ __ \ \/ /
 \___ \| | | | '_ \ / _` + "`" + ` |/ _ \| '_ ` + "`" + ` _ \ / _` + "`" + ` | | '_ \ \  /
  ___) | |_| | |_) | (_| | (_) | | | | | | (_| | | | | |/  \
 |____/ \__,_|_.__/ \__,_|\___/|_| |_| |_|\__,_|_|_| |_/_/\_\

        🗲  Automated Subdomain Gathering Tool 🗲
          GitHub: GitHub.com/zapstiko/SubdomainX
             Developed By Abu Raihan Biswas
                       zapstiko
`)
}

// ---------------- HTTP Helper ----------------

func fetchURL(url string) string {
	client := &http.Client{Timeout: 20 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var body strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		body.WriteString(scanner.Text())
		body.WriteString("\n")
	}

	return body.String()
}

// ---------------- Regex Extractor ----------------

func extractSubdomains(content, domain string) []string {
	reg := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
	matches := reg.FindAllString(content, -1)

	unique := make(map[string]struct{})
	for _, m := range matches {
		unique[m] = struct{}{}
	}

	var results []string
	for k := range unique {
		results = append(results, k)
	}
	return results
}

// ---------------- Sources ----------------

func fromGoogle(domain string) []string {
	url := "https://www.google.com/search?q=site:" + domain
	return extractSubdomains(fetchURL(url), domain)
}

func fromBing(domain string) []string {
	url := "https://www.bing.com/search?q=site:" + domain
	return extractSubdomains(fetchURL(url), domain)
}

func fromYahoo(domain string) []string {
	url := "https://search.yahoo.com/search?p=site:" + domain
	return extractSubdomains(fetchURL(url), domain)
}

func fromCrtSh(domain string) []string {
	url := "https://crt.sh/?q=%25." + domain
	return extractSubdomains(fetchURL(url), domain)
}

// ThreatCrowd JSON API
func fromThreatCrowd(domain string) []string {
	url := "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + domain
	body := fetchURL(url)

	type TC struct {
		Subdomains []string `json:"subdomains"`
	}

	var data TC
	json.Unmarshal([]byte(body), &data)
	return data.Subdomains
}

// BufferOver PassiveDNS
func fromBufferOver(domain string) []string {
	url := "https://dns.bufferover.run/dns?q=." + domain
	body := fetchURL(url)

	type BO struct {
		FDNSA []string `json:"FDNS_A"`
	}

	var data BO
	json.Unmarshal([]byte(body), &data)

	var results []string
	for _, entry := range data.FDNSA {
		parts := strings.Split(entry, ",")
		if len(parts) == 2 {
			results = append(results, parts[1])
		}
	}
	return results
}

// ---------------- Main ----------------

func main() {
	banner()

	if len(os.Args) < 2 {
		fmt.Println("Usage: subdomainx <domain>")
		return
	}

	domain := os.Args[1]

	var wg sync.WaitGroup
	resultsChan := make(chan []string)

	sources := []func(string) []string{
		fromGoogle,
		fromBing,
		fromYahoo,
		fromCrtSh,
		fromThreatCrowd,
		fromBufferOver,
	}

	for _, source := range sources {
		wg.Add(1)
		go func(src func(string) []string) {
			defer wg.Done()
			resultsChan <- src(domain)
		}(source)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	unique := make(map[string]struct{})

	for res := range resultsChan {
		for _, sub := range res {
			unique[sub] = struct{}{}
		}
	}

	var final []string
	for k := range unique {
		final = append(final, k)
	}

	sort.Strings(final)

	if len(final) == 0 {
		fmt.Printf("No subdomains found for %s\n", domain)
		return
	}

	fmt.Printf("\nNumber of subdomains found for %s: %d\n\n", domain, len(final))
	for _, sub := range final {
		fmt.Println(sub)
	}
}
