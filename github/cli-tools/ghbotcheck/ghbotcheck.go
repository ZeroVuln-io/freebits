// Command: ghbotcheck
// Description: A CLI tool to interact with GitHub's Dependabot alerts.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

type Alert struct {
	Number   int    `json:"number"`
	State    string `json:"state"`
	URL      string `json:"html_url"`
	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		Summary     string `json:"summary"`
		Severity    string `json:"severity"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	} `json:"security_advisory"`
}

func getClient(token string) *http.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return oauth2.NewClient(context.Background(), ts)
}

func fetchAlerts(client *http.Client, owner, repo string) []Alert {
	fmt.Fprintf(os.Stderr, "Fetching alerts for %s/%s...\n", owner, repo)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/dependabot/alerts", owner, repo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error fetching alerts: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("Failed to fetch alerts: %v. Response: %s", resp.Status, body)
	}

	var alerts []Alert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		log.Fatalf("Error decoding alerts: %v", err)
	}
	return alerts
}

func extractCVE(identifiers []struct {
	Type string `json:"type"`
	Value string `json:"value"`
}) string {
	for _, id := range identifiers {
		if strings.EqualFold(id.Type, "CVE") {
			return id.Value
		}
	}
	return ""
}

func matches(alert Alert, match string, cveMatch string) bool {
	match = strings.ToLower(match)
	cveMatch = strings.ToLower(cveMatch)

	if match != "" && (strings.Contains(strings.ToLower(alert.Dependency.Package.Name), match) ||
		strings.Contains(strings.ToLower(alert.SecurityAdvisory.Summary), match)) {
		return true
	}

	if cveMatch != "" {
		for _, id := range alert.SecurityAdvisory.Identifiers {
			if strings.EqualFold(id.Type, "CVE") && strings.Contains(strings.ToLower(id.Value), cveMatch) {
				return true
			}
		}
	}

	return match == "" && cveMatch == ""
}

func normalizeSeverity(sev string) string {
	if sev == "" {
		return "Unspecified"
	}
	return strings.ToUpper(sev[:1]) + strings.ToLower(sev[1:])
}

func outputAlerts(alerts []Alert, group bool, filter string, match string, cve string, format string) {
	var filtered []Alert
	for _, a := range alerts {
		if strings.ToLower(a.State) != "open" {
			continue
		}
		if filter != "" && !strings.EqualFold(a.SecurityAdvisory.Severity, filter) {
			continue
		}
		if !matches(a, match, cve) {
			continue
		}
		filtered = append(filtered, a)
	}

	if len(filtered) == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(filtered)
		return
	}

	if !group {
		for _, a := range filtered {
			cve := extractCVE(a.SecurityAdvisory.Identifiers)
			fmt.Println("----------------------------------------")
			fmt.Printf("Severity:           %s\n", normalizeSeverity(a.SecurityAdvisory.Severity))
			fmt.Printf("Vulnerability Name: %s\n", a.SecurityAdvisory.Summary)
			fmt.Printf("Package Affected:   %s\n", a.Dependency.Package.Name)
			if cve != "" {
				fmt.Printf("CVE:                %s\n", cve)
			}
			fmt.Printf("More Info:          %s\n", a.URL)
		}
		return
	}

	severityBuckets := map[string][]Alert{}
	for _, alert := range filtered {
		sev := normalizeSeverity(alert.SecurityAdvisory.Severity)
		severityBuckets[sev] = append(severityBuckets[sev], alert)
	}

	levels := []string{"Critical", "High", "Moderate", "Low", "Unspecified"}
	fmt.Println("ghbotcheck 🚨 - Grouped GitHub Dependabot alerts\n")
	for _, level := range levels {
		alertsByLevel := severityBuckets[level]
		if len(alertsByLevel) == 0 {
			continue
		}
		fmt.Printf("\n==== %s Severity ====%s\n", level, strings.Repeat("=", 40-len(level)))
		for _, a := range alertsByLevel {
			cve := extractCVE(a.SecurityAdvisory.Identifiers)
			fmt.Println("----------------------------------------")
			fmt.Printf("Severity:           %s\n", normalizeSeverity(a.SecurityAdvisory.Severity))
			fmt.Printf("Vulnerability Name: %s\n", a.SecurityAdvisory.Summary)
			fmt.Printf("Package Affected:   %s\n", a.Dependency.Package.Name)
			if cve != "" {
				fmt.Printf("CVE:                %s\n", cve)
			}
			fmt.Printf("More Info:          %s\n", a.URL)
		}
	}
	fmt.Println("----------------------------------------")
}

func promptForToken() string {
	fmt.Fprint(os.Stderr, "Enter GitHub PAT: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		byteToken, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("Failed to read token securely: %v", err)
		}
		fmt.Println()
		return strings.TrimSpace(string(byteToken))
	} else {
		reader := bufio.NewReader(os.Stdin)
		token, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Failed to read token: %v", err)
		}
		return strings.TrimSpace(token)
	}
}

func main() {
	org := flag.String("org", "", "GitHub organization name")
	repo := flag.String("repo", "", "GitHub repository name")
	group := flag.Bool("group", false, "Group alerts by severity")
	severity := flag.String("severity", "", "Only show alerts matching this severity (e.g. Critical)")
	match := flag.String("match", "", "Partial match in package or summary")
	cve := flag.String("cve", "", "Partial match for CVE IDs")
	format := flag.String("format", "default", "Output format: default or json")
	flag.Parse()

	token := promptForToken()
	client := getClient(token)

	if *org == "" && *repo == "" {
		log.Fatal("You must specify either --org or --repo")
	}

	if *repo != "" && *org != "" {
		alerts := fetchAlerts(client, *org, *repo)
		outputAlerts(alerts, *group, *severity, *match, *cve, *format)
		return
	}

	if *org != "" {
		url := fmt.Sprintf("https://api.github.com/orgs/%s/repos", *org)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("Failed to list org repos: %v", err)
		}
		defer resp.Body.Close()

		var repos []struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&repos); err != nil {
			log.Fatalf("Failed to decode repos list: %v", err)
		}

		var allAlerts []Alert
		for _, r := range repos {
			alerts := fetchAlerts(client, *org, r.Name)
			allAlerts = append(allAlerts, alerts...)
		}
		outputAlerts(allAlerts, *group, *severity, *match, *cve, *format)
	}
}
