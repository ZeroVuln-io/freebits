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
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/term"
)

// security advisory identifier (e.g. CVE etc)
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// dependabot alert
type Alert struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	URL    string `json:"html_url"`

	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
	} `json:"dependency"`

	SecurityAdvisory struct {
		Summary     string       `json:"summary"`
		Severity    string       `json:"severity"`
		Identifiers []Identifier `json:"identifiers"`
	} `json:"security_advisory"`
}

// http client with oauth
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// builds an HTTP client that injects the PAT
func gc(tok string) *http.Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: tok})
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: oauth2.NewClient(context.Background(), ts).Transport,
	}
}

// fetch dependabot alerts for owner/repo
func fa(cli httpClient, ow, rp string) ([]Alert, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/dependabot/alerts", ow, rp)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// handle disabled or rate‑limited repos
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		msg := string(body)
		switch {
		case strings.Contains(msg, "Dependabot alerts are disabled"):
			fmt.Fprintf(os.Stderr, "⚠️ %s/%s: alerts disabled\n", ow, rp)
		case strings.Contains(msg, "API rate limit exceeded"):
			fmt.Fprintf(os.Stderr, "⚠️ Rate limit exceeded for %s/%s\n", ow, rp)
		default:
			fmt.Fprintf(os.Stderr, "⚠️ %s/%s: %s\n", ow, rp, resp.Status)
		}
		return []Alert{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var list []Alert
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	return list, nil
}

// returns the first CVE identifier it finds
func ec(ids []Identifier) string {
	for _, id := range ids {
		if strings.EqualFold(id.Type, "CVE") {
			return id.Value
		}
	}
	return ""
}

// formats severity text
func ns(sv string) string {
	if sv == "" {
		return "Unspecified"
	}
	return strings.ToUpper(sv[:1]) + strings.ToLower(sv[1:])
}

// prints either JSON or human readable alerts
func oa(alerts []Alert, fmtType string) {
	if len(alerts) == 0 {
		return
	}
	if fmtType == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(alerts)
		return
	}
	for _, a := range alerts {
		cve := ec(a.SecurityAdvisory.Identifiers)
		fmt.Printf("Vulnerability Name: %s\n", a.SecurityAdvisory.Summary)
		fmt.Printf("Severity:           %s\n", ns(a.SecurityAdvisory.Severity))
		fmt.Printf("Package Affected:   %s\n", a.Dependency.Package.Name)
		if cve != "" {
			fmt.Printf("CVE:                %s\n", cve)
		}
		fmt.Printf("More Info:          %s\n\n", a.URL)
	}
}

// pt prompts for a PAT
func pt() string {
	fmt.Fprint(os.Stderr, "Enter GitHub PAT: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return strings.TrimSpace(string(b))
	}
	r := bufio.NewReader(os.Stdin)
	tok, _ := r.ReadString('\n')
	return strings.TrimSpace(tok)
}

func main() {
	repoArg := flag.String("repo", "", "Repository (owner/repo) or repo name")
	orgArg := flag.String("org", "", "Organization name (for org scan)")
	pkgArg := flag.String("pkg", "", "Filters for package names, comma‑separated")
	fmtArg := flag.String("format", "default", "Output format: default or json")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --repo owner/repo [--pkg pkg1,pkg2] [--format format]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "   or:  %s --org ORG [--pkg pkg1,pkg2] [--format format]\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Flags:")
		fmt.Fprintln(os.Stderr, "  --repo    Repository to scan (owner/repo or repo name)")
		fmt.Fprintln(os.Stderr, "  --org     Organization for org‑wide scan")
		fmt.Fprintln(os.Stderr, "  --pkg     Package filters, comma‑separated")
		fmt.Fprintln(os.Stderr, "  --format  Output format: default or json")
	}
	flag.Parse()

	if *repoArg == "" && *orgArg == "" {
		flag.Usage()
		os.Exit(1)
	}

	// build package filters
	var filters []string
	if *pkgArg != "" {
		for _, p := range strings.Split(*pkgArg, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				filters = append(filters, strings.ToLower(p))
			}
		}
	}

	// get token + client
	token := pt()
	client := gc(token)

	// org‑wide mode
	if *orgArg != "" && *repoArg == "" {
		page := 1
		for {
			url := fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&page=%d", *orgArg, page)
			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", "application/vnd.github+json")

			resp, err := client.Do(req)
			if err != nil {
				log.Fatalf("Error listing repos: %v", err)
			}
			defer resp.Body.Close()

			data, _ := io.ReadAll(resp.Body)
			var repos []struct {
				Name     string `json:"name"`
				Archived bool   `json:"archived"`
			}
			if err := json.Unmarshal(data, &repos); err != nil {
				log.Fatalf("Error parsing repos: %v", err)
			}
			if len(repos) == 0 {
				break
			}

			for _, r := range repos {
				if r.Archived {
					continue
				}
				fmt.Fprintf(os.Stderr, "🔍 %s/%s\n", *orgArg, r.Name)
				sp(client, token, *orgArg, r.Name, filters, *fmtArg)
			}

			link := resp.Header.Get("Link")
			if !strings.Contains(link, `rel="next"`) {
				break
			}
			page++
		}
		return
	}

	// single repo mode
	var owner, repo string
	parts := strings.SplitN(*repoArg, "/", 2)
	if len(parts) == 2 {
		owner, repo = parts[0], parts[1]
	} else if *orgArg != "" {
		owner, repo = *orgArg, parts[0]
	} else {
		fmt.Fprintln(os.Stderr, "❌ Invalid repo format; must be owner/repo or specify --org.")
		os.Exit(1)
	}
	sp(client, token, owner, repo, filters, *fmtArg)
}

// sp = scan + print for a single repo
func sp(cli httpClient, tok, owner, repo string, filters []string, fmtType string) {
	alerts, err := fa(cli, owner, repo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching %s/%s: %v\n", owner, repo, err)
		return
	}

	var matches []Alert
	for _, a := range alerts {
		if strings.EqualFold(a.State, "open") {
			if len(filters) == 0 {
				matches = append(matches, a)
			} else {
				for _, f := range filters {
					if strings.Contains(strings.ToLower(a.Dependency.Package.Name), f) {
						matches = append(matches, a)
						break
					}
				}
			}
		}
	}
	if len(matches) == 0 {
		fmt.Fprintf(os.Stderr, "⚠️ %s/%s: no matching open alerts\n", owner, repo)
		return
	}
	oa(matches, fmtType)
}
