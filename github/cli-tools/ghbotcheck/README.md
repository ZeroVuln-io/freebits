# ghbotcheck 🚨

`ghbotcheck` is a Go-based CLI that queries GitHub Dependabot alerts across individual repositories or entire organizations. It outputs either clean human-readable summaries or structured JSON, filtering out resolved alerts and surfacing only those that matter.

---

## ✅ Features

- 🔐 Secure, interactive PAT authentication  
- 📁 Organization‑wide or repo‑specific scanning  
- 🔍 Filter alerts by package name substring (`--pkg foo,bar`)  
- 📤 Output in either human‑readable or JSON format (`--format json`)  
- ❌ Only unresolved (`open`) alerts are shown  
- 🆔 CVE IDs are automatically extracted and displayed when present  

---

## 💻 Installation

```bash
git clone https://github.com/your-username/ghbotcheck.git
cd ghbotcheck
go build -o ghbotcheck ghbotcheck.go
```

> Requires Go 1.17 or higher

---

## 🔐 Authentication

You’ll be prompted at runtime to enter your GitHub Personal Access Token (PAT) securely.

**Required scope:** `security_events`

Even if you redirect output (e.g. `> output.json`), the prompt appears via `stderr` to prevent leaking to files.

---

## 🚀 Usage

### Scan an organization:
```bash
./ghbotcheck --org my-org
```

### Scan a specific repository:
```bash
./ghbotcheck --org my-org --repo my-repo
```

### Filter by severity:
```bash
./ghbotcheck --org my-org --severity Critical
```

### Match partial package name or summary:
```bash
./ghbotcheck --org my-org --pkg tj-actions
```

### Match by CVE ID:
```bash
./ghbotcheck --org my-org --cve 2025-30066
```

### Group results by severity:
```bash
./ghbotcheck --org my-org --group
```

### Output JSON:
```bash
./ghbotcheck --org my-org --pkg tj-actions --format json > tj-actions.json
```

---

## 🧪 Example Output

```
----------------------------------------
Severity:           High
Vulnerability Name: Remote code execution in foobar
Package Affected:   foobar
CVE:                CVE-2025-12345
More Info:          https://github.com/org/repo/security/dependabot/1
```

---

## ⚙️ Available Flags

| Flag         | Description                                                   |
|--------------|---------------------------------------------------------------|
| `--org`      | GitHub organization name                                      |
| `--repo`     | Repository name (must be used with `--org`)                   |
| `--group`    | Group alerts by severity level                                |
| `--severity` | Only show alerts with this severity (e.g. `Critical`)         |
| `--pkg`    | Partial keyword match in summary or package name              |
| `--cve`      | Partial CVE ID match                                          |
| `--format`   | Output format: `default` (pretty) or `json`                   |

---

## 🛡️ Security

- Only unresolved (`open`) alerts are shown.
- GitHub tokens are requested securely and never stored on disk.

---

## 📄 License

MIT — use, fork, extend. Just don’t hardcode your PAT.

---

For issues, contributions, or feature requests, open an issue or PR.
