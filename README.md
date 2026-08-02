# SAT - Security Audit Tool

**SAT (Security Audit Tool)** is a high-performance, asynchronous console application written in C# (.NET) designed for rapid security auditing of domains, SSL configurations, HTTP headers, open ports, DNS records, and subdomains.

## Features (v0.4)

* **Optimized Full Domain Audit:** Inspects SSL/TLS certificate validity, expiration days, RSA key size, and signature algorithms.
* **Security Headers Check:** Automatically detects missing security headers such as `HSTS`, `CSP`, `X-Frame-Options`, and `X-Content-Type-Options`.
* **HTTP to HTTPS Redirection Check:** Verifies if the target correctly forces secure connections.
* **Concurrent Port Scanning & Subdomain Enumeration:** Fast multi-threaded checks for common ports and subdomains using `ConcurrentBag` and `Parallel.ForEachAsync`.
* **DNS & Mail Security:** Validates SPF and DMARC records via TXT lookups.
* **File Compliance:** Checks for the presence of `security.txt` (in root and `.well-known`) and `robots.txt`.
* **IP & ASN Lookup:** Integrates with external IP intelligence APIs to retrieve hosting provider and geographical details.
* **Smart SQLite History & Deduplication:** Stores scan history locally, computes state hashes to prevent duplicate logs, and highlights changes between scans.
* **Multi-Format Reports:** Automatically exports professional reports in **JSON** and **HTML** formats alongside rich CLI output with **actionable remediation steps**.
* **Webhook Integration:** Send instant security alert notifications to Webhooks (Discord, Slack, etc.).

---
# About Program
 Interactive Menu Options

   *  Scan single domain: Runs a full optimized audit on a target.

   *  Scan multiple domains (Batch): High-speed parallelized concurrent scanning for multiple domains.

   *  Lookup IP & ASN details: Resolves domain IP and fetches network details.

   *  Check DNS & Mail Security: Verifies SPF and DMARC configurations.

   *  Check security.txt & robots.txt: Verifies standard compliance files.

   *  Fast Subdomain Enumeration: Discovers active subdomains concurrently.

   *  View Scan History & Unique Trends: Queries the local SQLite database for historical reports and changes.

   *  Send Webhook Notification: Sends custom notifications via webhook URL.

   *  Exit: Closes the application.

# Output Files

**For every scanned domain, the tool automatically generates:

   * ** {DomainName}_report.json - Structured raw audit data.

   * ** {DomainName}_report.html - Styled standalone web report.

   * ** security_scans.db - Local SQLite database tracking historical scans.
---
## System Requirements

* [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) or later.
* Required NuGet packages:
  * `Microsoft.Data.Sqlite`

## Testing Platform

* Macbook Pro 2018 15"
* Intel Core u7
* Radeon Pro 560x && Intel UHD 630
* RAM 16 GB 2400 MHz DDR4
* MacOS Sequoia 15.7.8

---
## License
* This tool is created for educational and authorized security auditing purposes only.
---

## Installation & Running

1. Clone the repository or download the source code.
2. Ensure you have .NET 8.0 installed.
3. Run the project from your terminal:

```bash
dotnet run
---



