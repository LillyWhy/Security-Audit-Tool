# Security-Audit-Tool
An educational C# console tool for security auditing, SSL checks, and generating HTML reports. For learning purposes only.

# Security Scanner CLI

An educational console application built in C# designed to explore network reconnaissance, SSL/TLS certificate validation, security header analysis, and reporting automation. 

Disclaimer: This tool is created strictly for educational purposes, portfolio presentation, and authorized security auditing in personal lab environments. It is not intended for malicious use or unauthorized scanning.

## Project Overview

The goal of this project is to understand how automated security scanners work under the hood using native .NET capabilities without relying on heavy third-party security libraries. It combines HTTP networking, TCP socket manipulation, asynchronous programming, DNS queries over HTTPS, and lightweight data persistence using SQLite.

## Key Features

- SSL/TLS Deep Dive: Validates certificate chains, checks expiration time, extracts public key sizes (RSA), and inspects signature algorithms.
- Security Header Inspection: Evaluates responses for critical headers like Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, and X-Content-Type-Options.
- Recon and Enumeration: Performs basic subdomain enumeration using threaded wordlist matching and scans common open ports using asynchronous TCP sockets.
- Fuzzing and File Check: Looks for common exposed sensitive files (such as backup archives, configuration files, and git directories).
- Local History and Trends: Saves every audit report into a local SQLite database, allowing historical trend comparison between consecutive scans.
- Multi-Format Export: Automatically generates structured JSON files and human-readable HTML reports complete with score-based evaluations.

## Project Architecture and Tech Stack

- Language: C# (.NET)
- Networking: HttpClient, TcpClient, SslStream
- Database: SQLite via Microsoft.Data.Sqlite
- Concurrency: Task Parallel Library (TPL), ConcurrentBag
- Serialization and DNS: System.Text.Json, Cloudflare DNS-over-HTTPS API

## Getting Started

### Prerequisites

Ensure you have the .NET SDK installed on your machine. You can verify this by running:

```bash
dotnet --version
