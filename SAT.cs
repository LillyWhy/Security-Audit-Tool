using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Linq;
using System.Text.Json;
using System.Net.Http.Headers;
using System.Security.Authentication;
using Microsoft.Data.Sqlite;

InitializeDatabase();

if (args.Length >= 2)
{
    string command = args[0].ToLower();
    string target = args[1];

    if (command == "--scan")
    {
        string cleanDomain = target.Replace("https://", "").Replace("http://", "").TrimEnd('/');
        Console.WriteLine($"Running automated educational scan for: {cleanDomain} (made by Lilly#Why - Ver. 0.1)");
        SecurityScanner scanner = new SecurityScanner();
        SecurityReport report = await scanner.ScanDomainAsync(cleanDomain);

        SaveReportToDatabase(report);
        CompareWithHistory(cleanDomain, report);
        PrintReport(report);

        string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync($"{report.DomainName}_report.json", json);
        GenerateHtmlReport(report);

        Console.WriteLine($"Reports exported to {report.DomainName}_report.json and {report.DomainName}_report.html");
        return;
    }
}

while (true)
{
    Console.Clear();
    Console.WriteLine("╔════════════════════════════════════════╗");
    Console.WriteLine("║         SAT - SECURITY SCANNER CLI     ║");
    Console.WriteLine("║         Ver. 0.1 | made by Lilly#Why   ║");
    Console.WriteLine("╠════════════════════════════ ═══════════╣");
    Console.WriteLine("╔═══════════════════════════════════════════════════════════════╗");
    Console.WriteLine("║  Disclaimer: For educational & authorized auditing only.     ║");
    Console.WriteLine("║  This is NOT a hacking tool. Use only on your own systems.   ║");
    Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
    Console.WriteLine("1. Scan single domain (Full Audit + Fuzzing + Crypto + DB + HTML)");
    Console.WriteLine("2. Scan multiple domains in parallel");
    Console.WriteLine("3. Lookup IP & ASN details");
    Console.WriteLine("4. Check DNS & Mail Security (SPF / DMARC)");
    Console.WriteLine("5. Check security.txt & robots.txt");
    Console.WriteLine("6. Subdomain Enumeration");
    Console.WriteLine("7. View Scan History & Trends (SQLite)");
    Console.WriteLine("8. Send Webhook Notification");
    Console.WriteLine("9. Legend / Glossary");
    Console.WriteLine("10. Exit");
    Console.Write("Select option: ");
    string? choice = Console.ReadLine();

    if (choice == "10")
    {
        Console.WriteLine("Exiting...");
        break;
    }

    if (choice == "1")
    {
        Console.Clear();
        Console.Write("Enter target domain: ");
        string? domainName = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(domainName))
        {
            string cleanDomain = domainName.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            SecurityScanner scanner = new SecurityScanner();
            SecurityReport result = await scanner.ScanDomainAsync(cleanDomain);

            SaveReportToDatabase(result);
            CompareWithHistory(cleanDomain, result);
            PrintReport(result);

            string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync($"{result.DomainName}_report.json", json);
            GenerateHtmlReport(result);

            Console.WriteLine($"Reports exported to: {result.DomainName}_report.json & {result.DomainName}_report.html");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "2")
    {
        Console.Clear();
        Console.Write("Enter domains (space or comma separated): ");
        string? input = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(input))
        {
            string[] domains = input.Split(new char[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            Console.WriteLine($"\nScanning {domains.Length} target(s) in parallel...\n");

            ConcurrentBag<SecurityReport> allResults = new ConcurrentBag<SecurityReport>();
            List<Task> tasks = new List<Task>();

            foreach (string d in domains)
            {
                string cleanDomain = d.Trim().Replace("https://", "").Replace("http://", "").TrimEnd('/');
                if (!string.IsNullOrWhiteSpace(cleanDomain))
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        SecurityScanner scanner = new SecurityScanner();
                        SecurityReport result = await scanner.ScanDomainAsync(cleanDomain);
                        allResults.Add(result);

                        SaveReportToDatabase(result);
                        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
                        await File.WriteAllTextAsync($"{result.DomainName}_report.json", json);
                        GenerateHtmlReport(result);

                        lock (Console.Out)
                        {
                            PrintReport(result);
                        }
                    }));
                }
            }

            await Task.WhenAll(tasks);

            string batchJson = JsonSerializer.Serialize(allResults.ToList(), new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync("scan_summary.json", batchJson);

            Console.WriteLine("Batch scan completed. Results saved to DB and exported.");
        }
        else
        {
            Console.WriteLine("No input provided.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "3")
    {
        Console.Clear();
        Console.Write("Enter domains for IP/ASN lookup: ");
        string? input = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(input))
        {
            string[] domains = input.Split(new char[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
            Console.WriteLine("\nResolving IP and ASN details...\n");

            using HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(5);

            foreach (string d in domains)
            {
                string cleanDomain = d.Trim().Replace("https://", "").Replace("http://", "").TrimEnd('/');
                if (!string.IsNullOrWhiteSpace(cleanDomain))
                {
                    Console.WriteLine($"[TARGET] {cleanDomain}");
                    try
                    {
                        IPAddress[] addresses = Dns.GetHostAddresses(cleanDomain);
                        foreach (IPAddress addr in addresses)
                        {
                            try
                            {
                                string json = await client.GetStringAsync($"http://ip-api.com/json/{addr}");
                                using JsonDocument doc = JsonDocument.Parse(json);
                                JsonElement root = doc.RootElement;

                                string status = root.GetProperty("status").GetString() ?? string.Empty;
                                if (status == "success")
                                {
                                    string asn = root.GetProperty("as").GetString() ?? string.Empty;
                                    string org = root.GetProperty("org").GetString() ?? string.Empty;
                                    string country = root.GetProperty("country").GetString() ?? string.Empty;

                                    Console.WriteLine($"  -> IP: {addr}");
                                    Console.WriteLine($"     Country: {country}");
                                    Console.WriteLine($"     ASN: {asn}");
                                    Console.WriteLine($"     Organization: {org}");
                                }
                                else
                                {
                                    Console.WriteLine($"  -> IP: {addr} (ASN data unavailable)");
                                }
                            }
                            catch
                            {
                                Console.WriteLine($"  -> IP: {addr} (Failed to fetch ASN)");
                            }
                        }
                    }
                    catch (Exception)
                    {
                        Console.WriteLine($"  -> Failed to resolve IP addresses for {cleanDomain}");
                    }
                    Console.WriteLine();
                }
            }
        }
        else
        {
            Console.WriteLine("No input provided.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "4")
    {
        Console.Clear();
        Console.Write("Enter domain for DNS & Mail Security check (SPF/DMARC): ");
        string? domainInput = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            Console.WriteLine($"\nChecking DNS records for {cleanDomain}...\n");

            using HttpClient client = new HttpClient();
            client.Timeout = TimeSpan.FromSeconds(5);

            string spf = await SecurityScanner.GetTxtRecordAsync(client, cleanDomain);
            string dmarc = await SecurityScanner.GetTxtRecordAsync(client, $"_dmarc.{cleanDomain}");

            Console.WriteLine($"SPF Record: {(string.IsNullOrEmpty(spf) ? "Not found" : spf)}");
            Console.WriteLine($"DMARC Record: {(string.IsNullOrEmpty(dmarc) ? "Not found" : dmarc)}");
        }
        else
        {
            Console.WriteLine("No input provided.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "5")
    {
        Console.Clear();
        Console.Write("Enter domain to check security.txt & robots.txt: ");
        string? domainInput = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            Console.WriteLine($"\nChecking file presence for {cleanDomain}...\n");

            using HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };

            try
            {
                var secResp1 = await client.GetAsync($"https://{cleanDomain}/.well-known/security.txt");
                var secResp2 = await client.GetAsync($"https://{cleanDomain}/security.txt");
                bool hasSecurity = secResp1.IsSuccessStatusCode || secResp2.IsSuccessStatusCode;
                Console.WriteLine($"security.txt: {(hasSecurity ? "Found" : "Not found")}");
            }
            catch
            {
                Console.WriteLine("security.txt: Error checking file.");
            }

            try
            {
                var robResp = await client.GetAsync($"https://{cleanDomain}/robots.txt");
                Console.WriteLine($"robots.txt: {(robResp.IsSuccessStatusCode ? "Found" : "Not found")}");
            }
            catch
            {
                Console.WriteLine("robots.txt: Error checking file.");
            }
        }
        else
        {
            Console.WriteLine("No input provided.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "6")
    {
        Console.Clear();
        Console.Write("Enter domain for Subdomain Enumeration: ");
        string? domainInput = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            Console.WriteLine($"\nEnumerating subdomains for {cleanDomain}...\n");
            List<string> found = await SecurityScanner.EnumerateSubdomainsAsync(cleanDomain);
            if (found.Count > 0)
            {
                Console.WriteLine($"Discovered subdomains ({found.Count}):");
                foreach (string sub in found)
                {
                    Console.WriteLine($"  - {sub}");
                }
            }
            else
            {
                Console.WriteLine("No active subdomains found from the wordlist.");
            }
        }
        else
        {
            Console.WriteLine("No input provided.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "7")
    {
        Console.Clear();
        Console.Write("Enter domain name to view history (leave blank for all): ");
        string? domainInput = Console.ReadLine();
        DisplayScanHistory(domainInput?.Trim());
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "8")
    {
        Console.Clear();
        Console.Write("Enter Webhook URL (Discord/Slack/Teams): ");
        string? webhookUrl = Console.ReadLine();
        Console.Write("Enter message text: ");
        string? msgText = Console.ReadLine();

        if (!string.IsNullOrWhiteSpace(webhookUrl) && !string.IsNullOrWhiteSpace(msgText))
        {
            bool sent = await SendWebhookAsync(webhookUrl, msgText);
            Console.WriteLine(sent ? "Webhook notification sent successfully!" : "Failed to send webhook notification.");
        }
        else
        {
            Console.WriteLine("Invalid input provided.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "9")
    {
        Console.Clear();
        Console.WriteLine("Metrics Legend and Explanations:");
        Console.WriteLine();
        Console.WriteLine(" - SSL Valid: Indicates whether the SSL/TLS certificate is trusted and currently active.");
        Console.WriteLine(" - Crypto & Key Size: RSA key length and Signature Algorithm.");
        Console.WriteLine(" - TLS Versions: Supported cryptographic protocols.");
        Console.WriteLine(" - Expires In: Number of days remaining before certificate expiration.");
        Console.WriteLine(" - HTTP to HTTPS Redirect: Checks automatic secure redirection.");
        Console.WriteLine(" - HSTS: HTTP Strict Transport Security enforcing secure connections.");
        Console.WriteLine(" - X-Frame-Options: Defense header against clickjacking.");
        Console.WriteLine(" - CSP: Content-Security-Policy mitigating XSS.");
        Console.WriteLine(" - Sensitive Path Fuzzing: Scans for exposed files like .env, .git/config, backups.");
        Console.WriteLine(" - Banner Disclosures: Exposed server versions in headers.");
        Console.WriteLine(" - SPF / DMARC: Email authentication records.");
        Console.WriteLine(" - security.txt / robots.txt: Standard operational files.");
        Console.WriteLine(" - SQLite History: Historical trend tracking database.");
        Console.WriteLine();
        Console.WriteLine("Press any key to return to the menu...");
        Console.ReadKey();
    }
}

void InitializeDatabase()
{
    using var connection = new SqliteConnection("Data Source=security_scans.db");
    connection.Open();
    string commandText = @"
        CREATE TABLE IF NOT EXISTS Scans (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            DomainName TEXT,
            SecurityGrade INTEGER,
            ScanDate TEXT,
            ReportJson TEXT
        );";
    using var command = new SqliteCommand(commandText, connection);
    command.ExecuteNonQuery();
}

void SaveReportToDatabase(SecurityReport report)
{
    try
    {
        using var connection = new SqliteConnection("Data Source=security_scans.db");
        connection.Open();
        string json = JsonSerializer.Serialize(report);
        string query = "INSERT INTO Scans (DomainName, SecurityGrade, ScanDate, ReportJson) VALUES (@domain, @grade, @date, @json)";
        using var command = new SqliteCommand(query, connection);
        command.Parameters.AddWithValue("@domain", report.DomainName);
        command.Parameters.AddWithValue("@grade", report.SecurityGrade);
        command.Parameters.AddWithValue("@date", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
        command.Parameters.AddWithValue("@json", json);
        command.ExecuteNonQuery();
    }
    catch
    {
    }
}

void DisplayScanHistory(string? domainFilter)
{
    try
    {
        using var connection = new SqliteConnection("Data Source=security_scans.db");
        connection.Open();
        string query = string.IsNullOrEmpty(domainFilter)
            ? "SELECT DomainName, SecurityGrade, ScanDate FROM Scans ORDER BY Id DESC LIMIT 20"
            : "SELECT DomainName, SecurityGrade, ScanDate FROM Scans WHERE DomainName = @domain ORDER BY Id DESC LIMIT 20";

        using var command = new SqliteCommand(query, connection);
        if (!string.IsNullOrEmpty(domainFilter))
        {
            command.Parameters.AddWithValue("@domain", domainFilter);
        }

        using var reader = command.ExecuteReader();
        Console.WriteLine("\n--- Scan History & Trends ---");
        bool found = false;
        while (reader.Read())
        {
            found = true;
            Console.WriteLine($"[{reader["ScanDate"]}] Domain: {reader["DomainName"]} | Score: {reader["SecurityGrade"]}/100");
        }
        if (!found)
        {
            Console.WriteLine("No history records found.");
        }
        Console.WriteLine("-----------------------------");
    }
    catch
    {
        Console.WriteLine("Error reading database history.");
    }
}

void PrintReport(SecurityReport result)
{
    Console.WriteLine($"[REPORT] Domain: {result.DomainName}");
    Console.WriteLine($"  SSL Valid: {result.IsSslValid}");
    Console.WriteLine($"  RSA Key Size: {result.RsaKeySize} bits");
    Console.WriteLine($"  Signature Algorithm: {result.SignatureAlgorithm}");
    Console.WriteLine($"  TLS Protocols: {string.Join(", ", result.SupportedTlsVersions)}");
    Console.WriteLine($"  Expires In: {result.DaysToExpiration} days");
    Console.WriteLine($"  HTTP to HTTPS Redirect: {result.HasHttpToHttpsRedirect}");
    Console.WriteLine($"  HSTS: {result.HasHsts}");
    Console.WriteLine($"  X-Frame-Options: {result.HasXFrameOptions}");
    Console.WriteLine($"  CSP: {result.HasCsp}");
    Console.WriteLine($"  X-Content-Type-Options: {result.HasXContentTypeOptions}");
    Console.WriteLine($"  Disclosed Headers: {(result.DisclosedHeaders.Count > 0 ? string.Join(", ", result.DisclosedHeaders.Keys) : "None detected")}");
    Console.WriteLine($"  Exposed Sensitive Files: {(result.ExposedSensitiveFiles.Count > 0 ? string.Join(", ", result.ExposedSensitiveFiles) : "None detected")}");
    Console.WriteLine($"  SPF Record: {(string.IsNullOrEmpty(result.SpfRecord) ? "Not found" : "Configured")}");
    Console.WriteLine($"  DMARC Record: {(string.IsNullOrEmpty(result.DmarcRecord) ? "Not found" : "Configured")}");
    Console.WriteLine($"  security.txt: {result.HasSecurityTxt}");
    Console.WriteLine($"  robots.txt: {result.HasRobotsTxt}");
    Console.WriteLine($"  Discovered Subdomains: {result.DiscoveredSubdomains.Count}");
    Console.WriteLine($"  Open Ports: {(result.OpenPorts.Count > 0 ? string.Join(", ", result.OpenPorts) : "None detected")}");
    Console.WriteLine($"  Score: {result.SecurityGrade}/100");
    if (result.Recommendations.Count > 0)
    {
        Console.WriteLine("  Recommendations:");
        foreach (var rec in result.Recommendations)
        {
            Console.WriteLine($"    - {rec}");
        }
    }
    Console.WriteLine();
}

void CompareWithHistory(string domain, SecurityReport newReport)
{
    try
    {
        using var connection = new SqliteConnection("Data Source=security_scans.db");
        connection.Open();
        string query = "SELECT ReportJson FROM Scans WHERE DomainName = @domain ORDER BY Id DESC LIMIT 1 OFFSET 1";
        using var command = new SqliteCommand(query, connection);
        command.Parameters.AddWithValue("@domain", domain);
        var prevJson = command.ExecuteScalar() as string;

        if (!string.IsNullOrEmpty(prevJson))
        {
            SecurityReport? oldReport = JsonSerializer.Deserialize<SecurityReport>(prevJson);
            if (oldReport != null)
            {
                Console.WriteLine("\n--- Comparison with Previous DB Scan ---");
                if (newReport.SecurityGrade != oldReport.SecurityGrade)
                {
                    Console.WriteLine($"  Score changed: {oldReport.SecurityGrade} -> {newReport.SecurityGrade}");
                }
                else
                {
                    Console.WriteLine("  Score remained unchanged.");
                }
                if (newReport.IsSslValid != oldReport.IsSslValid)
                {
                    Console.WriteLine($"  SSL Status changed: Valid={oldReport.IsSslValid} -> Valid={newReport.IsSslValid}");
                }
                Console.WriteLine("------------------------------------------\n");
            }
        }
    }
    catch
    {
    }
}

async Task<bool> SendWebhookAsync(string url, string message)
{
    try
    {
        using HttpClient client = new HttpClient();
        var payload = new { content = message };
        string json = JsonSerializer.Serialize(payload);
        using StringContent content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        HttpResponseMessage response = await client.PostAsync(url, content);
        return response.IsSuccessStatusCode;
    }
    catch
    {
        return false;
    }
}

void GenerateHtmlReport(SecurityReport report)
{
    string scoreColor = report.SecurityGrade >= 80 ? "#28a745" : report.SecurityGrade >= 50 ? "#ffc107" : "#dc3545";
    string html = $@"<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Educational Security Audit - {report.DomainName} (by Lilly#Why)</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f4f7f6; margin: 0; padding: 20px; color: #333; }}
        .container {{ max-width: 800px; background: #fff; margin: auto; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #007bff; }}
        .score {{ font-size: 24px; font-weight: bold; color: {scoreColor}; background: #eef2f3; padding: 10px 20px; border-radius: 5px; display: inline-block; margin-bottom: 20px; }}
        ul {{ line-height: 1.6; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; color: #fff; font-size: 12px; }}
        .true {{ background: #28a745; }}
        .false {{ background: #dc3545; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #777; border-top: 1px solid #ddd; padding-top: 10px; }}
    </style>
</head>
<body>
    <div class='container'>
        <h1>Security Audit Report: {report.DomainName}</h1>
        <div class='score'>Security Score: {report.SecurityGrade} / 100</div>
        <h3>Key Metrics</h3>
        <ul>
            <li>SSL Valid: <span class='badge {report.IsSslValid}'>{report.IsSslValid}</span></li>
            <li>RSA Key Size: <b>{report.RsaKeySize} bits</b></li>
            <li>Signature Algorithm: <b>{report.SignatureAlgorithm}</b></li>
            <li>TLS Protocols: <b>{string.Join(", ", report.SupportedTlsVersions)}</b></li>
            <li>Days to Expiration: <b>{report.DaysToExpiration}</b></li>
            <li>HTTP to HTTPS Redirect: <span class='badge {report.HasHttpToHttpsRedirect}'>{report.HasHttpToHttpsRedirect}</span></li>
            <li>HSTS Header: <span class='badge {report.HasHsts}'>{report.HasHsts}</span></li>
            <li>X-Frame-Options: <span class='badge {report.HasXFrameOptions}'>{report.HasXFrameOptions}</span></li>
            <li>Content-Security-Policy (CSP): <span class='badge {report.HasCsp}'>{report.HasCsp}</span></li>
            <li>X-Content-Type-Options: <span class='badge {report.HasXContentTypeOptions}'>{report.HasXContentTypeOptions}</span></li>
            <li>Disclosed Banners: <b>{(report.DisclosedHeaders.Count > 0 ? string.Join(", ", report.DisclosedHeaders.Select(h => $"{h.Key}: {h.Value}")) : "None")}</b></li>
            <li>Exposed Sensitive Files: <b>{(report.ExposedSensitiveFiles.Count > 0 ? string.Join(", ", report.ExposedSensitiveFiles) : "None")}</b></li>
            <li>SPF Record: <b>{(string.IsNullOrEmpty(report.SpfRecord) ? "Not found" : "Configured")}</b></li>
            <li>DMARC Record: <b>{(string.IsNullOrEmpty(report.DmarcRecord) ? "Not found" : "Configured")}</b></li>
            <li>Security.txt: <span class='badge {report.HasSecurityTxt}'>{report.HasSecurityTxt}</span></li>
            <li>Robots.txt: <span class='badge {report.HasRobotsTxt}'>{report.HasRobotsTxt}</span></li>
        </ul>
        <h3>Discovered Subdomains</h3>
        <p>{(report.DiscoveredSubdomains.Count > 0 ? string.Join(", ", report.DiscoveredSubdomains) : "None detected")}</p>
        <h3>Open Ports</h3>
        <p>{(report.OpenPorts.Count > 0 ? string.Join(", ", report.OpenPorts) : "None detected")}</p>
        <h3>Recommendations</h3>
        <ul>
            {(report.Recommendations.Count > 0 ? string.Join("", report.Recommendations.Select(r => $"<li>{r}</li>")) : "<li>No specific recommendations. Good job!</li>")}
        </ul>
        <div class='footer'>
            Educational Tool Ver. 0.1 | made by Lilly#Why — Not a hacking tool. For learning & authorized labs only.
        </div>
    </div>
</body>
</html>";
    File.WriteAllText($"{report.DomainName}_report.html", html);
}

public class SecurityReport
{
    public string DomainName { get; set; } = string.Empty;
    public bool IsSslValid { get; set; }
    public int RsaKeySize { get; set; }
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public List<string> SupportedTlsVersions { get; set; } = new List<string>();
    public int DaysToExpiration { get; set; }
    public bool HasHttpToHttpsRedirect { get; set; }
    public int SecurityGrade { get; set; }
    public bool HasHsts { get; set; }
    public bool HasXFrameOptions { get; set; }
    public bool HasCsp { get; set; }
    public bool HasXContentTypeOptions { get; set; }
    public Dictionary<string, string> DisclosedHeaders { get; set; } = new Dictionary<string, string>();
    public List<string> ExposedSensitiveFiles { get; set; } = new List<string>();
    public string SpfRecord { get; set; } = string.Empty;
    public string DmarcRecord { get; set; } = string.Empty;
    public bool HasSecurityTxt { get; set; }
    public bool HasRobotsTxt { get; set; }
    public List<string> DiscoveredSubdomains { get; set; } = new List<string>();
    public List<int> OpenPorts { get; set; } = new List<int>();
    public List<string> Recommendations { get; set; } = new List<string>();
}

public class SecurityScanner
{
    public async Task<SecurityReport> ScanDomainAsync(string domain)
    {
        SecurityReport report = new SecurityReport();
        report.DomainName = domain;

        try
        {
            using TcpClient client = new TcpClient(domain, 443);
            using SslStream sslStream = new SslStream(client.GetStream(), false, (sender, cert, chain, errors) => true);

            sslStream.AuthenticateAsClient(domain);

            System.Security.Cryptography.X509Certificates.X509Certificate? remoteCert = sslStream.RemoteCertificate;
            if (remoteCert != null)
            {
                using X509Certificate2 certificate = new X509Certificate2(remoteCert);
                report.IsSslValid = certificate.Verify();
                report.DaysToExpiration = (certificate.NotAfter - DateTime.Now).Days;
                report.SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? "Unknown";

                var rsaKey = certificate.GetRSAPublicKey();
                if (rsaKey != null)
                {
                    report.RsaKeySize = rsaKey.KeySize;
                }
            }
            else
            {
                report.IsSslValid = false;
                report.DaysToExpiration = 0;
                report.Recommendations.Add("No SSL certificate was returned by the server.");
            }

            report.SupportedTlsVersions.Add(sslStream.SslProtocol.ToString());

            using HttpClient httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            HttpResponseMessage response = await httpClient.GetAsync($"https://{domain}");

            report.HasCsp = response.Headers.Contains("Content-Security-Policy");
            report.HasXContentTypeOptions = response.Headers.Contains("X-Content-Type-Options");
            report.HasHsts = response.Headers.Contains("Strict-Transport-Security");
            report.HasXFrameOptions = response.Headers.Contains("X-Frame-Options");

            if (response.Headers.TryGetValues("Server", out var serverValues))
            {
                string serverVal = serverValues.FirstOrDefault() ?? string.Empty;
                if (!string.IsNullOrEmpty(serverVal))
                {
                    report.DisclosedHeaders["Server"] = serverVal;
                }
            }
            if (response.Headers.TryGetValues("X-Powered-By", out var poweredValues))
            {
                string poweredVal = poweredValues.FirstOrDefault() ?? string.Empty;
                if (!string.IsNullOrEmpty(poweredVal))
                {
                    report.DisclosedHeaders["X-Powered-By"] = poweredVal;
                }
            }
        }
        catch (Exception)
        {
            report.IsSslValid = false;
            report.DaysToExpiration = 0;
            report.Recommendations.Add("Critical error connecting to domain or validating SSL certificate.");
        }

        try
        {
            using HttpClientHandler handler = new HttpClientHandler { AllowAutoRedirect = false };
            using HttpClient redirectClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4) };
            HttpResponseMessage httpResponse = await redirectClient.GetAsync($"http://{domain}");

            if ((int)httpResponse.StatusCode >= 300 && (int)httpResponse.StatusCode <= 399)
            {
                string location = httpResponse.Headers.Location != null ? httpResponse.Headers.Location.ToString() : "";
                report.HasHttpToHttpsRedirect = location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            report.HasHttpToHttpsRedirect = false;
        }

        try
        {
            using HttpClient dnsClient = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
            report.SpfRecord = await GetTxtRecordAsync(dnsClient, domain);
            report.DmarcRecord = await GetTxtRecordAsync(dnsClient, $"_dmarc.{domain}");
        }
        catch
        {
        }

        try
        {
            using HttpClient fileClient = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
            var sec1 = await fileClient.GetAsync($"https://{domain}/.well-known/security.txt");
            var sec2 = await fileClient.GetAsync($"https://{domain}/security.txt");
            report.HasSecurityTxt = sec1.IsSuccessStatusCode || sec2.IsSuccessStatusCode;

            var rob = await fileClient.GetAsync($"https://{domain}/robots.txt");
            report.HasRobotsTxt = rob.IsSuccessStatusCode;
        }
        catch
        {
        }

        try
        {
            using HttpClient fuzzClient = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            string[] sensitivePaths = { "/.env", "/.git/config", "/backup.zip", "/database.sql", "/config.json", "/wp-login.php" };
            foreach (string path in sensitivePaths)
            {
                try
                {
                    var fuzzResp = await fuzzClient.GetAsync($"https://{domain}{path}");
                    if (fuzzResp.IsSuccessStatusCode && (int)fuzzResp.StatusCode == 200)
                    {
                        report.ExposedSensitiveFiles.Add(path);
                    }
                }
                catch
                {
                }
            }
        }
        catch
        {
        }

        try
        {
            report.DiscoveredSubdomains = await EnumerateSubdomainsAsync(domain);
        }
        catch
        {
        }

        int[] commonPorts = { 80, 443, 22, 21, 3306 };
        foreach (int port in commonPorts)
        {
            try
            {
                using TcpClient portClient = new TcpClient();
                var connectTask = portClient.ConnectAsync(domain, port);
                if (await Task.WhenAny(connectTask, Task.Delay(800)) == connectTask && portClient.Connected)
                {
                    report.OpenPorts.Add(port);
                }
            }
            catch
            {
            }
        }

        int grade = 0;
        if (report.IsSslValid)
        {
            grade += 20;
        }
        else
        {
            report.Recommendations.Add("Fix or renew SSL certificate.");
        }

        if (report.RsaKeySize >= 2048)
        {
            grade += 5;
        }
        else if (report.IsSslValid)
        {
            report.Recommendations.Add("SSL certificate uses a weak RSA key size (< 2048 bits).");
        }

        if (report.DaysToExpiration > 30)
        {
            grade += 10;
        }
        else if (report.IsSslValid)
        {
            report.Recommendations.Add("SSL certificate expiring soon. Consider renewal.");
        }

        if (report.HasHttpToHttpsRedirect)
        {
            grade += 15;
        }
        else
        {
            report.Recommendations.Add("HTTP traffic does not automatically redirect to HTTPS.");
        }

        if (report.HasHsts)
        {
            grade += 15;
        }
        else
        {
            report.Recommendations.Add("Missing HSTS header (Strict-Transport-Security).");
        }

        if (report.HasXFrameOptions)
        {
            grade += 10;
        }
        else
        {
            report.Recommendations.Add("Missing X-Frame-Options header (clickjacking risk).");
        }

        if (report.HasCsp)
        {
            grade += 5;
        }
        else
        {
            report.Recommendations.Add("Implement Content-Security-Policy (CSP) to mitigate XSS.");
        }

        if (report.HasXContentTypeOptions)
        {
            grade += 5;
        }
        else
        {
            report.Recommendations.Add("Add X-Content-Type-Options: nosniff header.");
        }

        if (report.DisclosedHeaders.Count == 0)
        {
            grade += 5;
        }
        else
        {
            report.Recommendations.Add("Server reveals software version banners in headers.");
        }

        if (report.ExposedSensitiveFiles.Count == 0)
        {
            grade += 5;
        }
        else
        {
            report.Recommendations.Add("Critical sensitive files or paths exposed publicly.");
        }

        if (!string.IsNullOrEmpty(report.SpfRecord))
        {
            grade += 5;
        }
        else
        {
            report.Recommendations.Add("Missing SPF record to prevent email spoofing.");
        }

        if (!string.IsNullOrEmpty(report.DmarcRecord))
        {
            grade += 5;
        }
        else
        {
            report.Recommendations.Add("Missing DMARC record for email security verification.");
        }

        report.SecurityGrade = grade;

        return report;
    }

    public static async Task<string> GetTxtRecordAsync(HttpClient client, string queryDomain)
    {
        try
        {
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-json"));
            string response = await client.GetStringAsync($"https://cloudflare-dns.com/dns-query?name={queryDomain}&type=TXT");
            using JsonDocument doc = JsonDocument.Parse(response);
            if (doc.RootElement.TryGetProperty("Answer", out JsonElement answers))
            {
                foreach (JsonElement answer in answers.EnumerateArray())
                {
                    if (answer.TryGetProperty("data", out JsonElement data))
                    {
                        return data.GetString() ?? string.Empty;
                    }
                }
            }
        }
        catch
        {
        }
        return string.Empty;
    }

    public static async Task<List<string>> EnumerateSubdomainsAsync(string domain)
    {
        List<string> foundSubdomains = new List<string>();
        string[] wordlist = { "www", "api", "admin", "mail", "test", "dev", "shop", "portal", "vpn", "staging", "app", "blog", "cloud", "secure", "status", "support" };
        ConcurrentBag<string> bag = new ConcurrentBag<string>();
        List<Task> tasks = new List<Task>();

        foreach (string sub in wordlist)
        {
            tasks.Add(Task.Run(async () =>
            {
                string targetSub = $"{sub}.{domain}";
                try
                {
                    IPAddress[] addresses = await Dns.GetHostAddressesAsync(targetSub);
                    if (addresses.Length > 0)
                    {
                        bag.Add(targetSub);
                    }
                }
                catch
                {
                }
            }));
        }

        await Task.WhenAll(tasks);
        return bag.Distinct().OrderBy(s => s).ToList();
    }
}
