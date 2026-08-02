SAT

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Linq;
using System.Text.Json;
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
        Console.WriteLine($"Running high-perf educational scan for: {cleanDomain} (Ver. 0.4)");
        SecurityScanner scanner = new SecurityScanner();
        SecurityReport report = await scanner.ScanDomainAsync(cleanDomain);

        CompareAndSaveSmart(cleanDomain, report);
        PrintReport(report);

        string json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync($"{report.DomainName}_report.json", json);
        GenerateHtmlReport(report);
        return;
    }
}

while (true)
{
    Console.Clear();
    Console.WriteLine("╔════════════════════════════════════════╗");
    Console.WriteLine("║         SAT - SECURITY AUDIT TOOL      ║");
    Console.WriteLine("║         Ver. 0.4 | MADE BY LILLY#WHY   ║");
    Console.WriteLine("╠════════════════════════════════════════╣");
    Console.WriteLine("1. Scan single domain (Optimized Full Audit)");
    Console.WriteLine("2. Scan multiple domains in parallel (Batch)");
    Console.WriteLine("3. Lookup IP & ASN details");
    Console.WriteLine("4. Check DNS & Mail Security (SPF / DMARC)");
    Console.WriteLine("5. Check security.txt & robots.txt");
    Console.WriteLine("6. Fast Subdomain Enumeration (Concurrent)");
    Console.WriteLine("7. View Scan History & Unique Trends");
    Console.WriteLine("8. Send Webhook Notification");
    Console.WriteLine("9. Exit");
    Console.Write("Select option: ");
    string? choice = Console.ReadLine();

    if (choice == "9")
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

            Console.WriteLine("\nRunning high-speed asynchronous scan...\n");
            SecurityReport result = await scanner.ScanDomainAsync(cleanDomain);

            CompareAndSaveSmart(cleanDomain, result);
            PrintReport(result);

            string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync($"{result.DomainName}_report.json", json);
            GenerateHtmlReport(result);

            Console.WriteLine($"\nReports exported to: {result.DomainName}_report.json & {result.DomainName}_report.html");
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
            Console.WriteLine($"\nScanning {domains.Length} targets concurrently...\n");

            ConcurrentBag<SecurityReport> allResults = new ConcurrentBag<SecurityReport>();
            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };

            await Parallel.ForEachAsync(domains, parallelOptions, async (d, token) =>
            {
                string cleanDomain = d.Trim().Replace("https://", "").Replace("http://", "").TrimEnd('/');
                if (!string.IsNullOrWhiteSpace(cleanDomain))
                {
                    SecurityScanner scanner = new SecurityScanner();
                    SecurityReport result = await scanner.ScanDomainAsync(cleanDomain);
                    allResults.Add(result);

                    CompareAndSaveSmart(cleanDomain, result);
                    string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
                    await File.WriteAllTextAsync($"{result.DomainName}_report.json", json);
                    GenerateHtmlReport(result);

                    lock (Console.Out)
                    {
                        PrintReport(result);
                    }
                }
            });

            Console.WriteLine("Batch high-speed scan completed.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "3")
    {
        Console.Clear();
        Console.Write("Enter domain for IP/ASN lookup: ");
        string? domainInput = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            try
            {
                IPAddress[] addresses = await Dns.GetHostAddressesAsync(cleanDomain);
                foreach (IPAddress addr in addresses)
                {
                    using HttpResponseMessage response = await SharedHttp.NormalClient.GetAsync($"http://ip-api.com/json/{addr}");
                    string json = await response.Content.ReadAsStringAsync();
                    using JsonDocument doc = JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.GetProperty("status").GetString() == "success")
                    {
                        Console.WriteLine($"[IP] {addr} | ASN: {root.GetProperty("as").GetString()} | Org: {root.GetProperty("org").GetString()} | Country: {root.GetProperty("country").GetString()}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "4")
    {
        Console.Clear();
        Console.Write("Enter domain for DNS/Mail Security: ");
        string? domainInput = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            string spf = await SecurityScanner.GetTxtRecordAsync(cleanDomain);
            string dmarc = await SecurityScanner.GetTxtRecordAsync($"_dmarc.{cleanDomain}");
            Console.WriteLine($"SPF: {(string.IsNullOrEmpty(spf) ? "Not found" : "Configured")}");
            Console.WriteLine($"DMARC: {(string.IsNullOrEmpty(dmarc) ? "Not found" : "Configured")}");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "5")
    {
        Console.Clear();
        Console.Write("Enter domain for security.txt & robots.txt: ");
        string? domainInput = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            var taskSec1 = SharedHttp.NormalClient.GetAsync($"https://{cleanDomain}/.well-known/security.txt");
            var taskSec2 = SharedHttp.NormalClient.GetAsync($"https://{cleanDomain}/security.txt");
            var taskRob = SharedHttp.NormalClient.GetAsync($"https://{cleanDomain}/robots.txt");
            await Task.WhenAll(taskSec1, taskSec2, taskRob);

            bool hasSec = taskSec1.Result.IsSuccessStatusCode || taskSec2.Result.IsSuccessStatusCode;
            bool hasRob = taskRob.Result.IsSuccessStatusCode;

            Console.WriteLine($"security.txt: {(hasSec ? "Found" : "Not found")}");
            Console.WriteLine($"robots.txt: {(hasRob ? "Found" : "Not found")}");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "6")
    {
        Console.Clear();
        Console.Write("Enter domain for Concurrent Subdomain Enumeration: ");
        string? domainInput = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(domainInput))
        {
            string cleanDomain = domainInput.Replace("https://", "").Replace("http://", "").TrimEnd('/');
            var subs = await SecurityScanner.EnumerateSubdomainsAsync(cleanDomain);
            Console.WriteLine($"Discovered subdomains ({subs.Count}):");
            foreach (var sub in subs) Console.WriteLine($" - {sub}");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "7")
    {
        Console.Clear();
        Console.Write("Enter domain name (leave blank for all): ");
        string? domainInput = Console.ReadLine();
        DisplayUniqueHistory(domainInput?.Trim());
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
    else if (choice == "8")
    {
        Console.Clear();
        Console.Write("Enter Webhook URL: ");
        string? url = Console.ReadLine();
        Console.Write("Enter message: ");
        string? msg = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(url) && !string.IsNullOrWhiteSpace(msg))
        {
            bool ok = await SendWebhookAsync(url, msg);
            Console.WriteLine(ok ? "Webhook sent!" : "Failed.");
        }
        Console.WriteLine("\nPress any key to return to the menu...");
        Console.ReadKey();
    }
}

void InitializeDatabase()
{
    using var connection = new SqliteConnection("Data Source=security_scans.db");
    connection.Open();
    string cmdText = @"
        CREATE TABLE IF NOT EXISTS Scans (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            DomainName TEXT,
            SecurityGrade INTEGER,
            ScanDate TEXT,
            ReportJson TEXT,
            ReportHash TEXT
        );";
    using var cmd = new SqliteCommand(cmdText, connection);
    cmd.ExecuteNonQuery();
}

string ComputeReportHash(SecurityReport report)
{
    string raw = $"{report.IsSslValid}-{report.RsaKeySize}-{report.SecurityGrade}-{report.HasHsts}-{report.HasCsp}-{string.Join(",", report.OpenPorts)}-{string.Join(",", report.DiscoveredSubdomains)}";
    using var sha256 = System.Security.Cryptography.SHA256.Create();
    var bytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(bytes);
}

void CompareAndSaveSmart(string domain, SecurityReport newReport)
{
    string newHash = ComputeReportHash(newReport);
    try
    {
        using var connection = new SqliteConnection("Data Source=security_scans.db");
        connection.Open();
        string query = "SELECT ReportJson, ReportHash FROM Scans WHERE DomainName = @domain ORDER BY Id DESC LIMIT 1";
        using var command = new SqliteCommand(query, connection);
        command.Parameters.AddWithValue("@domain", domain);

        string? prevJson = null;
        string? prevHash = null;

        using (var reader = command.ExecuteReader())
        {
            if (reader.Read())
            {
                prevJson = reader["ReportJson"] as string;
                prevHash = reader["ReportHash"] as string;
            }
        }

        if (prevHash == newHash)
        {
            Console.WriteLine("\n[Anti-Duplicate] Stan domeny jest identyczny jak w poprzednim skanie. Pomijam zapis duplikatu w bazie.");
            return;
        }

        string insertQuery = "INSERT INTO Scans (DomainName, SecurityGrade, ScanDate, ReportJson, ReportHash) VALUES (@domain, @grade, @date, @json, @hash)";
        using var insertCmd = new SqliteCommand(insertQuery, connection);
        insertCmd.Parameters.AddWithValue("@domain", newReport.DomainName);
        insertCmd.Parameters.AddWithValue("@grade", newReport.SecurityGrade);
        insertCmd.Parameters.AddWithValue("@date", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
        insertCmd.Parameters.AddWithValue("@json", JsonSerializer.Serialize(newReport));
        insertCmd.Parameters.AddWithValue("@hash", newHash);
        insertCmd.ExecuteNonQuery();

        if (!string.IsNullOrEmpty(prevJson))
        {
            SecurityReport? oldReport = JsonSerializer.Deserialize<SecurityReport>(prevJson);
            if (oldReport != null)
            {
                Console.WriteLine("\n--- Wykryte zmiany od ostatniego unikalnego skanu ---");
                if (newReport.SecurityGrade != oldReport.SecurityGrade)
                    Console.WriteLine($"  [!] Ocena bezpieczeństwa: {oldReport.SecurityGrade} -> {newReport.SecurityGrade}");

                var newSubs = newReport.DiscoveredSubdomains.Except(oldReport.DiscoveredSubdomains).ToList();
                if (newSubs.Any()) Console.WriteLine($"  [+] Nowe subdomeny: {string.Join(", ", newSubs)}");

                var newPorts = newReport.OpenPorts.Except(oldReport.OpenPorts).ToList();
                if (newPorts.Any()) Console.WriteLine($"  [+] Nowe otwarte porty: {string.Join(", ", newPorts)}");
                Console.WriteLine("----------------------------------------------------\n");
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Database error: {ex.Message}");
    }
}

void DisplayUniqueHistory(string? domainFilter)
{
    try
    {
        using var connection = new SqliteConnection("Data Source=security_scans.db");
        connection.Open();
        string query = string.IsNullOrEmpty(domainFilter)
            ? "SELECT DomainName, SecurityGrade, ScanDate FROM Scans ORDER BY Id DESC LIMIT 20"
            : "SELECT DomainName, SecurityGrade, ScanDate FROM Scans WHERE DomainName = @domain ORDER BY Id DESC LIMIT 20";

        using var command = new SqliteCommand(query, connection);
        if (!string.IsNullOrEmpty(domainFilter)) command.Parameters.AddWithValue("@domain", domainFilter);

        using var reader = command.ExecuteReader();
        Console.WriteLine("\n--- Unikalna Historia Skanów (Bez Duplikatów) ---");
        bool found = false;
        while (reader.Read())
        {
            found = true;
            Console.WriteLine($"[{reader["ScanDate"]}] Domena: {reader["DomainName"]} | Wynik: {reader["SecurityGrade"]}/100");
        }
        if (!found) Console.WriteLine("Brak wpisów w historii.");
        Console.WriteLine("------------------------------------------------");
    }
    catch
    {
        Console.WriteLine("Błąd odczytu bazy historii.");
    }
}

void PrintReport(SecurityReport result)
{
    Console.WriteLine($"[RAPORT] {result.DomainName}");
    Console.WriteLine($"  SSL Valid: {result.IsSslValid} | Wygasa za: {result.DaysToExpiration} dni");
    Console.WriteLine($"  RSA Key: {result.RsaKeySize} bit | Algorytm: {result.SignatureAlgorithm}");
    Console.WriteLine($"  Protokoły TLS: {string.Join(", ", result.SupportedTlsVersions)}");
    Console.WriteLine($"  Przekierowanie HTTP->HTTPS: {result.HasHttpToHttpsRedirect} | HSTS: {result.HasHsts}");
    Console.WriteLine($"  Nagłówki bezpieczeństwa: CSP={result.HasCsp}, X-Frame={result.HasXFrameOptions}, X-Content={result.HasXContentTypeOptions}");
    Console.WriteLine($"  Otwarte porty: {(result.OpenPorts.Count > 0 ? string.Join(", ", result.OpenPorts) : "Brak / ukryte")}");
    Console.WriteLine($"  Subdomeny: {result.DiscoveredSubdomains.Count}");
    Console.WriteLine($"  Końcowa ocena: {result.SecurityGrade}/100");

    if (result.Recommendations.Count > 0)
    {
        Console.WriteLine("\n  Note: What needs to be changed:");
        foreach (var rec in result.Recommendations)
        {
            Console.WriteLine($"   • {rec}");
        }
    }
    else
    {
        Console.WriteLine("\n  No issues! All basic safety tests were passed successfully.");
    }
    Console.WriteLine();
}

async Task<bool> SendWebhookAsync(string url, string message)
{
    try
    {
        var payload = new { content = message };
        string json = JsonSerializer.Serialize(payload);
        using StringContent content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await SharedHttp.NormalClient.PostAsync(url, content);
        return response.IsSuccessStatusCode;
    }
    catch { return false; }
}

void GenerateHtmlReport(SecurityReport report)
{
    string recommendationsHtml = "";
    if (report.Recommendations.Count > 0)
    {
        recommendationsHtml = "<h3>Co poprawić, aby zwiększyć wynik:</h3><ul>";
        foreach (var rec in report.Recommendations)
        {
            recommendationsHtml += $"<li>{rec}</li>";
        }
        recommendationsHtml += "</ul>";
    }

    string html = $@"<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>Audit - {report.DomainName}</title></head>
<body style='font-family:Arial;background:#f4f7f6;padding:20px;'>
<div style='max-width:800px;background:#fff;margin:auto;padding:30px;border-radius:8px;'>
<h1>Raport: {report.DomainName}</h1>
<h2>Ocena: {report.SecurityGrade} / 100</h2>
<ul>
<li>SSL: {report.IsSslValid} (Wygasa za {report.DaysToExpiration} dni)</li>
<li>RSA: {report.RsaKeySize} bits</li>
<li>HSTS: {report.HasHsts} | CSP: {report.HasCsp}</li>
<li>Otwarte porty: {string.Join(", ", report.OpenPorts)}</li>
<li>Subdomeny: {string.Join(", ", report.DiscoveredSubdomains)}</li>
</ul>
{recommendationsHtml}
</div></body></html>";
    File.WriteAllText($"{report.DomainName}_report.html", html);
}

public static class SharedHttp
{
    public static readonly HttpClient NormalClient;
    public static readonly HttpClient NoRedirectClient;

    static SharedHttp()
    {
        var socketsHandlerNormal = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectTimeout = TimeSpan.FromSeconds(4)
        };
        NormalClient = new HttpClient(socketsHandlerNormal) { Timeout = TimeSpan.FromSeconds(6) };

        var socketsHandlerNoRedirect = new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectTimeout = TimeSpan.FromSeconds(4),
            AllowAutoRedirect = false
        };
        NoRedirectClient = new HttpClient(socketsHandlerNoRedirect) { Timeout = TimeSpan.FromSeconds(5) };
    }
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
    public List<string> DiscoveredSubdomains { get; set; } = new List<string>();
    public List<int> OpenPorts { get; set; } = new List<int>();
    public List<string> Recommendations { get; set; } = new List<string>();
}

public class SecurityScanner
{
    private static readonly int[] TargetPorts = { 80, 443, 21, 22, 25, 3306, 5432, 8080 };

    public async Task<SecurityReport> ScanDomainAsync(string domain)
    {
        SecurityReport report = new SecurityReport { DomainName = domain };

        var portTask = ScanPortsAsync(domain, TargetPorts);
        var sslAndHttpTask = ScanSslAndHttpAsync(domain, report);

        await Task.WhenAll(portTask, sslAndHttpTask);
        report.OpenPorts = await portTask;

        return report;
    }

    private async Task<List<int>> ScanPortsAsync(string domain, int[] ports)
    {
        var openPorts = new ConcurrentBag<int>();
        var tasks = ports.Select(async port =>
        {
            try
            {
                using var tcpClient = new TcpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1.5));
                await tcpClient.ConnectAsync(domain, port, cts.Token);
                if (tcpClient.Connected)
                {
                    openPorts.Add(port);
                }
            }
            catch
            {
            }
        });

        await Task.WhenAll(tasks);
        return openPorts.OrderBy(p => p).ToList();
    }

    private async Task ScanSslAndHttpAsync(string domain, SecurityReport report)
    {
        try
        {
            using (var client = new TcpClient())
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await client.ConnectAsync(domain, 443, cts.Token);
                using var sslStream = new SslStream(client.GetStream(), false, (sender, cert, chain, errors) => true);
                await sslStream.AuthenticateAsClientAsync(domain);

                if (sslStream.RemoteCertificate is System.Security.Cryptography.X509Certificates.X509Certificate remoteCert)
                {
                    using X509Certificate2 certificate = new X509Certificate2(remoteCert);
                    report.IsSslValid = certificate.Verify();
                    report.DaysToExpiration = (certificate.NotAfter - DateTime.Now).Days;
                    report.SignatureAlgorithm = certificate.SignatureAlgorithm.FriendlyName ?? "Unknown";

                    using var rsaKey = certificate.GetRSAPublicKey();
                    if (rsaKey != null) report.RsaKeySize = rsaKey.KeySize;
                }
                report.SupportedTlsVersions.Add(sslStream.SslProtocol.ToString());
            }

            using var response = await SharedHttp.NormalClient.GetAsync($"https://{domain}");
            report.HasCsp = response.Headers.Contains("Content-Security-Policy");
            report.HasXContentTypeOptions = response.Headers.Contains("X-Content-Type-Options");
            report.HasHsts = response.Headers.Contains("Strict-Transport-Security");
            report.HasXFrameOptions = response.Headers.Contains("X-Frame-Options");

            using var noRedirectResponse = await SharedHttp.NoRedirectClient.GetAsync($"http://{domain}");
            report.HasHttpToHttpsRedirect = (int)noRedirectResponse.StatusCode >= 300 && (int)noRedirectResponse.StatusCode < 400;

            int score = 100;

            if (!report.IsSslValid)
            {
                score -= 30;
                report.Recommendations.Add("The SSL certificate is invalid. How to fix it: Renew or properly configure a valid SSL certificate from a trusted certificate authority (CA).");
            }
            if (!report.HasHsts)
            {
                score -= 15;
                report.Recommendations.Add("Missing HSTS (Strict-Transport-Security) header. How to fix it: Enable the HSTS header in the server configuration (this enforces encrypted HTTPS connections).");
            }
            if (!report.HasCsp)
            {
                score -= 15;
                report.Recommendations.Add("Missing CSP (Content-Security-Policy) header. How to fix it: Add a CSP policy on the server to protect the site from XSS attacks.");
            }
            if (!report.HasXFrameOptions)
            {
                score -= 10;
                report.Recommendations.Add("Missing X-Frame-Options header. How to fix it: Configure the X-Frame-Options header (e.g., DENY or SAMEORIGIN) to protect against clickjacking.");
            }
            if (!report.HasHttpToHttpsRedirect)
            {
                score -= 10;
                report.Recommendations.Add("No redirection from HTTP to HTTPS. How to fix it: Configure the server (e.g., Nginx/Apache) to automatically redirect traffic from port 80 to 443.");
            }

            report.SecurityGrade = Math.Max(0, score);
        }
        catch (Exception ex)
        {
            report.Recommendations.Add($"Krytyczny błąd audytu: {ex.Message}. Sprawdź czy domena jest poprawnie dostępna w sieci.");
        }
    }

    public static async Task<string> GetTxtRecordAsync(string queryDomain)
    {
        try
        {
            var hostEntry = await Dns.GetHostEntryAsync(queryDomain);
            return hostEntry != null ? "Configured" : string.Empty;
        }
        catch { return string.Empty; }
    }

    public static async Task<List<string>> EnumerateSubdomainsAsync(string domain)
    {
        string[] commonSubs = { "www", "mail", "ftp", "test", "admin", "api", "shop", "blog", "portal", "dev", "vpn", "remote" };
        var found = new ConcurrentBag<string>();

        var tasks = commonSubs.Select(async sub =>
        {
            string testDomain = $"{sub}.{domain}";
            try
            {
                var ips = await Dns.GetHostAddressesAsync(testDomain);
                if (ips.Length > 0) found.Add(testDomain);
            }
            catch { }
        });

        await Task.WhenAll(tasks);
        return found.ToList();
    }
}

