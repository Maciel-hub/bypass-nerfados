using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using System.Runtime.InteropServices;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Histórico de downloads do Chrome/Edge/Brave/Opera/Firefox — detecta executáveis e URLs suspeitos.
/// Lê o banco de dados SQLite do Chromium via winsqlite3.dll (incluído no Windows 10+)
/// e places.sqlite do Firefox, sem dependências externas de SQLite gerenciado.
/// </summary>
public class BrowserDownloadsModule : BaseModule
{
    public override string Name        => "Browser Downloads";
    public override string Description => "Histórico de downloads do Chrome/Edge/Brave/Opera/Firefox — detecta executáveis e URLs suspeitos";

    // ── SQLite P/Invoke declarations ──────────────────────────────────────────
    // All calls go through winsqlite3.dll which ships with Windows 10+.
    // AllowUnsafeBlocks=false: all unmanaged data is read through Marshal, never unsafe pointers.

    private const int SQLITE_OK       = 0;
    private const int SQLITE_ROW      = 100;
    private const int SQLITE_OPEN_READONLY = 1;

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string filename,
        out IntPtr db,
        int flags,
        IntPtr vfs);

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_prepare_v2(
        IntPtr db,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string sql,
        int nByte,
        out IntPtr stmt,
        IntPtr pzTail);

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr stmt);

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern long sqlite3_column_int64(IntPtr stmt, int col);

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr stmt);

    [DllImport("winsqlite3", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);

    // ── URL domains considered safe for executable downloads ─────────────────
    // Matched against Uri.Host (exact or parent-domain suffix), not substring.
    // GitHub is NOT in this list — it's handled via SafeGitHubOrgs to avoid
    // treating arbitrary github.com releases as safe.

    private static readonly string[] SafeDomains =
    [
        "microsoft.com",
        "cfx.re",
        "rockstargames.com",
        "epicgames.com",
        "steampowered.com",
        "gog.com",
        "discordapp.com",
        "discord.com",
        "mozilla.org",
        "google.com",
        "visualstudio.com",
        "nuget.org",
    ];

    // GitHub org/repo path prefixes considered safe.
    // Checked against the full URL string when host is github.com / raw.githubusercontent.com.
    private static readonly string[] SafeGitHubOrgs =
    [
        "github.com/citizenfx/",
        "github.com/microsoft/",
        "github.com/dotnet/",
        "github.com/git-for-windows/",
        "raw.githubusercontent.com/citizenfx/",
        "raw.githubusercontent.com/microsoft/",
    ];

    // URL path/host fragments that indicate a suspicious cheat-related download origin.
    // Kept to specific identifiers — avoid generic terms that match legitimate content.
    private static readonly string[] SuspiciousUrlKeywords =
    [
        "foxee69",
        "echo-bypass-fivem",
        "batchgotadmin",
        "cheat-fivem",
        "hack-fivem",
        "spoofer-hwid",
        "eulen.cc",
        "redengine.",
        "cherax.",
        "susano.",
    ];

    // Cheat portal URL paths — specific enough to confirm portal access, not just keyword match.
    // Returns the family name if matched; null otherwise.
    private static string? MatchCheatPortalUrl(string urlLower)
    {
        if (urlLower.Contains("redengine.net/customer-area") ||
            urlLower.Contains("redengine.net/orders") ||
            urlLower.Contains("redengine.net/download"))
            return "RedENGINE";
        return null;
    }

    // Cheat archive filename patterns (case-insensitive match on the filename portion).
    private static bool IsCheatPortalArchive(string fileNameLower)
    {
        if (!fileNameLower.EndsWith(".zip") && !fileNameLower.EndsWith(".rar")) return false;
        // Loader-<hash>.zip (Stan/RedENGINE delivery pattern)
        if (fileNameLower.StartsWith("loader-")) return true;
        // Executor V2.zip, Executor+Spoofer.zip
        if (fileNameLower.StartsWith("executor")) return true;
        // *spoofer*.zip
        if (fileNameLower.Contains("spoofer")) return true;
        return false;
    }

    // Executable-type extensions that are flagged if not from a safe domain
    private static readonly HashSet<string> ExecExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
        };

    // ── WebKit timestamp helpers ──────────────────────────────────────────────

    /// <summary>
    /// Converts a Chromium/WebKit timestamp (microseconds since 1601-01-01 UTC) to local DateTime.
    /// Returns null for values ≤ 0.
    /// </summary>
    private static DateTime? WebKitToDateTime(long wk)
    {
        if (wk <= 0) return null;
        // WebKit µs → Windows FILETIME (100-ns intervals): multiply by 10
        var fileTime = wk * 10L;
        return DateTime.FromFileTimeUtc(fileTime).ToLocalTime();
    }

    /// <summary>
    /// Converts a UTC DateTime to a Chromium WebKit timestamp (µs since 1601-01-01 UTC).
    /// Inverse of WebKitToDateTime.
    /// </summary>
    private static long DateTimeToWebKit(DateTime utc) =>
        utc.ToFileTimeUtc() / 10L;

    // ── SQLite query helper ───────────────────────────────────────────────────

    /// <summary>
    /// Opens a SQLite database read-only, executes <paramref name="sql"/>, and returns
    /// all rows as a list of string arrays with <paramref name="cols"/> elements each.
    /// Text columns are read via Marshal.PtrToStringUTF8; integer columns are converted
    /// to their decimal string representation.
    /// Returns an empty list on any failure — never throws.
    /// </summary>
    private List<string[]> QueryDb(string path, string sql, int cols)
    {
        var rows = new List<string[]>();
        var db   = IntPtr.Zero;
        var stmt = IntPtr.Zero;

        try
        {
            if (sqlite3_open_v2(path, out db, SQLITE_OPEN_READONLY, IntPtr.Zero) != SQLITE_OK)
            {
                LogPartialError($"Browser Downloads: sqlite3_open falhou — {Path.GetFileName(path)}");
                return rows;
            }

            if (sqlite3_prepare_v2(db, sql, -1, out stmt, IntPtr.Zero) != SQLITE_OK)
            {
                LogPartialError($"Browser Downloads: sqlite3_prepare falhou — {Path.GetFileName(path)}");
                return rows;
            }

            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                var row = new string[cols];
                for (var c = 0; c < cols; c++)
                {
                    // Read as int64 first; if the column type is text the value will be 0,
                    // but we always prefer to read text via sqlite3_column_text for accuracy.
                    var ptr = sqlite3_column_text(stmt, c);
                    row[c] = ptr != IntPtr.Zero
                        ? Marshal.PtrToStringUTF8(ptr) ?? string.Empty
                        : sqlite3_column_int64(stmt, c).ToString();
                }
                rows.Add(row);
            }
        }
        catch (Exception ex)
        {
            LogPartialError($"Browser Downloads: QueryDb falhou — {Path.GetFileName(path)}", ex);
        }
        finally
        {
            if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
            if (db   != IntPtr.Zero) sqlite3_close(db);
        }

        return rows;
    }

    // ── URL safe-domain helper ────────────────────────────────────────────────

    /// <summary>
    /// Returns true when the URL's registered host is in SafeDomains (exact match
    /// or parent-domain suffix — e.g., "update.microsoft.com" passes "microsoft.com").
    /// GitHub is only safe for known trusted orgs listed in SafeGitHubOrgs.
    /// Uses Uri.Host to avoid substring false matches like "evil-microsoft.com".
    /// </summary>
    private static bool IsFromSafeDomain(string url)
    {
        if (string.IsNullOrEmpty(url)) return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        var host    = uri.Host.ToLowerInvariant();
        var urlLow  = url.ToLowerInvariant();

        // GitHub: only trusted for specific orgs, not github.com globally
        if (host == "github.com" || host == "raw.githubusercontent.com" ||
            host.EndsWith(".github.com", StringComparison.Ordinal))
        {
            return SafeGitHubOrgs.Any(org => urlLow.Contains(org));
        }

        return SafeDomains.Any(safe =>
            host == safe || host.EndsWith("." + safe, StringComparison.Ordinal));
    }

    // ── Browser profile discovery ─────────────────────────────────────────────

    /// <summary>
    /// Enumerates all browser history database paths for Chrome, Edge, Brave, Opera, and Firefox.
    /// Returns (browserName, historyPath, isFirefox) tuples for paths that exist on disk.
    /// </summary>
    private static IEnumerable<(string Browser, string HistoryPath, bool IsFirefox)> GetBrowserProfiles()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Helper: yield Default + all Profile N sub-folders for a Chromium User Data root
        IEnumerable<(string, string, bool)> ChromiumProfiles(string browser, string userDataRoot)
        {
            var def = Path.Combine(userDataRoot, "Default", "History");
            if (File.Exists(def)) yield return (browser, def, false);

            if (!Directory.Exists(userDataRoot)) yield break;
            foreach (var dir in Directory.GetDirectories(userDataRoot, "Profile *"))
            {
                var p = Path.Combine(dir, "History");
                if (File.Exists(p)) yield return (browser, p, false);
            }
        }

        foreach (var t in ChromiumProfiles("Chrome",
            Path.Combine(localAppData, "Google", "Chrome", "User Data")))
            yield return t;

        foreach (var t in ChromiumProfiles("Edge",
            Path.Combine(localAppData, "Microsoft", "Edge", "User Data")))
            yield return t;

        foreach (var t in ChromiumProfiles("Brave",
            Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "User Data")))
            yield return t;

        var opera = Path.Combine(appData, "Opera Software", "Opera Stable", "History");
        if (File.Exists(opera)) yield return ("Opera", opera, false);

        // Firefox: enumerate all profiles in %APPDATA%\Mozilla\Firefox\Profiles\
        var ffProfiles = Path.Combine(appData, "Mozilla", "Firefox", "Profiles");
        if (Directory.Exists(ffProfiles))
        {
            string[] ffDirs;
            try { ffDirs = Directory.GetDirectories(ffProfiles); }
            catch { ffDirs = []; }

            foreach (var dir in ffDirs)
            {
                var places = Path.Combine(dir, "places.sqlite");
                if (File.Exists(places)) yield return ("Firefox", places, true);
            }
        }
    }

    // ── Module entry point ────────────────────────────────────────────────────

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        var lookbackDays = (int)config.EventWindowLookback.TotalDays;
        var cutoffWebKit = DateTimeToWebKit(DateTime.UtcNow.AddDays(-lookbackDays));

        // Chromium downloads table query
        var chromiumSql = $"""
            SELECT target_path, tab_url, referrer, start_time, state, received_bytes, mime_type
            FROM downloads
            WHERE start_time > {cutoffWebKit}
            ORDER BY start_time DESC
            LIMIT 500
            """;

        // Firefox places.sqlite: downloads stored in moz_annos (destination URI annotation)
        var firefoxSql = """
            SELECT p.url, a.content, a.dateAdded
            FROM moz_places p
            JOIN moz_annos a ON a.place_id = p.id
            JOIN moz_anno_attributes attr ON attr.id = a.anno_attribute_id
            WHERE attr.name = 'downloads/destinationFileURI'
            ORDER BY a.dateAdded DESC
            LIMIT 500
            """;

        await Task.Run(() =>
        {
            foreach (var (browser, historyPath, isFirefox) in GetBrowserProfiles())
            {
                cancellationToken.ThrowIfCancellationRequested();

                var sql = isFirefox ? firefoxSql : chromiumSql;
                AnalyzeBrowserHistory(browser, historyPath, sql, isFirefox, findings);
            }
        }, cancellationToken);

        return findings;
    }

    // ── Per-profile analysis ──────────────────────────────────────────────────

    /// <summary>
    /// Copies the SQLite history file via CopyLockedFile (permissive FileShare copy, handles
    /// browsers with open handles), queries it, and analyses each download row for suspicious indicators.
    /// </summary>
    private void AnalyzeBrowserHistory(
        string browser, string historyPath, string sql, bool isFirefox, List<Finding> findings)
    {
        var tmpPath = CopyLockedFile(historyPath);
        if (tmpPath == null)
        {
            LogPartialError($"Browser Downloads — {browser}: não foi possível copiar histórico ({historyPath})");
            return;
        }

        try
        {
            var cols = isFirefox ? 3 : 7;
            var rows = QueryDb(tmpPath, sql, cols);

            foreach (var row in rows)
            {
                if (row.Length < cols) continue;

                if (isFirefox)
                    AnalyzeFirefoxRow(browser, row, findings);
                else
                    AnalyzeDownloadRow(browser, row, findings);
            }
        }
        catch (Exception ex)
        {
            LogPartialError($"Histórico do {browser} inacessível ({historyPath})", ex);
        }
        finally
        {
            try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
        }
    }

    /// <summary>
    /// Analyses a single Firefox download row (url, destinationFileURI, dateAdded).
    /// Firefox stores the destination as a file:// URI; we extract the local path from it.
    /// </summary>
    private void AnalyzeFirefoxRow(string browser, string[] row, List<Finding> findings)
    {
        var tabUrl       = row[0] ?? string.Empty;
        var destUri      = row[1] ?? string.Empty;
        var dateAddedRaw = row[2] ?? "0";

        // Convert file:// URI to local path
        string targetPath;
        try
        {
            targetPath = Uri.TryCreate(destUri, UriKind.Absolute, out var uri) && uri.IsFile
                ? uri.LocalPath
                : destUri;
        }
        catch { targetPath = destUri; }

        DateTime? startTime = null;
        if (long.TryParse(dateAddedRaw, out var usec) && usec > 0)
            startTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddMicroseconds(usec).ToLocalTime();

        AnalyzeFirefoxEntry(browser, targetPath, tabUrl, startTime, findings);
    }

    private void AnalyzeFirefoxEntry(
        string browser, string targetPath, string tabUrl, DateTime? startTime, List<Finding> findings)
    {
        var fileName = Path.GetFileName(targetPath).ToLowerInvariant();
        var ext      = Path.GetExtension(fileName).ToLowerInvariant();
        var urlLower = tabUrl.ToLowerInvariant();

        if (CheatDatabase.HasSuspiciousKeyword(fileName) &&
            !CheatDatabase.IsKnownLegitimate(targetPath))
        {
            findings.Add(new Finding(
                RiskLevel.High, FindingCategory.Cheat, Name,
                $"Download suspeito — nome de arquivo: {fileName} ({browser})",
                $"Arquivo com nome suspeito baixado pelo {browser}.\nArquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime, confidence: Confidence.Medium,
                ruleId: $"BROWSER_DL_SUSPICIOUS_NAME_{fileName.ToUpperInvariant()}",
                entity: targetPath));
        }

        var portalFamily = MatchCheatPortalUrl(urlLower);
        var matchedKw    = SuspiciousUrlKeywords.FirstOrDefault(kw => urlLower.Contains(kw));

        if (portalFamily != null)
        {
            findings.Add(new Finding(
                RiskLevel.High, FindingCategory.Cheat, Name,
                $"{portalFamily}: download do portal de compra detectado ({browser})",
                $"Arquivo baixado do portal de assinantes {portalFamily}.\nArquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime, confidence: Confidence.High,
                ruleId: "BROWSER_DL_REDENGINE_PORTAL", entity: targetPath));
        }
        else if (matchedKw != null)
        {
            findings.Add(new Finding(
                RiskLevel.High, FindingCategory.Cheat, Name,
                $"Download com URL suspeita ({browser}): {fileName}",
                $"Arquivo baixado de URL associada a cheats.\nArquivo: {targetPath}\nURL: {tabUrl}\nIndicador: '{matchedKw}'",
                $"URL: {tabUrl} | Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime, confidence: Confidence.Medium,
                ruleId: "BROWSER_DL_SUSPICIOUS_URL", entity: targetPath));
        }

        if (IsCheatPortalArchive(fileName) && portalFamily == null)
        {
            findings.Add(new Finding(
                RiskLevel.High, FindingCategory.Cheat, Name,
                $"Download de arquivo de loader/executor: {fileName} ({browser})",
                $"Arquivo com padrão de loader/executor cheat.\nArquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime, confidence: Confidence.Medium,
                ruleId: "BROWSER_DL_CHEAT_PORTAL_ARCHIVE", entity: targetPath));
        }

        if (ExecExtensions.Contains(ext) && !IsFromSafeDomain(tabUrl))
        {
            findings.Add(new Finding(
                RiskLevel.Medium, FindingCategory.SuspiciousExecution, Name,
                $"Download de executável de fonte não verificada ({browser}): {fileName}",
                $"Arquivo executável baixado de origem não listada como segura.\nArquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime, confidence: Confidence.Low,
                ruleId: $"BROWSER_DL_EXEC_{ext.TrimStart('.').ToUpperInvariant()}",
                entity: targetPath));
        }
    }

    /// <summary>
    /// Evaluates a single download row and emits findings for:
    /// A) suspicious file name / path (CheatDatabase keyword match)
    /// B) suspicious URL / referrer
    /// C) executable extension from an untrusted source
    /// </summary>
    private void AnalyzeDownloadRow(string browser, string[] row, List<Finding> findings)
    {
        var targetPath = row[0] ?? string.Empty;
        var tabUrl     = row[1] ?? string.Empty;
        var referrer   = row[2] ?? string.Empty;
        var startRaw   = row[3] ?? "0";

        DateTime? startTime = null;
        if (long.TryParse(startRaw, out var wkTs))
            startTime = WebKitToDateTime(wkTs);

        var fileName  = Path.GetFileName(targetPath).ToLowerInvariant();
        var ext       = Path.GetExtension(fileName).ToLowerInvariant();
        var urlLower  = (tabUrl + " " + referrer).ToLowerInvariant();

        // ── Condition A: suspicious file name (filename only — full path causes FP on dev dirs)
        if (CheatDatabase.HasSuspiciousKeyword(fileName) &&
            !CheatDatabase.IsKnownLegitimate(targetPath))
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                Name,
                $"Download suspeito — nome de arquivo: {fileName} ({browser})",
                $"Arquivo com nome suspeito baixado pelo {browser}.\n" +
                $"Arquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Referrer: {referrer} | " +
                $"Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime,
                confidence: Confidence.Medium,
                ruleId: $"BROWSER_DL_SUSPICIOUS_NAME_{fileName.ToUpperInvariant()}",
                entity: targetPath
            ));
        }

        // ── Condition B: suspicious URL or referrer ───────────────────────────
        var matchedUrlKw = SuspiciousUrlKeywords.FirstOrDefault(kw => urlLower.Contains(kw));
        // Portal-specific match (D) supersedes the generic B finding when URL is a confirmed portal.
        var portalFamily = MatchCheatPortalUrl(urlLower);

        if (portalFamily != null)
        {
            // ── Condition D: confirmed cheat portal URL ───────────────────────
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                Name,
                $"{portalFamily}: download do portal de compra detectado ({browser})",
                $"Arquivo baixado do portal de assinantes {portalFamily} — confirma compra/acesso ao serviço cheat.\n" +
                $"Arquivo: {targetPath}\nURL: {tabUrl}\nReferência: {referrer}",
                $"URL: {tabUrl} | Referrer: {referrer} | " +
                $"Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime,
                confidence: Confidence.High,
                ruleId: "BROWSER_DL_REDENGINE_PORTAL",
                entity: targetPath
            ));
        }
        else if (matchedUrlKw != null)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                Name,
                $"Download com URL suspeita ({browser}): {fileName}",
                $"Arquivo baixado de uma URL associada a cheats/bypass.\n" +
                $"Arquivo: {targetPath}\nURL: {tabUrl}\nIndicador: '{matchedUrlKw}'",
                $"URL: {tabUrl} | Referrer: {referrer} | " +
                $"Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime,
                confidence: Confidence.Medium,
                ruleId: "BROWSER_DL_SUSPICIOUS_URL",
                entity: targetPath
            ));
        }

        // ── Condition D2: cheat portal archive by filename pattern ────────────
        if (IsCheatPortalArchive(fileName) && portalFamily == null)
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                Name,
                $"Download de arquivo de loader/executor: {fileName} ({browser})",
                $"Arquivo com padrão de nome de loader/executor cheat baixado pelo {browser}.\n" +
                $"Padrão: Loader-<hash>.zip, Executor*.zip, *spoofer*.zip\n" +
                $"Arquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime,
                confidence: Confidence.Medium,
                ruleId: "BROWSER_DL_CHEAT_PORTAL_ARCHIVE",
                entity: targetPath
            ));
        }

        // ── Condition C: executable from untrusted source ─────────────────────
        if (ExecExtensions.Contains(ext) &&
            !IsFromSafeDomain(tabUrl) && !IsFromSafeDomain(referrer))
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.SuspiciousExecution,
                Name,
                $"Download de executável de fonte não verificada ({browser}): {fileName}",
                $"Arquivo executável baixado de uma origem não listada como segura.\n" +
                $"Arquivo: {targetPath}\nURL: {tabUrl}",
                $"URL: {tabUrl} | Referrer: {referrer} | " +
                $"Data: {startTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "N/A"}",
                timestamp: startTime,
                confidence: Confidence.Low,
                ruleId: $"BROWSER_DL_EXEC_{ext.TrimStart('.').ToUpperInvariant()}",
                entity: targetPath
            ));
        }
    }
}
