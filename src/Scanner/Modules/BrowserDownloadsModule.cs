using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using System.Runtime.InteropServices;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Histórico de downloads do Chrome/Edge/Brave/Opera — detecta executáveis e URLs suspeitos.
/// Lê o banco de dados SQLite do Chromium via winsqlite3.dll (incluído no Windows 10+)
/// sem dependências externas de SQLite gerenciado.
/// </summary>
public class BrowserDownloadsModule : BaseModule
{
    public override string Name        => "Browser Downloads";
    public override string Description => "Histórico de downloads do Chrome/Edge/Brave/Opera — detecta executáveis e URLs suspeitos";

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

    private static readonly string[] SafeDomains =
    [
        "microsoft.com",
        "github.com/citizenfx",
        "cfx.re",
        "rockstargames.com",
        "epicgames.com",
        "steampowered.com",
        "gog.com",
        "discordapp.com",
        "discord.com",
        "mozilla.org",
        "google.com/chrome",
        "visualstudio.com",
    ];

    // URL fragments that indicate a suspicious cheat-related download origin
    private static readonly string[] SuspiciousUrlKeywords =
    [
        "foxee69",
        "echo-bypass-fivem",
        "batchgotadmin",
        "cheat",
        "hack",
        "spoofer",
        "eulen",
        "redengine",
        "gosth",
        "farinha",
        "cherax",
        "susano",
    ];

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
    private static List<string[]> QueryDb(string path, string sql, int cols)
    {
        var rows = new List<string[]>();
        var db   = IntPtr.Zero;
        var stmt = IntPtr.Zero;

        try
        {
            if (sqlite3_open_v2(path, out db, SQLITE_OPEN_READONLY, IntPtr.Zero) != SQLITE_OK)
                return rows;

            if (sqlite3_prepare_v2(db, sql, -1, out stmt, IntPtr.Zero) != SQLITE_OK)
                return rows;

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
        catch
        {
            // Swallow all failures; caller handles an empty result set
        }
        finally
        {
            if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
            if (db   != IntPtr.Zero) sqlite3_close(db);
        }

        return rows;
    }

    // ── Browser profile discovery ─────────────────────────────────────────────

    /// <summary>
    /// Enumerates all browser history database paths for Chrome, Edge, Brave, and Opera.
    /// Returns (browserName, historyPath) tuples for paths that exist on disk.
    /// Expands "Profile *" glob patterns via Directory.GetDirectories.
    /// </summary>
    private static IEnumerable<(string Browser, string HistoryPath)> GetBrowserProfiles()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appData      = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        // Helper: yield Default + all Profile N sub-folders for a Chromium User Data root
        IEnumerable<(string, string)> ChromiumProfiles(string browser, string userDataRoot)
        {
            // Default profile
            var def = Path.Combine(userDataRoot, "Default", "History");
            if (File.Exists(def)) yield return (browser, def);

            // Named profiles: "Profile 1", "Profile 2", etc.
            if (!Directory.Exists(userDataRoot)) yield break;
            foreach (var dir in Directory.GetDirectories(userDataRoot, "Profile *"))
            {
                var p = Path.Combine(dir, "History");
                if (File.Exists(p)) yield return (browser, p);
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

        // Opera uses a flat profile (no "User Data" sub-dir with multiple profiles)
        var opera = Path.Combine(appData, "Opera Software", "Opera Stable", "History");
        if (File.Exists(opera)) yield return ("Opera", opera);
    }

    // ── Module entry point ────────────────────────────────────────────────────

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        // Cutoff: 60-day lookback expressed as a WebKit timestamp
        var cutoffWebKit = DateTimeToWebKit(DateTime.UtcNow.AddDays(-60));

        // SQL query for the Chromium downloads table
        var sql = $"""
            SELECT target_path, tab_url, referrer, start_time, state, received_bytes, mime_type
            FROM downloads
            WHERE start_time > {cutoffWebKit}
            ORDER BY start_time DESC
            LIMIT 500
            """;

        await Task.Run(() =>
        {
            foreach (var (browser, historyPath) in GetBrowserProfiles())
            {
                cancellationToken.ThrowIfCancellationRequested();

                AnalyzeBrowserHistory(browser, historyPath, sql, findings);
            }
        }, cancellationToken);

        return findings;
    }

    // ── Per-profile analysis ──────────────────────────────────────────────────

    /// <summary>
    /// Copies the SQLite history file to a temp path (avoids locking the live DB),
    /// queries it, and analyses each download row for suspicious indicators.
    /// </summary>
    private void AnalyzeBrowserHistory(
        string browser, string historyPath, string sql, List<Finding> findings)
    {
        var tmpPath = Path.Combine(Path.GetTempPath(), $"echo_brdl_{Guid.NewGuid():N}.tmp");

        try
        {
            // Copy to temp so we don't lock the live browser file
            File.Copy(historyPath, tmpPath, overwrite: true);

            var rows = QueryDb(tmpPath, sql, cols: 7);

            foreach (var row in rows)
            {
                if (row.Length < 7) continue;

                AnalyzeDownloadRow(browser, row, findings);
            }
        }
        catch (Exception ex)
        {
            LogPartialError($"Histórico do {browser} inacessível ({historyPath})", ex);
        }
        finally
        {
            // Always clean up the temp copy
            try { if (File.Exists(tmpPath)) File.Delete(tmpPath); } catch { }
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

        // ── Condition A: suspicious file name or path ─────────────────────────
        if (CheatDatabase.HasSuspiciousKeyword(fileName) ||
            CheatDatabase.HasSuspiciousKeyword(targetPath))
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
        if (matchedUrlKw != null)
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

        // ── Condition C: executable from untrusted source ─────────────────────
        if (ExecExtensions.Contains(ext) &&
            !SafeDomains.Any(domain => urlLower.Contains(domain)))
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
