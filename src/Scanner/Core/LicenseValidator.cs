using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace BypassNerfados.Scanner.Core;

public enum LicenseErrorCode
{
    None,
    NotFound,
    ParseError,
    InvalidSignature,
    Expired,
    WrongMachine,
    VersionTooHigh,
    ClockRollback
}

public sealed record LicenseInfo(
    string CustomerId,
    DateTimeOffset IssuedAt,
    DateTimeOffset ExpiresAt,
    string MachineId,
    string[] Features,
    string MaxVersion);

public sealed record LicenseResult(
    bool Success,
    LicenseErrorCode ErrorCode = LicenseErrorCode.None,
    string ErrorMessage = "",
    LicenseInfo? License = null);

public static class LicenseValidator
{
    // Echo Nerfados ECDSA P-256 public key (embedded at build time).
    // Regenerate with: LicenseTool.exe --generate-keys
    private const string EmbeddedPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5NATMD4Ogyg2aQQ+yv/P/Dsdvyc" +
        "ZiJqyHQn19tS8h6jslWfDIPXUdEguigs9X9207vlktpNepBwfKCXQgdGpQ==\n" +
        "-----END PUBLIC KEY-----";

    private static readonly JsonSerializerOptions s_jsonOpts = new()
    {
        PropertyNamingPolicy        = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    // Known OEM placeholder strings that are NOT stable identifiers
    private static readonly HashSet<string> s_placeholders = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "N/A", "None", "Unknown", "0", "00000000",
        "To be filled by O.E.M.", "To Be Filled By O.E.M.",
        "Not Specified", "System Serial Number",
        "Default string", "OEM", "OEM Chassis",
        "00000000000000000000000000000000",
        "INVALID", "Base Board Serial Number"
    };

    // %ProgramData%\EchoNerfados\ — shared state directory (DPAPI clock state + installed license)
    private static readonly string s_stateDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EchoNerfados");
    private static readonly string s_statePath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EchoNerfados", "last_check");
    private const int ClockToleranceMinutes = 5;

    // License search: ProgramData first (installed layout), then beside EXE (dev/portable).
    private static readonly string[] s_licenseSearchPaths =
    [
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EchoNerfados", "license.nerf"),
        Path.Combine(AppContext.BaseDirectory, "license.nerf")
    ];

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes a stable 16-hex-char machine ID from 4 hardware/OS sources.
    /// Order: ProcessorId, BaseBoard.SerialNumber, BIOS.SerialNumber, MachineGuid.
    /// Placeholder values are excluded. Falls back to MachineName+Domain if all fail.
    /// </summary>
    public static string ComputeMachineId()
    {
        var parts = new List<string>();

        // ProcessorId — survives OS reinstall, changes with new CPU
        parts.AddRange(GetWmiStrings("SELECT ProcessorId FROM Win32_Processor", "ProcessorId"));
        // BaseBoard SerialNumber — motherboard
        parts.AddRange(GetWmiStrings("SELECT SerialNumber FROM Win32_BaseBoard", "SerialNumber"));
        // BIOS SerialNumber — often same as chassis serial
        parts.AddRange(GetWmiStrings("SELECT SerialNumber FROM Win32_BIOS", "SerialNumber"));
        // MachineGuid — set at Windows install time, survives hardware swaps
        var guid = GetRegistryString(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid", RegistryView.Registry64);
        if (!IsPlaceholder(guid)) parts.Add(guid!);

        if (parts.Count == 0)
        {
            parts.Add(Environment.MachineName);
            parts.Add(Environment.UserDomainName ?? "WORKGROUP");
        }

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("|", parts)));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    /// <summary>
    /// Validates license.nerf. Searches %ProgramData%\EchoNerfados\ first (installed layout),
    /// then beside the EXE (dev/portable layout).
    /// </summary>
    public static LicenseResult Validate()
    {
        var utcNow      = DateTimeOffset.UtcNow;
        var licensePath = s_licenseSearchPaths.FirstOrDefault(File.Exists);

        if (licensePath is null)
            return Fail(LicenseErrorCode.NotFound,
                $"Arquivo de licença não encontrado. Coloque license.nerf em:{Environment.NewLine}" +
                $"  {s_licenseSearchPaths[0]}{Environment.NewLine}" +
                $"  {s_licenseSearchPaths[1]}");

        // Clock rollback check — before anything else
        if (IsClockRolledBack(utcNow))
            return Fail(LicenseErrorCode.ClockRollback,
                "Relógio do sistema foi retrocedido. Verifique data/hora e sincronize com NTP.");

        LicenseData? data;
        try
        {
            var json = File.ReadAllText(licensePath, Encoding.UTF8);
            data = JsonSerializer.Deserialize<LicenseData>(json, s_jsonOpts);
        }
        catch
        {
            return Fail(LicenseErrorCode.ParseError, "Arquivo license.nerf inválido ou corrompido (JSON).");
        }

        if (data is null                            ||
            string.IsNullOrEmpty(data.CustomerId)  ||
            string.IsNullOrEmpty(data.IssuedAt)    ||
            string.IsNullOrEmpty(data.ExpiresAt)   ||
            string.IsNullOrEmpty(data.MachineId)   ||
            string.IsNullOrEmpty(data.MaxVersion)  ||
            string.IsNullOrEmpty(data.Sig))
            return Fail(LicenseErrorCode.ParseError, "Arquivo license.nerf com campos obrigatórios ausentes.");

        // Verify signature first — any field tampering invalidates it
        if (!VerifySignature(CanonicalPayload(data), data.Sig))
            return Fail(LicenseErrorCode.InvalidSignature,
                "Licença adulterada ou inválida. Não edite license.nerf manualmente.");

        if (!DateTimeOffset.TryParse(data.IssuedAt, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var issuedAt) ||
            !DateTimeOffset.TryParse(data.ExpiresAt, null,
                System.Globalization.DateTimeStyles.RoundtripKind, out var expiresAt))
            return Fail(LicenseErrorCode.ParseError, "Datas de licença inválidas em license.nerf.");

        if (utcNow > expiresAt)
            return Fail(LicenseErrorCode.Expired,
                $"Licença expirada em {expiresAt.LocalDateTime:dd/MM/yyyy}. Renove sua licença.");

        // "*" = wildcard / trial (no machine binding)
        if (data.MachineId != "*")
        {
            var myId = ComputeMachineId();
            if (!string.Equals(data.MachineId, myId, StringComparison.OrdinalIgnoreCase))
                return Fail(LicenseErrorCode.WrongMachine,
                    $"Licença não é válida para esta máquina.\nID desta máquina: {myId}");
        }

        // maxVersion: fail closed — invalid format treated as version too high
        var currentVersion = GetAssemblyVersion();
        if (!IsVersionAllowed(currentVersion, data.MaxVersion))
            return Fail(LicenseErrorCode.VersionTooHigh,
                $"Licença não cobre esta versão ({currentVersion}). Versão máxima: {data.MaxVersion}");

        return new LicenseResult(true, License: new LicenseInfo(
            data.CustomerId,
            issuedAt,
            expiresAt,
            data.MachineId,
            data.Features ?? [],
            data.MaxVersion));
    }

    /// <summary>
    /// Records successful validation timestamp (DPAPI-protected, used to detect clock rollback).
    /// Call immediately after a successful Validate().
    /// </summary>
    public static void RecordValidation(DateTimeOffset utcNow)
    {
        try
        {
            Directory.CreateDirectory(s_stateDir);
            var plain = Encoding.UTF8.GetBytes(utcNow.UtcTicks.ToString("D20"));
            var enc   = System.Security.Cryptography.ProtectedData.Protect(
                plain, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
            File.WriteAllBytes(s_statePath, enc);
        }
        catch { }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    // Canonical payload: pipe-separated raw string fields, features sorted.
    // Must match LicenseTool.CanonicalPayload exactly.
    internal static string CanonicalPayload(LicenseData d)
    {
        var features = d.Features is { Length: > 0 }
            ? string.Join(",", d.Features.OrderBy(x => x, StringComparer.Ordinal))
            : "";
        return $"{d.CustomerId}|{d.IssuedAt}|{d.ExpiresAt}|{d.MachineId}|{features}|{d.MaxVersion}";
    }

    private static bool IsClockRolledBack(DateTimeOffset utcNow)
    {
        try
        {
            if (!File.Exists(s_statePath)) return false;
            var enc   = File.ReadAllBytes(s_statePath);
            var plain = System.Security.Cryptography.ProtectedData.Unprotect(
                enc, null, System.Security.Cryptography.DataProtectionScope.LocalMachine);
            var ticks = long.Parse(Encoding.UTF8.GetString(plain).Trim());
            var last  = new DateTimeOffset(ticks, TimeSpan.Zero);
            return utcNow < last.AddMinutes(-ClockToleranceMinutes);
        }
        catch { return false; }
    }

    private static bool VerifySignature(string payload, string sigBase64)
    {
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(EmbeddedPublicKeyPem);
            var payloadBytes = Encoding.UTF8.GetBytes(payload);
            var sigBytes     = Convert.FromBase64String(sigBase64);
            return ecdsa.VerifyData(payloadBytes, sigBytes,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch { return false; }
    }

    private static string GetAssemblyVersion()
    {
        var info = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
        var plus = info.IndexOf('+');
        return plus > 0 ? info[..plus] : info;
    }

    // Fail closed: if maxVersion can't be parsed, it's treated as too restrictive.
    private static bool IsVersionAllowed(string current, string maxVersion)
    {
        if (!Version.TryParse(maxVersion, out var max)) return false;
        if (!Version.TryParse(current,    out var cur)) return true;
        return cur <= max;
    }

    private static List<string> GetWmiStrings(string query, string property)
    {
        var result = new List<string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject obj in searcher.Get())
            {
                var v = obj[property]?.ToString()?.Trim();
                if (!IsPlaceholder(v)) result.Add(v!);
            }
        }
        catch { }
        return result;
    }

    private static string? GetRegistryString(string subKey, string name, RegistryView view = RegistryView.Default)
    {
        try
        {
            using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var key  = hive.OpenSubKey(subKey);
            return key?.GetValue(name)?.ToString();
        }
        catch { return null; }
    }

    private static bool IsPlaceholder(string? v) =>
        string.IsNullOrWhiteSpace(v) || s_placeholders.Contains(v.Trim());

    private static LicenseResult Fail(LicenseErrorCode code, string msg) =>
        new(false, code, msg);

    internal sealed class LicenseData
    {
        public string?   CustomerId { get; set; }
        public string?   IssuedAt   { get; set; }
        public string?   ExpiresAt  { get; set; }
        public string?   MachineId  { get; set; }
        public string[]? Features   { get; set; }
        public string?   MaxVersion { get; set; }
        public string?   Sig        { get; set; }
    }
}
