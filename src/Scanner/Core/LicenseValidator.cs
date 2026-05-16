using System.Management;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BypassNerfados.Scanner.Core;

public enum LicenseErrorCode
{
    None,
    NotFound,
    ParseError,
    InvalidSignature,
    Expired,
    WrongMachine,
    VersionTooHigh
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

    /// <summary>
    /// Returns a stable 16-hex-char machine ID derived from CPU + motherboard serial numbers.
    /// </summary>
    public static string ComputeMachineId()
    {
        string cpuId = "", boardSerial = "";
        try
        {
            using var cpu = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
            cpuId = cpu.Get().Cast<ManagementObject>()
                .Select(o => o["ProcessorId"]?.ToString()?.Trim())
                .FirstOrDefault(s => !string.IsNullOrEmpty(s)) ?? "";
        }
        catch { }
        try
        {
            using var board = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
            boardSerial = board.Get().Cast<ManagementObject>()
                .Select(o => o["SerialNumber"]?.ToString()?.Trim())
                .FirstOrDefault(s => !string.IsNullOrEmpty(s) && s != "To be filled by O.E.M.") ?? "";
        }
        catch { }

        var raw = string.IsNullOrEmpty(cpuId) && string.IsNullOrEmpty(boardSerial)
            ? Environment.MachineName + "|" + Environment.UserDomainName
            : cpuId + "|" + boardSerial;

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    /// <summary>
    /// Validates license.nerf beside the EXE. Returns <see cref="LicenseResult.Success"/> == true if valid.
    /// </summary>
    public static LicenseResult Validate()
    {
        var licensePath = Path.Combine(AppContext.BaseDirectory, "license.nerf");

        if (!File.Exists(licensePath))
            return Fail(LicenseErrorCode.NotFound,
                "Arquivo de licença não encontrado. Coloque license.nerf ao lado do EXE.");

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

        if (DateTimeOffset.UtcNow > expiresAt)
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

    // Canonical payload: pipe-separated raw string fields, features sorted.
    // Must match LicenseTool.CanonicalPayload exactly.
    internal static string CanonicalPayload(LicenseData d)
    {
        var features = d.Features is { Length: > 0 }
            ? string.Join(",", d.Features.OrderBy(x => x, StringComparer.Ordinal))
            : "";
        return $"{d.CustomerId}|{d.IssuedAt}|{d.ExpiresAt}|{d.MachineId}|{features}|{d.MaxVersion}";
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

    private static bool IsVersionAllowed(string current, string maxVersion)
    {
        if (!Version.TryParse(current, out var cur) || !Version.TryParse(maxVersion, out var max))
            return true;
        return cur <= max;
    }

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
