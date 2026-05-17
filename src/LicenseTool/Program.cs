// Echo Nerfados License Tool — ferramenta interna de emissão de licenças
//
// USO:
//   LicenseTool.exe --generate-keys [--output <dir>]
//       Gera par de chaves ECDSA P-256. Guarde echo_priv.pem em segurança.
//       Cole o conteúdo de echo_pub.pem em LicenseValidator.EmbeddedPublicKeyPem.
//
//   LicenseTool.exe --machine-id
//       Exibe o Machine ID desta máquina (útil para emitir licença para si mesmo).
//
//   LicenseTool.exe --issue
//       --customer  <id>          Ex.: CUST-001
//       --expires   <YYYY-MM-DD>  Data de expiração (UTC)
//       --machine   <id|*>        Machine ID do cliente ("*" = sem binding)
//       --key       <echo_priv.pem>
//       [--features <a,b,c>]      Ex.: deep,br_pack  (padrão: deep)
//       [--max-version <X.Y.Z>]   Versão máxima permitida (padrão: 1.0.0)
//       [--output   <license.nerf>]
//
//   LicenseTool.exe --verify
//       [--license  <license.nerf>]
//       --pub-key   <echo_pub.pem>

using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

if (args.Length == 0) { PrintUsage(); return 1; }

var cmd = args[0].ToLowerInvariant();

return cmd switch
{
    "--generate-keys"          => CmdGenerateKeys(args),
    "--generate-manifest-keys" => CmdGenerateManifestKeys(args),
    "--machine-id"             => CmdMachineId(),
    "--issue"                  => CmdIssue(args),
    "--verify"                 => CmdVerify(args),
    "--sign-manifest"          => CmdSignManifest(args),
    "--help" or "-h"           => Help(),
    _                          => Unknown(args[0])
};

static int Help()    { PrintUsage(); return 0; }
static int Unknown(string c) { Console.Error.WriteLine($"Comando desconhecido: {c}"); return 1; }

// ── --generate-keys ───────────────────────────────────────────────────────────

static int CmdGenerateKeys(string[] args)
{
    var outputDir = ".";
    for (int i = 1; i < args.Length - 1; i++)
        if (args[i] == "--output") outputDir = args[i + 1];

    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var pubPem  = BuildPem("PUBLIC KEY",  ecdsa.ExportSubjectPublicKeyInfo());
    var privPem = BuildPem("PRIVATE KEY", ecdsa.ExportPkcs8PrivateKey());

    Directory.CreateDirectory(outputDir);
    var pubPath  = Path.Combine(outputDir, "echo_pub.pem");
    var privPath = Path.Combine(outputDir, "echo_priv.pem");
    File.WriteAllText(pubPath,  pubPem,  Encoding.ASCII);
    File.WriteAllText(privPath, privPem, Encoding.ASCII);

    Console.WriteLine($"Chaves salvas:");
    Console.WriteLine($"  Pública : {Path.GetFullPath(pubPath)}");
    Console.WriteLine($"  Privada : {Path.GetFullPath(privPath)}");
    Console.WriteLine();
    Console.WriteLine("ATENÇÃO: mantenha echo_priv.pem em segurança absoluta.");
    Console.WriteLine("Cole o conteúdo de echo_pub.pem em LicenseValidator.EmbeddedPublicKeyPem.");
    Console.WriteLine();
    Console.WriteLine("=== echo_pub.pem ===");
    Console.WriteLine(pubPem);
    return 0;
}

// ── --generate-manifest-keys ──────────────────────────────────────────────────

static int CmdGenerateManifestKeys(string[] args)
{
    var outputDir = ".";
    for (int i = 1; i < args.Length - 1; i++)
        if (args[i] == "--output") outputDir = args[i + 1];

    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var pubPem  = BuildPem("PUBLIC KEY",  ecdsa.ExportSubjectPublicKeyInfo());
    var privPem = BuildPem("PRIVATE KEY", ecdsa.ExportPkcs8PrivateKey());

    Directory.CreateDirectory(outputDir);
    var pubPath  = Path.Combine(outputDir, "echo_manifest_pub.pem");
    var privPath = Path.Combine(outputDir, "echo_manifest_priv.pem");
    File.WriteAllText(pubPath,  pubPem,  Encoding.ASCII);
    File.WriteAllText(privPath, privPem, Encoding.ASCII);

    Console.WriteLine("Manifest signing keypair saved:");
    Console.WriteLine($"  Public  : {Path.GetFullPath(pubPath)}");
    Console.WriteLine($"  Private : {Path.GetFullPath(privPath)}");
    Console.WriteLine();
    Console.WriteLine("ATENÇÃO: mantenha echo_manifest_priv.pem em segurança.");
    Console.WriteLine("  - Para assinar automaticamente no scan: coloque ao lado de EchoNerfados.exe");
    Console.WriteLine("  - Para assinar manualmente pos-scan:   LicenseTool.exe --sign-manifest <pasta> --key echo_manifest_priv.pem");
    Console.WriteLine("  - Atualize ManifestSigner.EmbeddedPublicKeyPem com o conteudo abaixo e recompile.");
    Console.WriteLine();
    Console.WriteLine("=== echo_manifest_pub.pem ===");
    Console.WriteLine(pubPem);
    return 0;
}

// ── --sign-manifest ───────────────────────────────────────────────────────────

static int CmdSignManifest(string[] args)
{
    string? reportDir = null;
    string? keyPath   = null;

    for (int i = 1; i < args.Length; i++)
        switch (args[i])
        {
            case "--key"    when i + 1 < args.Length: keyPath   = args[++i]; break;
            case "--output" when i + 1 < args.Length: reportDir = args[++i]; break;
            default:
                if (!args[i].StartsWith("--") && reportDir is null) reportDir = args[i];
                break;
        }

    reportDir ??= ".";
    var manifestPath = Path.Combine(reportDir, "manifest.json");

    if (keyPath is null)    { Console.Error.WriteLine("--sign-manifest requer --key <echo_manifest_priv.pem>"); return 1; }
    if (!File.Exists(keyPath))     { Console.Error.WriteLine($"Chave privada nao encontrada: {keyPath}"); return 1; }
    if (!File.Exists(manifestPath)){ Console.Error.WriteLine($"manifest.json nao encontrado em: {reportDir}"); return 1; }

    try
    {
        var manifestBytes = File.ReadAllBytes(manifestPath);
        var hash          = System.Security.Cryptography.SHA256.HashData(manifestBytes);

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(File.ReadAllText(keyPath, Encoding.ASCII));

        var sig     = ecdsa.SignHash(hash, System.Security.Cryptography.DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var sigPath = Path.Combine(reportDir, "manifest.sig");
        File.WriteAllText(sigPath, Convert.ToBase64String(sig), Encoding.ASCII);

        Console.WriteLine($"manifest.sig gerado: {Path.GetFullPath(sigPath)}");
        Console.WriteLine($"  Manifest SHA256: {Convert.ToHexString(hash).ToLowerInvariant()}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Erro ao assinar manifesto: {ex.Message}");
        return 1;
    }
}

// ── --machine-id ──────────────────────────────────────────────────────────────

static int CmdMachineId()
{
    Console.WriteLine(ComputeMachineId());
    return 0;
}

// ── --issue ───────────────────────────────────────────────────────────────────

static int CmdIssue(string[] args)
{
    string? customer = null, expires = null, machine = null, keyPath = null;
    string  features   = "deep";
    string  maxVersion = "1.0.0";
    string  output     = "license.nerf";

    for (int i = 1; i < args.Length - 1; i++)
        switch (args[i])
        {
            case "--customer":    customer   = args[++i]; break;
            case "--expires":     expires    = args[++i]; break;
            case "--machine":     machine    = args[++i]; break;
            case "--key":         keyPath    = args[++i]; break;
            case "--features":    features   = args[++i]; break;
            case "--max-version": maxVersion = args[++i]; break;
            case "--output":      output     = args[++i]; break;
        }

    if (customer is null || expires is null || machine is null || keyPath is null)
    {
        Console.Error.WriteLine("--issue requer: --customer, --expires, --machine, --key");
        return 1;
    }

    if (!DateTimeOffset.TryParse(expires, out var expiresAt))
    {
        Console.Error.WriteLine($"Data inválida: {expires} (use YYYY-MM-DD)");
        return 1;
    }

    if (!Version.TryParse(maxVersion, out _))
    {
        Console.Error.WriteLine($"--max-version inválida: '{maxVersion}' — use formato X.Y ou X.Y.Z");
        return 1;
    }

    if (!File.Exists(keyPath))
    {
        Console.Error.WriteLine($"Chave privada não encontrada: {keyPath}");
        return 1;
    }

    var issuedAtStr  = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
    var expiresAtStr = new DateTimeOffset(expiresAt.Date.AddHours(23).AddMinutes(59).AddSeconds(59), TimeSpan.Zero)
                           .ToString("yyyy-MM-ddTHH:mm:ssZ");

    var featureArray = features.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    Array.Sort(featureArray, StringComparer.Ordinal);

    // Build canonical payload and sign
    var payload = CanonicalPayload(customer, issuedAtStr, expiresAtStr, machine, featureArray, maxVersion);

    string sigBase64;
    try
    {
        var privPem = File.ReadAllText(keyPath, Encoding.ASCII);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(privPem);
        var sigBytes = ecdsa.SignData(Encoding.UTF8.GetBytes(payload),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        sigBase64 = Convert.ToBase64String(sigBytes);
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Erro ao assinar: {ex.Message}");
        return 1;
    }

    var license = new LicenseFile
    {
        CustomerId = customer,
        IssuedAt   = issuedAtStr,
        ExpiresAt  = expiresAtStr,
        MachineId  = machine,
        Features   = featureArray,
        MaxVersion = maxVersion,
        Sig        = sigBase64
    };

    var json = JsonSerializer.Serialize(license, new JsonSerializerOptions
    {
        WriteIndented         = true,
        PropertyNamingPolicy  = JsonNamingPolicy.CamelCase
    });

    File.WriteAllText(output, json, Encoding.UTF8);
    Console.WriteLine($"Licença emitida: {Path.GetFullPath(output)}");
    Console.WriteLine($"  Cliente    : {customer}");
    Console.WriteLine($"  Emitida em : {issuedAtStr}");
    Console.WriteLine($"  Expira em  : {expiresAtStr}");
    Console.WriteLine($"  Machine ID : {machine}");
    Console.WriteLine($"  Features   : {string.Join(", ", featureArray)}");
    Console.WriteLine($"  Max version: {maxVersion}");
    Console.WriteLine($"  Payload    : {payload}");
    return 0;
}

// ── --verify ──────────────────────────────────────────────────────────────────

static int CmdVerify(string[] args)
{
    string licPath  = "license.nerf";
    string? pubPath = null;

    for (int i = 1; i < args.Length - 1; i++)
        switch (args[i])
        {
            case "--license": licPath = args[++i]; break;
            case "--pub-key": pubPath = args[++i]; break;
        }

    if (pubPath is null) { Console.Error.WriteLine("--verify requer --pub-key"); return 1; }
    if (!File.Exists(licPath))  { Console.Error.WriteLine($"License não encontrada: {licPath}"); return 1; }
    if (!File.Exists(pubPath))  { Console.Error.WriteLine($"Chave pública não encontrada: {pubPath}"); return 1; }

    LicenseFile? lic;
    try
    {
        lic = JsonSerializer.Deserialize<LicenseFile>(
            File.ReadAllText(licPath), new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
    catch { Console.Error.WriteLine("Falha ao parsear license.nerf"); return 1; }

    if (lic?.CustomerId is null || lic.IssuedAt is null || lic.ExpiresAt is null ||
        lic.MachineId is null   || lic.MaxVersion is null || lic.Sig is null)
    { Console.Error.WriteLine("Campos ausentes no license.nerf"); return 1; }

    var payload = CanonicalPayload(lic.CustomerId, lic.IssuedAt, lic.ExpiresAt,
        lic.MachineId, lic.Features ?? [], lic.MaxVersion);

    try
    {
        var pubPem = File.ReadAllText(pubPath, Encoding.ASCII);
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pubPem);
        var sigBytes = Convert.FromBase64String(lic.Sig);
        var ok = ecdsa.VerifyData(Encoding.UTF8.GetBytes(payload),
            sigBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        if (ok)
        {
            Console.WriteLine("ASSINATURA VÁLIDA");
            Console.WriteLine($"  Cliente    : {lic.CustomerId}");
            Console.WriteLine($"  Expira em  : {lic.ExpiresAt}");
            Console.WriteLine($"  Machine ID : {lic.MachineId}");
            return 0;
        }
        else
        {
            Console.Error.WriteLine("ASSINATURA INVÁLIDA — arquivo adulterado ou chave errada");
            return 2;
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Erro na verificação: {ex.Message}");
        return 1;
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

static string CanonicalPayload(string customerId, string issuedAt, string expiresAt,
    string machineId, string[] features, string maxVersion)
{
    // Must match LicenseValidator.CanonicalPayload exactly.
    var featStr = features.Length > 0
        ? string.Join(",", features.OrderBy(x => x, StringComparer.Ordinal))
        : "";
    return $"{customerId}|{issuedAt}|{expiresAt}|{machineId}|{featStr}|{maxVersion}";
}

static string ComputeMachineId()
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

    var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash)[..16].ToLowerInvariant();
}

static string BuildPem(string label, byte[] data) =>
    $"-----BEGIN {label}-----\n" +
    Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks) +
    $"\n-----END {label}-----";

static void PrintUsage()
{
    Console.WriteLine("Echo Nerfados License Tool");
    Console.WriteLine();
    Console.WriteLine("COMANDOS:");
    Console.WriteLine("  --generate-keys [--output <dir>]");
    Console.WriteLine("      Gera par de chaves ECDSA P-256 para licencas (echo_pub.pem + echo_priv.pem)");
    Console.WriteLine();
    Console.WriteLine("  --generate-manifest-keys [--output <dir>]");
    Console.WriteLine("      Gera par de chaves ECDSA P-256 para assinar manifestos de relatorio");
    Console.WriteLine("      (echo_manifest_pub.pem + echo_manifest_priv.pem)");
    Console.WriteLine();
    Console.WriteLine("  --machine-id");
    Console.WriteLine("      Exibe Machine ID desta maquina");
    Console.WriteLine();
    Console.WriteLine("  --issue --customer <id> --expires <YYYY-MM-DD> --machine <id|*> --key <priv.pem>");
    Console.WriteLine("      [--features <a,b>] [--max-version <X.Y.Z>] [--output <license.nerf>]");
    Console.WriteLine("      Emite license.nerf assinado");
    Console.WriteLine();
    Console.WriteLine("  --verify --pub-key <pub.pem> [--license <license.nerf>]");
    Console.WriteLine("      Verifica assinatura de license.nerf");
    Console.WriteLine();
    Console.WriteLine("  --sign-manifest <pasta> --key <echo_manifest_priv.pem>");
    Console.WriteLine("      Assina manifest.json de um relatorio, gerando manifest.sig");
    Console.WriteLine("      (alternativa ao TrySign automatico do scan, para fluxos offline)");
}

// ── DTOs ──────────────────────────────────────────────────────────────────────

internal sealed class LicenseFile
{
    [JsonPropertyName("customerId")] public string?   CustomerId { get; set; }
    [JsonPropertyName("issuedAt")]   public string?   IssuedAt   { get; set; }
    [JsonPropertyName("expiresAt")]  public string?   ExpiresAt  { get; set; }
    [JsonPropertyName("machineId")]  public string?   MachineId  { get; set; }
    [JsonPropertyName("features")]   public string[]? Features   { get; set; }
    [JsonPropertyName("maxVersion")] public string?   MaxVersion { get; set; }
    [JsonPropertyName("sig")]        public string?   Sig        { get; set; }
}
