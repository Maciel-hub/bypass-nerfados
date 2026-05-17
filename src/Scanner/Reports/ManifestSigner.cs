using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BypassNerfados.Scanner.Reports;

public static class ManifestSigner
{
    // ECDSA P-256 public key for manifest signature verification.
    // Kept separate from the license public key (different purpose).
    // Bootstrap value shares the Sprint-3 license keypair so QA can proceed
    // without a second keygen step. For production, generate a dedicated pair:
    //   LicenseTool.exe --generate-manifest-keys
    // Then paste echo_manifest_pub.pem here and recompile.
    private const string EmbeddedPublicKeyPem =
        "-----BEGIN PUBLIC KEY-----\n" +
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH5NATMD4Ogyg2aQQ+yv/P/Dsdvyc\n" +
        "ZiJqyHQn19tS8h6jslWfDIPXUdEguigs9X9207vlktpNepBwfKCXQgdGpQ==\n" +
        "-----END PUBLIC KEY-----";

    private const string PrivKeyFileName = "echo_manifest_priv.pem";

    // Sign manifest.json using private key beside the EXE (if present).
    // Non-fatal: if the key file is absent the report is still complete, just unsigned.
    public static bool TrySign(string manifestJsonPath)
    {
        var privKeyPath = FindPrivKeyPath();
        if (privKeyPath is null) return false;

        try
        {
            var manifestBytes = File.ReadAllBytes(manifestJsonPath);
            var hash = SHA256.HashData(manifestBytes);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(File.ReadAllText(privKeyPath, Encoding.ASCII));

            var sig     = ecdsa.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var sigPath = Path.Combine(Path.GetDirectoryName(manifestJsonPath)!, "manifest.sig");
            File.WriteAllText(sigPath, Convert.ToBase64String(sig), Encoding.ASCII);
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ManifestSigner] Warning: signing failed: {ex.Message}");
            return false;
        }
    }

    // Sign manifest.json using an explicitly supplied private key path.
    // Used by LicenseTool --sign-manifest for post-scan / offline signing workflows.
    public static bool SignWithKey(string manifestJsonPath, string privKeyPath)
    {
        try
        {
            var manifestBytes = File.ReadAllBytes(manifestJsonPath);
            var hash = SHA256.HashData(manifestBytes);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(File.ReadAllText(privKeyPath, Encoding.ASCII));

            var sig     = ecdsa.SignHash(hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var sigPath = Path.Combine(Path.GetDirectoryName(manifestJsonPath)!, "manifest.sig");
            File.WriteAllText(sigPath, Convert.ToBase64String(sig), Encoding.ASCII);
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ManifestSigner] Signing failed: {ex.Message}");
            return false;
        }
    }

    // pubKeyPem: if null or empty, the embedded key is used.
    // Pass an explicit PEM to verify against a freshly-generated keypair without recompiling.
    public static ManifestVerifyResult Verify(string reportDir, string? pubKeyPem = null)
    {
        var effectivePubKey = string.IsNullOrWhiteSpace(pubKeyPem)
            ? EmbeddedPublicKeyPem
            : pubKeyPem;

        var manifestPath = Path.Combine(reportDir, "manifest.json");
        var sha256Path   = Path.Combine(reportDir, "manifest.sha256");
        var sigPath      = Path.Combine(reportDir, "manifest.sig");

        if (!File.Exists(manifestPath))
            return ManifestVerifyResult.Fail($"manifest.json not found in: {reportDir}");

        // 1. Verify manifest.sha256 matches manifest.json
        var actualHash = HashFile(manifestPath);
        if (File.Exists(sha256Path))
        {
            var expectedHash = ParseSha256Line(sha256Path);
            if (expectedHash != null &&
                !string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                return ManifestVerifyResult.Fail("manifest.sha256 mismatch — manifest.json was modified");
        }

        // 2. Verify ECDSA signature (if present)
        bool? sigValid = null;
        if (File.Exists(sigPath))
        {
            try
            {
                var manifestBytes = File.ReadAllBytes(manifestPath);
                var hash = SHA256.HashData(manifestBytes);
                var sig  = Convert.FromBase64String(File.ReadAllText(sigPath, Encoding.ASCII).Trim());

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(effectivePubKey);
                sigValid = ecdsa.VerifyHash(hash, sig, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch
            {
                sigValid = false;
            }

            if (sigValid == false)
                return ManifestVerifyResult.Fail(
                    "manifest.sig is INVALID — manifest was tampered or signed with a different key");
        }

        // 3. Verify each file hash listed in manifest.json
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
            if (doc.RootElement.TryGetProperty("files", out var filesEl))
            {
                foreach (var entry in filesEl.EnumerateObject())
                {
                    if (!entry.Value.TryGetProperty("sha256", out var sha256El)) continue;
                    var expectedFileSha = sha256El.GetString();
                    if (expectedFileSha is null) continue;

                    var filePath = Path.Combine(reportDir, entry.Name);
                    if (!File.Exists(filePath))
                        return ManifestVerifyResult.Fail($"File listed in manifest is missing: {entry.Name}");

                    var actualFileSha = HashFile(filePath);
                    if (!string.Equals(actualFileSha, expectedFileSha, StringComparison.OrdinalIgnoreCase))
                        return ManifestVerifyResult.Fail(
                            $"Hash mismatch: {entry.Name} — file was modified after scan");
                }
            }
        }
        catch (Exception ex)
        {
            return ManifestVerifyResult.Fail($"Failed to parse manifest.json: {ex.Message}");
        }

        var message = sigValid == true
            ? "VERIFIED — manifest and all report files are intact and cryptographically signed"
            : "VERIFIED (unsigned) — manifest and all report files are intact; no manifest.sig present";

        return new ManifestVerifyResult(true, message, sigValid == true, actualHash);
    }

    private static string HashFile(string path)
    {
        using var sha = SHA256.Create();
        using var fs  = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    private static string? ParseSha256Line(string sha256FilePath)
    {
        // sha256sum format: "<hex>  <filename>\n"
        var line = File.ReadAllText(sha256FilePath, Encoding.UTF8).Trim();
        var idx  = line.IndexOf(' ');
        return idx > 0 ? line[..idx] : null;
    }

    private static string? FindPrivKeyPath()
    {
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? ".";
        var p1 = Path.Combine(exeDir, PrivKeyFileName);
        if (File.Exists(p1)) return p1;
        var p2 = Path.Combine(Directory.GetCurrentDirectory(), PrivKeyFileName);
        if (File.Exists(p2)) return p2;
        return null;
    }
}

public sealed record ManifestVerifyResult(bool Ok, string Message, bool Signed, string ManifestHash)
{
    public static ManifestVerifyResult Fail(string msg) => new(false, msg, false, "");
}
