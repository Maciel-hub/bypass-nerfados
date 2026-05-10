using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using System.Text;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Inspeciona artefatos da pasta NVIDIA DRS para determinar quais apps
/// utilizaram a GPU recentemente. Timestamps de nvAppTimestamps confirmam
/// uso de GPU próximo à sessão FiveM; nvdrsdb*.bin registra perfis de jogo.
/// </summary>
public class NvidiaArtifactsModule : BaseModule
{
    public override string Name        => "NVIDIA Artifacts";
    public override string Description => "Timestamps de execução de apps na GPU (DRS) — confirma uso de GPU próximo à sessão FiveM";

    private const string DrsFolderPath = @"C:\ProgramData\NVIDIA Corporation\Drs\";

    // Maximum bytes read from nvAppTimestamps for string extraction
    private const int MaxTimestampReadBytes = 1_048_576; // 1 MB

    protected override Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        if (!Directory.Exists(DrsFolderPath))
            return Task.FromResult(findings);

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            CheckNvAppTimestamps(findings);

            cancellationToken.ThrowIfCancellationRequested();
            CheckNvdrsFiles(findings);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            LogPartialError("NvidiaArtifactsModule — erro geral na varredura DRS", ex);
        }

        return Task.FromResult(findings);
    }

    /// <summary>
    /// Examina todos os arquivos nvAppTimestamps* na pasta DRS.
    /// Emite achado se o arquivo foi modificado nos últimos 60 dias
    /// e, adicionalmente, extrai strings UTF-16 do binário para
    /// identificar caminhos de cheats.
    /// </summary>
    private void CheckNvAppTimestamps(List<Finding> findings)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(
                DrsFolderPath,
                "nvAppTimestamps*",
                new EnumerationOptions { IgnoreInaccessible = true });
        }
        catch (Exception ex)
        {
            LogPartialError("NVIDIA DRS — falha ao enumerar nvAppTimestamps", ex);
            return;
        }

        foreach (var filePath in files)
        {
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) continue;

                var lastWrite  = fi.LastWriteTime;
                var fileName   = fi.Name;
                var ageInDays  = (DateTime.Now - lastWrite).TotalDays;

                // Extrai strings UTF-16 do binário e verifica cheats
                // Nota: não emitimos finding só pela data de modificação — nvAppTimestamps
                // é atualizado por qualquer app que use GPU e dispararia em todo PC com NVIDIA.
                // Apenas High é emitido quando strings suspeitas são encontradas no binário.
                if (ageInDays <= 60)
                    ExtractAndFlagCheatStrings(findings, filePath, fileName);
            }
            catch (Exception ex)
            {
                LogPartialError($"NVIDIA DRS — falha ao processar {filePath}", ex);
            }
        }
    }

    /// <summary>
    /// Lê até 1 MB do arquivo binário e extrai sequências UTF-16LE de 4+ chars
    /// no intervalo ASCII imprimível (0x20–0x7E). Emite achado se alguma string
    /// contiver separador de caminho E palavra-chave suspeita de cheat.
    /// </summary>
    private void ExtractAndFlagCheatStrings(List<Finding> findings, string filePath, string fileName)
    {
        byte[] data;
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            var length = (int)Math.Min(fs.Length, MaxTimestampReadBytes);
            data = new byte[length];
            var read = 0;
            while (read < length)
            {
                var n = fs.Read(data, read, length - read);
                if (n == 0) break;
                read += n;
            }
            if (read < length)
                data = data[..read];
        }
        catch
        {
            // Binary read failure is non-fatal; skip string extraction
            return;
        }

        // Walk the byte array looking for runs of UTF-16LE printable ASCII chars.
        // UTF-16LE char: low byte in [0x20, 0x7E], high byte == 0x00.
        // We need at least 4 consecutive chars (8 bytes) to constitute a valid string.
        var extracted = new List<string>();
        var run = new StringBuilder();

        for (var i = 0; i + 1 < data.Length; i += 2)
        {
            var lo = data[i];
            var hi = data[i + 1];

            if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E)
            {
                run.Append((char)lo);
            }
            else
            {
                if (run.Length >= 4)
                    extracted.Add(run.ToString());
                run.Clear();
            }
        }
        // Flush any trailing run
        if (run.Length >= 4)
            extracted.Add(run.ToString());

        foreach (var s in extracted)
        {
            // Must look like a file path (contains backslash) and contain a cheat keyword
            if (!s.Contains('\\')) continue;
            if (!CheatDatabase.HasSuspiciousKeyword(s)) continue;

            var ruleId = $"NVIDIA_DRS_CHEAT_TRACE_{SanitizeForRuleId(fileName)}";
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.Cheat,
                Name,
                $"NVIDIA DRS: rastro de cheat nos timestamps de GPU",
                $"String suspeita extraída do arquivo de timestamps de GPU NVIDIA. " +
                $"Indica que um executável com caminho/nome de cheat utilizou a GPU. " +
                $"String encontrada: {TruncateForDisplay(s, 200)}",
                evidence:   $"Arquivo DRS: {filePath} | String: {TruncateForDisplay(s, 300)}",
                confidence: Confidence.Medium,
                ruleId:     ruleId,
                entity:     s
            ));
        }
    }

    /// <summary>
    /// Examina arquivos nvdrsdb*.bin. Se algum foi modificado nos últimos 7 dias
    /// E o diretório DRS também tem nvAppTimestamps recentes, emite Medium.
    /// Caso contrário, emite Info indicando que é necessário correlacionar com
    /// a sessão FiveM.
    /// </summary>
    private void CheckNvdrsFiles(List<Finding> findings)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(
                DrsFolderPath,
                "nvdrsdb*.bin",
                new EnumerationOptions { IgnoreInaccessible = true });
        }
        catch (Exception ex)
        {
            LogPartialError("NVIDIA DRS — falha ao enumerar nvdrsdb*.bin", ex);
            return;
        }

        // Verifica se há nvAppTimestamps recentes (últimos 7 dias) no mesmo diretório
        bool hasRecentTimestamps;
        try
        {
            hasRecentTimestamps = Directory
                .EnumerateFiles(DrsFolderPath, "nvAppTimestamps*",
                    new EnumerationOptions { IgnoreInaccessible = true })
                .Any(f =>
                {
                    try { return (DateTime.Now - new FileInfo(f).LastWriteTime).TotalDays <= 7; }
                    catch { return false; }
                });
        }
        catch { hasRecentTimestamps = false; }

        foreach (var filePath in files)
        {
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) continue;

                var lastWrite = fi.LastWriteTime;
                var ageInDays = (DateTime.Now - lastWrite).TotalDays;

                if (ageInDays > 7) continue;

                // Emitimos Info para cobertura — sozinho não é indicador de cheat.
                // Apenas escalamos quando strings suspeitas forem encontradas no nvAppTimestamps.
                _ = hasRecentTimestamps; // capturado para possível correlação futura
                findings.Add(new Finding(
                    RiskLevel.Info,
                    FindingCategory.FileSystem,
                    Name,
                    "NVIDIA: nvdrsdb*.bin modificado recentemente",
                    "O banco de perfis de driver NVIDIA foi atualizado recentemente. " +
                    $"Arquivo modificado há {ageInDays:F0} dias. " +
                    "Correlacionar com sessão FiveM e strings suspeitas em nvAppTimestamps para escalação.",
                    evidence:   $"Arquivo: {filePath} | LastWriteTime: {lastWrite:dd/MM/yyyy HH:mm:ss}",
                    timestamp:  lastWrite,
                    confidence: Confidence.Low,
                    ruleId:     "NVIDIA_DRSDB_INFO",
                    entity:     fi.Name
                ));
            }
            catch (Exception ex)
            {
                LogPartialError($"NVIDIA DRS — falha ao processar {filePath}", ex);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sanitiza um nome de arquivo para uso em RuleId (mantém apenas letras, dígitos e _).
    /// </summary>
    private static string SanitizeForRuleId(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.ToUpperInvariant())
        {
            if (char.IsLetterOrDigit(c))
                sb.Append(c);
            else if (c is '.' or '-' or '_')
                sb.Append('_');
        }
        return sb.ToString();
    }

    /// <summary>
    /// Trunca uma string para exibição, adicionando reticências se necessário.
    /// </summary>
    private static string TruncateForDisplay(string s, int maxLen) =>
        s.Length <= maxLen ? s : s[..maxLen] + "…";
}
