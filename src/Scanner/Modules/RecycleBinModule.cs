using Microsoft.Win32;
using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using System.Text;

namespace BypassNerfados.Scanner.Modules;

/// <summary>
/// Analisa os metadados dos arquivos $I da Lixeira do Windows para recuperar
/// o caminho original e a data de deleção de cada item removido nos últimos 60 dias.
/// Arquivos deletados com nomes ou caminhos de cheat indicam possível tentativa
/// de remoção de evidências.
/// </summary>
public class RecycleBinModule : BaseModule
{
    public override string Name        => "Recycle Bin";
    public override string Description => "Arquivos deletados — caminho original e data de deleção via $I (60 dias)";

    private const string RecycleBinRoot = @"C:\$RECYCLE.BIN\";
    private const int    LookbackDays   = 60;

    // Extensões executáveis que disparam análise por caminho suspeito
    private static readonly HashSet<string> ExecutableExtensions =
        new(StringComparer.OrdinalIgnoreCase) { ".exe", ".dll", ".bat", ".ps1" };

    private const string ValidationHintText =
        "Correlacionar com Amcache/Prefetch/ShimCache para confirmar execução antes da deleção";

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        if (!Directory.Exists(RecycleBinRoot))
            return findings;

        IEnumerable<string> sidDirs;
        try
        {
            sidDirs = Directory.EnumerateDirectories(
                RecycleBinRoot,
                "*",
                new EnumerationOptions { IgnoreInaccessible = true });
        }
        catch (Exception ex)
        {
            LogPartialError("RecycleBin — falha ao enumerar diretórios SID", ex);
            return findings;
        }

        var cutoff = DateTime.Now.AddDays(-LookbackDays);

        foreach (var sidDir in sidDirs)
        {
            ct.ThrowIfCancellationRequested();
            ProcessSidDirectory(findings, sidDir, cutoff, ct);
        }

        await Task.CompletedTask; // mantém assinatura async sem overhead
        return findings;
    }

    /// <summary>
    /// Processa todos os arquivos $I dentro de um único diretório SID.
    /// Erros de acesso ao diretório são registrados como partial error.
    /// </summary>
    private void ProcessSidDirectory(
        List<Finding> findings, string sidDir, DateTime cutoff, CancellationToken ct)
    {
        IEnumerable<string> iFiles;
        try
        {
            iFiles = Directory.EnumerateFiles(
                sidDir,
                "$I*",
                new EnumerationOptions { IgnoreInaccessible = true });
        }
        catch (Exception ex)
        {
            LogPartialError($"RecycleBin — acesso negado ao diretório {sidDir}", ex);
            return;
        }

        foreach (var iFile in iFiles)
        {
            ct.ThrowIfCancellationRequested();

            try
            {
                var data = File.ReadAllBytes(iFile);
                var parsed = ParseIFile(data);
                if (parsed == null) continue;

                var (originalPath, deletionTime, fileSize) = parsed.Value;
                if (string.IsNullOrWhiteSpace(originalPath)) continue;

                // Filtrar por janela de 60 dias (null passa para não excluir por data)
                if (deletionTime.HasValue && deletionTime.Value < cutoff) continue;

                EvaluatePath(findings, originalPath, deletionTime, fileSize);
            }
            catch
            {
                // Arquivos $I malformados são silenciosamente ignorados (corrupção ou formato desconhecido)
            }
        }
    }

    // ── Parser de arquivo $I ──────────────────────────────────────────────────────

    /// <summary>
    /// Interpreta o conteúdo binário de um arquivo $I da Lixeira do Windows.
    ///
    /// Formato:
    ///   [0..7]   int64  versão (1 = Vista/7/8.1 | 2 = Win10/11)
    ///   [8..15]  int64  tamanho original do arquivo
    ///   [16..23] int64  FILETIME da deleção
    ///
    ///   Versão 2:
    ///     [24..27] int32  número de chars do caminho
    ///     [28..]   UTF-16LE caminho (charCount * 2 bytes)
    ///
    ///   Versão 1 (e qualquer outra):
    ///     [24..]   UTF-16LE caminho com terminador nulo (até 520 bytes = 260 chars)
    ///
    /// Retorna null se o buffer for muito curto ou o caminho não puder ser extraído.
    /// </summary>
    private (string path, DateTime? deletionTime, long fileSize)? ParseIFile(byte[] data)
    {
        if (data.Length < 28) return null;

        var version      = BitConverter.ToInt64(data, 0);
        var fileSize     = BitConverter.ToInt64(data, 8);
        var fileTimeTicks = BitConverter.ToInt64(data, 16);
        var deletionTime = FileTimeToDateTime(fileTimeTicks);

        string path;

        if (version == 2)
        {
            // Versão 2 (Win10/11): int32 charCount em [24..27], seguido pelo caminho
            var charCount = BitConverter.ToInt32(data, 24);
            if (charCount <= 0) return null;

            var byteCount = charCount * 2;
            if (28 + byteCount > data.Length) return null;

            path = Encoding.Unicode.GetString(data, 28, byteCount);
        }
        else
        {
            // Versão 1 (Vista/7/8.1) e fallback: UTF-16LE terminado em nulo a partir de [24]
            if (data.Length <= 24) return null;

            path = Encoding.Unicode
                .GetString(data, 24, data.Length - 24)
                .Split('\0')[0]; // termina no primeiro nulo
        }

        path = path.Trim();
        return string.IsNullOrEmpty(path) ? null : (path, deletionTime, fileSize);
    }

    // ── Lógica de detecção ────────────────────────────────────────────────────────

    /// <summary>
    /// Aplica as regras de detecção ao caminho original recuperado do $I.
    /// Prioridade: cheat conhecido > palavra-chave suspeita > caminho executável suspeito.
    /// </summary>
    private void EvaluatePath(
        List<Finding> findings,
        string originalPath,
        DateTime? deletionTime,
        long fileSize)
    {
        if (IsOwnProcess(originalPath)) return;

        var fileName  = Path.GetFileName(originalPath).ToLowerInvariant();
        var extension = Path.GetExtension(originalPath).ToLowerInvariant();

        if (CheatDatabase.IsKnownLegitimate(originalPath)) return;

        // 1. Cheat com correspondência exata e credível
        var cheatInfo = CheatDatabase.TryGetCredibleCheat(fileName, originalPath);
        if (cheatInfo != null)
        {
            findings.Add(BuildFinding(
                RiskLevel.High,
                FindingCategory.Cheat,
                $"[DELETADO] RECYCLE BIN: Arquivo de cheat deletado: {cheatInfo.Name}",
                $"Arquivo de cheat identificado na Lixeira — forte indício de remoção de evidências. " +
                $"Cheat: {cheatInfo.Name}. {cheatInfo.Description}",
                originalPath, deletionTime, fileSize,
                Confidence.High,
                $"RECYCLEBIN_CHEAT_{SanitizeForRuleId(fileName)}",
                entity: originalPath
            ));
            return;
        }

        // 2. Palavra-chave suspeita no nome do arquivo (sem legítimo)
        if (CheatDatabase.HasSuspiciousKeyword(fileName) &&
            !CheatDatabase.IsKnownLegitimate(fileName))
        {
            findings.Add(BuildFinding(
                RiskLevel.Medium,
                FindingCategory.Cheat,
                $"[DELETADO] Arquivo suspeito na Lixeira: {fileName}",
                $"Nome do arquivo contém palavra-chave associada a cheats. " +
                "Pode indicar remoção de evidências após uso.",
                originalPath, deletionTime, fileSize,
                Confidence.Medium,
                $"RECYCLEBIN_SUSPICIOUS_{SanitizeForRuleId(fileName)}",
                entity: originalPath
            ));
            return;
        }

        // 3. Executável em caminho de alto risco
        if (ExecutableExtensions.Contains(extension) &&
            CheatDatabase.IsSuspiciousPath(originalPath.ToLowerInvariant()))
        {
            findings.Add(BuildFinding(
                RiskLevel.Medium,
                FindingCategory.FileSystem,
                $"[DELETADO] Executável em caminho suspeito: {fileName}",
                $"Arquivo executável deletado encontrado em caminho de risco. " +
                "Avaliar junto a outros artefatos para determinar relevância.",
                originalPath, deletionTime, fileSize,
                Confidence.Low,
                "RECYCLEBIN_EXEC_SUSPICIOUS_PATH",
                entity: originalPath
            ));
        }
    }

    /// <summary>
    /// Constrói um Finding padronizado para a Lixeira com todos os campos obrigatórios.
    /// </summary>
    private Finding BuildFinding(
        RiskLevel risk,
        FindingCategory category,
        string title,
        string detail,
        string originalPath,
        DateTime? deletionTime,
        long fileSize,
        Confidence confidence,
        string ruleId,
        string? entity = null)
    {
        var deletedLabel = deletionTime.HasValue
            ? deletionTime.Value.ToString("dd/MM/yyyy HH:mm:ss")
            : "data desconhecida";

        return new Finding(
            risk,
            category,
            Name,
            title,
            $"{detail}\nArquivo: {originalPath} | Tamanho original: {fileSize} bytes",
            evidence:       $"Caminho original: {originalPath} | Deletado em: {deletedLabel}",
            timestamp:      deletionTime,
            confidence:     confidence,
            ruleId:         ruleId,
            entity:         entity,
            validationHint: ValidationHintText
        );
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────

    /// <summary>
    /// Sanitiza uma string para uso como sufixo de RuleId (apenas letras, dígitos e _).
    /// </summary>
    private static string SanitizeForRuleId(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.ToUpperInvariant())
        {
            if (char.IsLetterOrDigit(c))
                sb.Append(c);
            else if (c is '.' or '-' or '_' or ' ')
                sb.Append('_');
        }
        return sb.ToString();
    }
}
