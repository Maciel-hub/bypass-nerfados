using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Isam.Esent.Interop;

namespace BypassNerfados.Scanner.Modules;

// System Resource Usage Monitor — reads SRUDB.dat (ESE database) for network/CPU usage
// per process over the last ~30-60 days. Requires admin to copy the live database via VSS.
public class SrumModule : BaseModule
{
    public override string Name        => "SRUM";
    public override string Description => "Uso de rede por processo (~30-60 dias) via SRUDB.dat";

    private const string SruDir  = @"C:\Windows\System32\sru";
    private const string SruDb   = "SRUDB.dat";
    // Network usage table — bytes sent/received per app per ~hour interval
    private const string NetTable = "{DD6636C4-8929-4683-974E-22C046A43763}";
    private const string IdTable  = "SruDbIdMapTable";

    protected override async Task<List<Finding>> ExecuteAsync(ScanConfig config, CancellationToken ct)
    {
        var findings = new List<Finding>();

        if (!Directory.Exists(SruDir))
        {
            LogPartialError("Pasta SRU não encontrada — SRUM indisponível neste sistema");
            return findings;
        }

        await Task.Run(() => ReadSrum(findings, config.EventWindowLookback, ct), ct);
        return findings;
    }

    private void ReadSrum(List<Finding> findings, TimeSpan lookback, CancellationToken ct)
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"echo_sru_{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(tempDir);
            CopySruDir(SruDir, tempDir);

            var dbPath = Path.Combine(tempDir, SruDb);
            if (!File.Exists(dbPath))
            {
                LogPartialError("SRUDB.dat não pôde ser copiado — VSS indisponível ou acesso negado");
                return;
            }

            // Try page sizes in order — Windows 10/11 SRUDB.dat uses 32768
            foreach (var pageSize in new[] { 32768, 16384, 8192 })
            {
                if (TryReadWithPageSize(dbPath, tempDir, pageSize, findings, lookback, ct))
                    return;
                ct.ThrowIfCancellationRequested();
            }
            LogPartialError("SRUM: não foi possível abrir SRUDB.dat com nenhum tamanho de página (32768/16384/8192)");
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private void CopySruDir(string src, string dst)
    {
        var skipped = new List<string>();
        try
        {
            foreach (var file in Directory.GetFiles(src))
            {
                var dstFile = Path.Combine(dst, Path.GetFileName(file));
                var copied  = false;

                // Use CopyLockedFile (VSS-backed) for SRUDB.dat — it may be locked by SruUsageSvc
                if (string.Equals(Path.GetFileName(file), SruDb, StringComparison.OrdinalIgnoreCase))
                {
                    var vssTemp = CopyLockedFile(file);
                    if (vssTemp != null)
                    {
                        try { File.Move(vssTemp, dstFile, overwrite: true); copied = true; }
                        catch { try { File.Delete(vssTemp); } catch { } }
                    }
                }

                // Fallback (log files and failed VSS): permissive FileStream copy
                if (!copied)
                {
                    try
                    {
                        using var s = new FileStream(file, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);
                        using var d = File.Create(dstFile);
                        s.CopyTo(d);
                        copied = true;
                    }
                    catch { }
                }

                if (!copied)
                    skipped.Add(Path.GetFileName(file));
            }
        }
        catch (Exception ex) { LogPartialError("SRUM: falha ao enumerar arquivos SRU", ex); }

        if (skipped.Count > 0)
            LogPartialError($"SRUM: {skipped.Count} arquivo(s) SRU não copiado(s): {string.Join(", ", skipped)}");
    }

    // Attempts to open and read SRUDB.dat with the given page size.
    // Returns true if the open succeeded (even if no cheat-related findings were found).
    private bool TryReadWithPageSize(string dbPath, string tempDir, int pageSize,
        List<Finding> findings, TimeSpan lookback, CancellationToken ct)
    {
        JET_INSTANCE instance = JET_INSTANCE.Nil;
        JET_SESID    sesid    = JET_SESID.Nil;
        JET_DBID     dbid     = JET_DBID.Nil;

        try
        {
            Api.JetCreateInstance2(out instance, $"echo_srum_{pageSize}", $"echo_srum_{pageSize}",
                CreateInstanceGrbit.None);

            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.DatabasePageSize, pageSize, null);
            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.Recovery,         0, "on");
            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.SystemPath,       0, tempDir + "\\");
            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.LogFilePath,      0, tempDir + "\\");
            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.TempPath,         0, tempDir + "\\");
            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.NoInformationEvent, 1, null);
            Api.JetSetSystemParameter(instance, JET_SESID.Nil, JET_param.MaxSessions,      2, null);

            Api.JetInit(ref instance);
            Api.JetBeginSession(instance, out sesid, null, null);
            Api.JetAttachDatabase2(sesid, dbPath, 0, AttachDatabaseGrbit.ReadOnly);
            Api.JetOpenDatabase(sesid, dbPath, null, out dbid, OpenDatabaseGrbit.ReadOnly);

            ct.ThrowIfCancellationRequested();

            var appMap = BuildAppMap(sesid, dbid, ct);
            ct.ThrowIfCancellationRequested();

            ReadNetworkUsage(sesid, dbid, appMap, findings, lookback, ct);
            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (EsentDatabaseDirtyShutdownException)
        {
            // Database needs recovery — log files might be incomplete; try next page size
            LogPartialError($"SRUM: desligamento sujo com pageSize={pageSize}, tentando recuperação");
            return false;
        }
        catch (EsentPageSizeMismatchException)
        {
            return false; // try next page size
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (ex.Message.Contains("page size", StringComparison.OrdinalIgnoreCase))
                return false;
            LogPartialError($"SRUM (pageSize={pageSize}): {ex.Message}");
            return false;
        }
        finally
        {
            if (dbid != JET_DBID.Nil)
                try { Api.JetCloseDatabase(sesid, dbid, CloseDatabaseGrbit.None); } catch { }
            if (dbid != JET_DBID.Nil)
                try { Api.JetDetachDatabase(sesid, dbPath); } catch { }
            if (sesid != JET_SESID.Nil)
                try { Api.JetEndSession(sesid, EndSessionGrbit.None); } catch { }
            if (instance != JET_INSTANCE.Nil)
                try { Api.JetTerm2(instance, TermGrbit.Complete); } catch { }
        }
    }

    // Builds idIndex → app path dictionary from SruDbIdMapTable.
    private static Dictionary<int, string> BuildAppMap(JET_SESID sesid, JET_DBID dbid, CancellationToken ct)
    {
        var map = new Dictionary<int, string>();
        try
        {
            Api.JetOpenTable(sesid, dbid, IdTable, null, 0, OpenTableGrbit.ReadOnly, out var tableId);
            try
            {
                var idxCol = Api.GetTableColumnid(sesid, tableId, "IdIndex");
                var appCol = Api.GetTableColumnid(sesid, tableId, "App");

                Api.MoveBeforeFirst(sesid, tableId);
                while (Api.TryMoveNext(sesid, tableId))
                {
                    ct.ThrowIfCancellationRequested();
                    var idx = Api.RetrieveColumnAsInt32(sesid, tableId, idxCol);
                    var app = Api.RetrieveColumnAsString(sesid, tableId, appCol,
                        System.Text.Encoding.Unicode) ?? "";
                    if (idx.HasValue && !string.IsNullOrEmpty(app))
                        map[idx.Value] = app;
                }
            }
            finally { Api.JetCloseTable(sesid, tableId); }
        }
        catch { /* table may not exist on older Windows */ }
        return map;
    }

    private void ReadNetworkUsage(JET_SESID sesid, JET_DBID dbid,
        Dictionary<int, string> appMap, List<Finding> findings,
        TimeSpan lookback, CancellationToken ct)
    {
        try
        {
            Api.JetOpenTable(sesid, dbid, NetTable, null, 0, OpenTableGrbit.ReadOnly, out var tableId);
            try
            {
                var colAppId  = Api.GetTableColumnid(sesid, tableId, "AppId");
                var colSent   = Api.GetTableColumnid(sesid, tableId, "BytesSent");
                var colRecvd  = Api.GetTableColumnid(sesid, tableId, "BytesRecvd");
                var colTs     = Api.GetTableColumnid(sesid, tableId, "TimeStamp");

                var cutoff = DateTime.UtcNow - lookback;
                // Accumulate per-app totals before emitting findings
                var appTotals = new Dictionary<string, (long sent, long recvd, DateTime? lastSeen)>(
                    StringComparer.OrdinalIgnoreCase);

                Api.MoveBeforeFirst(sesid, tableId);
                while (Api.TryMoveNext(sesid, tableId))
                {
                    ct.ThrowIfCancellationRequested();

                    var appId  = Api.RetrieveColumnAsInt32(sesid, tableId, colAppId);
                    var sent   = Api.RetrieveColumnAsInt64(sesid, tableId, colSent)   ?? 0;
                    var recvd  = Api.RetrieveColumnAsInt64(sesid, tableId, colRecvd)  ?? 0;
                    var tsRaw  = Api.RetrieveColumnAsInt64(sesid, tableId, colTs);
                    var ts     = tsRaw.HasValue ? FileTimeToDateTime(tsRaw.Value) : null;

                    if (ts.HasValue && ts.Value.ToUniversalTime() < cutoff) continue;
                    if (!appId.HasValue) continue;
                    if (!appMap.TryGetValue(appId.Value, out var appPath)) continue;
                    if (string.IsNullOrWhiteSpace(appPath) || appPath.StartsWith("S-1-")) continue;
                    if (IsOwnProcess(appPath) || CheatDatabase.IsKnownLegitimate(appPath)) continue;

                    if (!appTotals.TryGetValue(appPath, out var totals))
                        totals = (0, 0, null);

                    var lastTs = ts.HasValue && (!totals.lastSeen.HasValue || ts > totals.lastSeen)
                        ? ts : totals.lastSeen;
                    appTotals[appPath] = (totals.sent + sent, totals.recvd + recvd, lastTs);
                }

                // Evaluate accumulated entries
                foreach (var (appPath, (totalSent, totalRecvd, lastSeen)) in appTotals)
                {
                    ct.ThrowIfCancellationRequested();
                    EvaluateSrumEntry(appPath, totalSent, totalRecvd, lastSeen, findings);
                }
            }
            finally { Api.JetCloseTable(sesid, tableId); }
        }
        catch (EsentObjectNotFoundException)
        {
            LogPartialError($"SRUM: tabela de rede '{NetTable}' não encontrada — versão do Windows incompatível");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("SRUM: falha ao ler tabela de rede", ex); }
    }

    private void EvaluateSrumEntry(string appPath, long totalSent, long totalRecvd,
        DateTime? lastSeen, List<Finding> findings)
    {
        var fileName = Path.GetFileName(appPath).ToLowerInvariant();
        if (string.IsNullOrEmpty(fileName)) return;

        var totalMb = (totalSent + totalRecvd) / 1_048_576.0;
        var netDetail = $"Enviado: {totalSent / 1024:N0} KB | Recebido: {totalRecvd / 1024:N0} KB | Total: {totalMb:F1} MB";

        var cheat = CheatDatabase.TryGetCredibleCheat(fileName, appPath);
        if (cheat != null)
        {
            findings.Add(new Finding(
                totalMb > 1 ? RiskLevel.Critical : RiskLevel.High,
                FindingCategory.Cheat,
                Name,
                $"SRUM — CHEAT COM ATIVIDADE DE REDE: {cheat.Name} ({fileName})",
                $"Processo cheat confirmado com uso de rede registrado no SRUM.\n{cheat.Description}\n{netDetail}",
                $"Caminho: {appPath}",
                timestamp: lastSeen,
                confidence: Confidence.High,
                ruleId: $"SRUM_NET_CHEAT_{fileName.ToUpperInvariant().Replace('.', '_')}",
                entity: appPath
            ));
            return;
        }

        if (CheatDatabase.HasSuspiciousKeyword(fileName))
        {
            findings.Add(new Finding(
                RiskLevel.High,
                FindingCategory.SuspiciousExecution,
                Name,
                $"SRUM — PROCESSO SUSPEITO COM REDE: {fileName}",
                $"Nome suspeito com atividade de rede no SRUM.\n{netDetail}",
                $"Caminho: {appPath}",
                timestamp: lastSeen,
                confidence: Confidence.Medium,
                ruleId: $"SRUM_NET_SUSPICIOUS_{fileName.ToUpperInvariant().Replace('.', '_')}",
                entity: appPath,
                validationHint: "Correlacionar com Prefetch, BAM e sessão FiveM para confirmar execução"
            ));
            return;
        }

        if (CheatDatabase.IsSuspiciousPath(appPath.ToLowerInvariant()) && totalMb > 0.5)
        {
            findings.Add(new Finding(
                RiskLevel.Medium,
                FindingCategory.SuspiciousExecution,
                Name,
                $"SRUM — Executável em path suspeito com rede: {fileName}",
                $"Executável em localização de risco com tráfego de rede registrado.\n{netDetail}",
                $"Caminho: {appPath}",
                timestamp: lastSeen,
                confidence: Confidence.Low,
                ruleId: $"SRUM_NET_SUSPPATH_{fileName.ToUpperInvariant().Replace('.', '_')}",
                entity: appPath,
                validationHint: "Confirmar por hash e correlação com Amcache/Prefetch"
            ));
        }
    }
}
