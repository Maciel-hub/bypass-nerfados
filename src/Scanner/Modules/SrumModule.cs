using BypassNerfados.Scanner.Core;
using BypassNerfados.Scanner.Data;
using BypassNerfados.Scanner.Models;
using Microsoft.Isam.Esent.Interop;

namespace BypassNerfados.Scanner.Modules;

// System Resource Usage Monitor — reads SRUDB.dat (ESE database) for network usage
// per process over the last ~30-60 days. Copies the live database via permissive FileShare.
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
                LogPartialError("SRUDB.dat não pôde ser copiado — arquivo bloqueado, acesso negado ou cópia permissiva falhou");
                return;
            }

            // Read page size from ESE header (offset 236, cbDbPage) rather than looping through
            // all sizes — JET_param.DatabasePageSize is process-wide; multiple JetCreateInstance2
            // calls with different sizes in the same process cause "engine already initialized".
            var pageSize = DetectEsePageSize(dbPath);
            if (!TryReadWithPageSize(dbPath, tempDir, pageSize, findings, lookback, ct))
                LogPartialError($"SRUM: não foi possível abrir SRUDB.dat (pageSize={pageSize} detectado no header)");
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

                // SRUDB.dat: try permissive FileShare first, then VSS if ESE holds an exclusive lock
                if (string.Equals(Path.GetFileName(file), SruDb, StringComparison.OrdinalIgnoreCase))
                {
                    var vssTemp = CopyLockedFileWithVss(file);
                    if (vssTemp != null)
                    {
                        try { File.Move(vssTemp, dstFile, overwrite: true); copied = true; }
                        catch { try { File.Delete(vssTemp); } catch { } }
                    }
                }

                // Fallback: permissive FileStream copy for log files or if CopyLockedFile failed
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

    // Reads cbDbPage from the ESE database header at offset 236 (0xEC).
    // Defaults to 32768 (Windows 10/11 standard) when the header can't be read.
    private static int DetectEsePageSize(string dbPath)
    {
        try
        {
            using var fs = new FileStream(dbPath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < 240) return 32768;
            fs.Seek(236, SeekOrigin.Begin);
            var buf = new byte[4];
            if (fs.Read(buf, 0, 4) < 4) return 32768;
            var size = BitConverter.ToInt32(buf, 0);
            return size is 4096 or 8192 or 16384 or 32768 ? size : 32768;
        }
        catch { return 32768; }
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

            var appMap = BuildAppMap(sesid, dbid, findings, ct);
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

    // Returns the column ID for the first matching candidate name.
    // Column names in SRUDB vary slightly across Windows builds — this prevents hard failures.
    private static JET_COLUMNID TryGetColumn(JET_SESID sesid, JET_TABLEID tableId, params string[] candidates)
    {
        foreach (var name in candidates)
        {
            try { return Api.GetTableColumnid(sesid, tableId, name); }
            catch { }
        }
        throw new InvalidOperationException(
            $"SRUM: nenhuma coluna encontrada. Tentativas: {string.Join(", ", candidates)}");
    }

    // Builds idIndex → app path dictionary from SruDbIdMapTable.
    private Dictionary<int, string> BuildAppMap(JET_SESID sesid, JET_DBID dbid,
        List<Finding> findings, CancellationToken ct)
    {
        var map = new Dictionary<int, string>();
        bool tableOpened = false;

        try
        {
            Api.JetOpenTable(sesid, dbid, IdTable, null, 0, OpenTableGrbit.ReadOnly, out var tableId);
            tableOpened = true;
            try
            {
                JET_COLUMNID idxCol, appCol;
                try
                {
                    idxCol = TryGetColumn(sesid, tableId, "IdIndex", "IdIdx", "Id");
                    appCol = TryGetColumn(sesid, tableId, "App", "ExeInfo", "AppName");
                }
                catch (InvalidOperationException)
                {
                    var schema    = DumpTableSchema(sesid, tableId);
                    var schemaStr = string.Join(", ", schema.Select(c => $"{c.Name}({c.Coltyp})"));
                    LogPartialError(
                        $"SRUM: colunas do IdMap não encontradas. Colunas disponíveis: [{schemaStr}]");
                    var f = new Finding(
                        RiskLevel.Info, FindingCategory.LogCoverage, Name,
                        "SRUM: schema do IdMap incompatível — colunas de identificação não encontradas",
                        "As colunas IdIndex e App da tabela de mapeamento não foram encontradas.\n" +
                        "App paths não serão resolvidos — detecção por nome de arquivo do cheat ainda funciona.",
                        $"Colunas disponíveis: {schemaStr}",
                        confidence: Confidence.Confirmed,
                        ruleId: "SRUM_IDMAP_SCHEMA_INCOMPATIBLE");
                    f.ScoreEligible = false;
                    findings.Add(f);
                    return map;
                }

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
        catch (EsentObjectNotFoundException)
        {
            LogPartialError("SRUM: SruDbIdMapTable não encontrada — versão do Windows incompatível");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { LogPartialError("SRUM: falha ao ler IdMap", ex); }

        if (tableOpened && map.Count == 0)
        {
            var f = new Finding(
                RiskLevel.Info, FindingCategory.LogCoverage, Name,
                "SRUM: IdMap vazio — app paths não resolvidos",
                "A tabela SruDbIdMapTable foi lida mas não contém mapeamentos de app path.\n" +
                "Pode ocorrer em sistemas recém-instalados ou com SRUM ainda sem dados.\n" +
                "Detecção por nome de executável permanece ativa.",
                confidence: Confidence.Confirmed,
                ruleId: "SRUM_IDMAP_EMPTY");
            f.ScoreEligible = false;
            findings.Add(f);
        }

        return map;
    }

    // Enumerates all columns in a table for diagnostic output.
    // Used when TryGetColumn fails to identify the actual schema in this Windows build.
    private static List<(string Name, string Coltyp)> DumpTableSchema(JET_SESID sesid, JET_TABLEID tableId)
    {
        var result = new List<(string Name, string Coltyp)>();
        try
        {
            foreach (var col in Api.GetTableColumns(sesid, tableId))
                result.Add((col.Name, col.Coltyp.ToString()));
        }
        catch { }
        return result;
    }

    // Reads the timestamp column using the correct retrieval method for the column's ESE type.
    // JET_coltyp.DateTime (8) stores an OLE Automation date — use RetrieveColumnAsDateTime.
    // Long/LongLong/Currency store a Windows FILETIME (100-ns ticks since 1601-01-01 UTC).
    // Returns null on any error so callers can skip the row without throwing.
    private static DateTime? ReadSrumTimestamp(JET_SESID sesid, JET_TABLEID tableId,
        JET_COLUMNID colTs, string tsColtyp)
    {
        try
        {
            if (string.Equals(tsColtyp, "DateTime", StringComparison.OrdinalIgnoreCase))
            {
                var dt = Api.RetrieveColumnAsDateTime(sesid, tableId, colTs);
                if (!dt.HasValue) return null;
                // SRUDB DateTime columns store UTC — SpecifyKind then convert to local
                return DateTime.SpecifyKind(dt.Value, DateTimeKind.Utc).ToLocalTime();
            }
            else
            {
                var raw = Api.RetrieveColumnAsInt64(sesid, tableId, colTs);
                return raw.HasValue ? FileTimeToDateTime(raw.Value) : null;
            }
        }
        catch { return null; }
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
                // AppId and TimeStamp are required — without them we can't identify apps or filter by date
                var colAppId = TryGetColumn(sesid, tableId, "AppId", "AppID", "AppIndex");
                var colTs    = TryGetColumn(sesid, tableId, "TimeStamp", "Timestamp", "timestamp");

                // Byte columns are optional — try all known variants across Windows builds
                JET_COLUMNID? colSent = null, colRecvd = null;

                try
                {
                    colSent = TryGetColumn(sesid, tableId,
                        "BytesSent", "bytesSent", "BytesOut", "BytesOutbound",
                        "BytesTransmitted", "TxBytes", "SentBytes", "UploadBytes");
                }
                catch { }

                try
                {
                    colRecvd = TryGetColumn(sesid, tableId,
                        "BytesRecvd", "BytesRecv", "BytesReceived", "BytesIn",
                        "BytesInbound", "RxBytes", "RecvBytes", "DownloadBytes");
                }
                catch { }

                bool bytesAvailable = colSent.HasValue && colRecvd.HasValue;

                // Enumerate schema once for TimeStamp type detection and byte-column diagnostics
                var tableSchema = DumpTableSchema(sesid, tableId)
                    .ToDictionary(c => c.Name, c => c.Coltyp, StringComparer.OrdinalIgnoreCase);
                var tsColName  = new[] { "TimeStamp", "Timestamp", "timestamp" }
                    .FirstOrDefault(tableSchema.ContainsKey) ?? "TimeStamp";
                var tsColtyp   = tableSchema.GetValueOrDefault(tsColName, "Long");

                if (!bytesAvailable)
                {
                    var schemaStr = string.Join(", ", tableSchema.Select(kvp => $"{kvp.Key}({kvp.Value})"));
                    var missing   = new List<string>();
                    if (!colSent.HasValue)  missing.Add("BytesSent (e variantes)");
                    if (!colRecvd.HasValue) missing.Add("BytesRecvd (e variantes)");

                    var schemaFinding = new Finding(
                        RiskLevel.Info,
                        FindingCategory.LogCoverage,
                        Name,
                        $"SRUM: schema incompatível — {string.Join(" e ", missing)} não encontradas",
                        $"As colunas de bytes não foram encontradas nesta build do Windows.\n" +
                        $"AppId e TimeStamp disponíveis — cheats conhecidos ainda são detectáveis por nome.\n" +
                        $"Colunas não encontradas: {string.Join(", ", missing)}",
                        $"Colunas disponíveis: {schemaStr}",
                        confidence: Confidence.Confirmed,
                        ruleId: "SRUM_SCHEMA_INCOMPATIBLE"
                    );
                    schemaFinding.ScoreEligible = false;
                    findings.Add(schemaFinding);

                    LogPartialError(
                        $"SRUM: schema da tabela de rede — faltam {string.Join(", ", missing)}. " +
                        $"TimeStamp coltyp={tsColtyp}. Continuando sem totais de bytes.");
                }

                var cutoff = DateTime.UtcNow - lookback;
                var appTotals = new Dictionary<string, (long sent, long recvd, DateTime? lastSeen)>(
                    StringComparer.OrdinalIgnoreCase);
                int malformedRows = 0;

                Api.MoveBeforeFirst(sesid, tableId);
                while (Api.TryMoveNext(sesid, tableId))
                {
                    ct.ThrowIfCancellationRequested();

                    var appId = Api.RetrieveColumnAsInt32(sesid, tableId, colAppId);
                    var sent  = colSent.HasValue  ? Api.RetrieveColumnAsInt64(sesid, tableId, colSent.Value)  ?? 0 : 0;
                    var recvd = colRecvd.HasValue ? Api.RetrieveColumnAsInt64(sesid, tableId, colRecvd.Value) ?? 0 : 0;
                    var ts    = ReadSrumTimestamp(sesid, tableId, colTs, tsColtyp);

                    if (ts == null) { malformedRows++; continue; }
                    if (ts.Value.ToUniversalTime() < cutoff) continue;
                    if (!appId.HasValue) continue;
                    if (!appMap.TryGetValue(appId.Value, out var appPath)) continue;
                    if (string.IsNullOrWhiteSpace(appPath) || appPath.StartsWith("S-1-")) continue;
                    if (IsOwnProcess(appPath) || CheatDatabase.IsKnownLegitimate(appPath)) continue;

                    if (!appTotals.TryGetValue(appPath, out var totals))
                        totals = (0, 0, null);

                    var lastTs = !totals.lastSeen.HasValue || ts > totals.lastSeen ? ts : totals.lastSeen;
                    appTotals[appPath] = (totals.sent + sent, totals.recvd + recvd, lastTs);
                }

                if (malformedRows > 0)
                    LogPartialError($"SRUM: {malformedRows} linha(s) com timestamp inválido ignoradas");

                foreach (var (appPath, (totalSent, totalRecvd, lastSeen)) in appTotals)
                {
                    ct.ThrowIfCancellationRequested();
                    EvaluateSrumEntry(appPath, totalSent, totalRecvd, lastSeen, bytesAvailable, findings);
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
        DateTime? lastSeen, bool bytesAvailable, List<Finding> findings)
    {
        var fileName = Path.GetFileName(appPath).ToLowerInvariant();
        if (string.IsNullOrEmpty(fileName)) return;

        var totalMb = (totalSent + totalRecvd) / 1_048_576.0;
        var netDetail = bytesAvailable
            ? $"Enviado: {totalSent / 1024:N0} KB | Recebido: {totalRecvd / 1024:N0} KB | Total: {totalMb:F1} MB"
            : "Totais de bytes indisponíveis (schema SRUDB incompatível nesta build do Windows)";

        var cheat = CheatDatabase.TryGetCredibleCheat(fileName, appPath);
        if (cheat != null)
        {
            // When bytes unavailable, default to High since we can't confirm traffic volume
            var risk = bytesAvailable ? (totalMb > 1 ? RiskLevel.Critical : RiskLevel.High) : RiskLevel.High;
            findings.Add(new Finding(
                risk,
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

        // Threshold-based path check only when bytes are actually known
        if (bytesAvailable && CheatDatabase.IsSuspiciousPath(appPath.ToLowerInvariant()) && totalMb > 0.5)
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
