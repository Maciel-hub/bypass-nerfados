namespace BypassNerfados.Scanner.Data;

public record CheatInfo(
    string Name,
    string Description,
    string[] KnownPaths,
    string[]? Hashes = null,
    string[]? AssociatedFiles = null,
    bool IsGenericName = false  // true when the filename is common (launcher, setup) — needs path/hash to be credible
);

public static class CheatDatabase
{
    public static readonly Dictionary<string, CheatInfo> KnownExecutables =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["launcher.exe"] = new CheatInfo(
                "Loader FiveM Suspeito",
                "Loader de cheat FiveM fora de paths legítimos (padrão GOSTH). Gera arquivo de 8-10 chars aleatórios na System32.",
                [@"AppData\Local\Programs\Common", @"AppData\Local\Temp\"],
                AssociatedFiles: ["dxsetup"],
                IsGenericName: true   // "launcher.exe" é usado por Rockstar, Steam, Epic etc. — só paths muito específicos confirmam
            ),

            ["spotify.exe"] = new CheatInfo(
                "Loader FiveM Disfarçado (padrão GOSTH/Spotify)",
                "Loader de cheat renomeado como spotify.exe para evasão. O binário legítimo do Spotify reside em AppData\\Roaming\\Spotify\\ — fora desse path é suspeito.",
                [@"AppData\Local\Temp\", @"Downloads\", @"Desktop\", @"AppData\Local\Programs\Common"],
                IsGenericName: true   // spotify.exe legítimo está em AppData\Roaming\Spotify\ — fora desses paths é suspeito
            ),

            ["farinhafree.exe"] = new CheatInfo(
                "FarinhaFree",
                "Cheat FiveM. SHA1: 53f9c024f03c007ce1db49a02b2db39d35e340b2",
                [@"AppData\", @"Downloads\", @"Temp\"],
                Hashes: ["53f9c024f03c007ce1db49a02b2db39d35e340b2"]
            ),

            ["whatsapp installer.exe"] = new CheatInfo(
                "WhatsApp Installer Falso (GOSTH/Loader)",
                "Executável malicioso disfarçado de WhatsApp. Localizado em System32\\WinBioDatabase. SHA1: a7d04fdbc41fe2165a4cbc8e0657052ec3fb334f",
                [@"C:\Windows\System32\WinBioDatabase\"],
                Hashes: ["a7d04fdbc41fe2165a4cbc8e0657052ec3fb334f"]
            ),

            ["dxsetup.exe"] = new CheatInfo(
                "GOSTH Loader (dxsetup)",
                "Loader do cheat GOSTH disfarçado de instalador DirectX. Normalmente em AppData\\Local\\Programs\\Common",
                [@"AppData\Local\Programs\Common", @"AppData\Local\Temp\"],
                IsGenericName: true   // "dxsetup.exe" é o instalador legítimo do DirectX redistribuível
            ),

            // --- Famílias FiveM conhecidas ---

            ["eulen.exe"] = new CheatInfo(
                "Eulen",
                "Cheat FiveM da família Eulen. Inclui aimbot, ESP e bypass de anti-cheat.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["eulen loader.exe"] = new CheatInfo(
                "Eulen",
                "Loader do cheat FiveM Eulen.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["redengine.exe"] = new CheatInfo(
                "RedEngine",
                "Cheat FiveM redENGINE. Loader com módulos de aimbot e ESP.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["susano.exe"] = new CheatInfo(
                "Susano",
                "Cheat FiveM Susano.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["nightfall.exe"] = new CheatInfo(
                "Nightfall",
                "Cheat FiveM Nightfall.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["cherax.exe"] = new CheatInfo(
                "Cherax",
                "Script executor / cheat para FiveM e GTA V.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["hamafia.exe"] = new CheatInfo(
                "HaMafia",
                "Cheat FiveM HaMafia.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["cheathub.exe"] = new CheatInfo(
                "CheatHub",
                "Loader multi-cheat CheatHub.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["0xcheats.exe"] = new CheatInfo(
                "0xCheats",
                "Cheat FiveM 0xCheats.",
                [@"AppData\", @"Downloads\", @"Desktop\"]
            ),
            ["spoofer.exe"] = new CheatInfo(
                "HWID Spoofer",
                "Ferramenta de bypass de HWID (hardware ID). Usada para evadir banimentos baseados em hardware.",
                [@"AppData\", @"Downloads\", @"Desktop\", @"Temp\"],
                IsGenericName: true
            ),
        };

    public static readonly Dictionary<string, CheatInfo> KnownDlls =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["d3d10.dll"] = new CheatInfo(
                "FiveM DLL Cheat (d3d10)",
                "DLL maliciosa instalada no diretório de plugins do FiveM. Pesa aproximadamente 1MB.",
                [@"FiveM Application Data\Plugins\"],
                AssociatedFiles: ["FiveM Application Data\\Plugins\\d3d10.dll"]
            ),
        };

    public static readonly string[] SuspiciousKeywords =
    [
        "cheat", "hack", "bypass", "inject", "loader", "aimbot", "wallhack",
        "esp", "triggerbot", "bhop", "spinbot", "ragebot", "hvh",
        "keyauth", "skript", "skid", "ghost", "gosth", "farinha",
        "citizen", "fivem_bypass", "norecoil", "aimassist", "triggerassist",
        "storm", "xrc", "wexize", "regedit_cleaner", "logcleaner",
        // Famílias FiveM conhecidas
        "eulen", "redengine", "susano", "tzproject", "spoofer",
        "phaze", "cherax", "hamafia", "cheathub"
    ];

    public static readonly string[] SuspiciousStrings =
    [
        "VirtualProtectEx", "SuspendThread", "keyauth", "shellcode",
        "inject", "cdn.", "curl", ".pdb bypass", "delete logs",
        "sc stop", "wevtutil cl", "bcdedit", "fsutil usn deletejournal"
    ];

    public static readonly string[] HighRiskPaths =
    [
        @"\AppData\Local\Temp\",
        @"\Temp\",
        @"\AppData\Roaming\",
        @"\AppData\Local\Programs\",
        @"\Users\Public\",
        @"\ProgramData\",
        @"\Windows\Temp\",
        @"\Downloads\",
        @"\Desktop\",
        @"\System32\WinBioDatabase\",
        @"\FiveM Application Data\Plugins\"
    ];

    public static readonly string[] SystemServices =
    [
        "pcasvc", "dps", "diagtrack", "sysmain", "eventlog",
        "dusmsvc", "appinfo", "bam"
    ];

    // Legitimate executable/path fragments — match suspicious keywords but are not cheats.
    // Checked via IsKnownLegitimate(path) where path is the full file path, so fragments
    // should be distinct enough to avoid collision with cheat paths.
    private static readonly HashSet<string> _legitimatePatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        // FiveM / CitizenFX official binaries and project references
        // "citizenfx" as a bare keyword covers github.com/citizenfx URLs in PSReadLine history
        // and CitizenFX.exe shortcuts in UserAssist; distinct enough from cheat paths that
        // use "citizen" (internal module name) rather than "citizenfx" (project name).
        "citizenfx", "fivem_uninstall",
        "citizenfx.exe", "fivem.exe",

        // Game launchers (legit)
        "rockstargameslauncher", "epicgameslauncher", "gogalaxy",
        "eadesktop", "easetup", "originclientservice", "battlenet",
        "ubisoftconnect", "uplaybroker",

        // Anti-cheat systems (legit)
        "easyanticheat", "battleye", "eac_setup",

        // DirectX / Visual C++ redistributables (common in Amcache/AppData)
        "dxwebsetup", "directx_", "vcredist", "vc_redist", "windowsdesktop-runtime",

        // Comms / productivity — Spotify: only whitelist the real install paths; spotify.exe outside of
        // AppData\Roaming\Spotify\ or WindowsApps\SpotifyAB is flagged as GOSTH loader (see KnownExecutables)
        @"roaming\spotify\", @"windowsapps\spotifyab",
        "discord", "steam", "onedrive", "googledrive",
        "dropbox", "teams", "skype", "zoom",

        // Streaming / capture
        "obs", "streamlabs",

        // GPU drivers
        "nvidia", "nvcontainer", "nvcplui", "geforce",
        "amdinstall", "radeoninstall", "intelarc",

        // Security / AV (legit)
        "malwarebytes", "mbam", "avast", "avgui", "kaspersky", "eset",
        "msseces",

        // Windows Defender platform directory (mpcmdrun.exe, msmpeng.exe, nissrv.exe)
        // Path: C:\ProgramData\Microsoft\Windows Defender\Platform\...
        @"\windows defender\",

        // Visual Studio Code internals (rg.exe, code-tunnel.exe, openconsole.exe, etc.)
        // Path: AppData\Local\Programs\Microsoft VS Code\...
        "microsoft vs code",

        // .NET SDK / runtime / global tools in user profile hidden folder
        // Path: C:\Users\<user>\.dotnet\...
        @"\.dotnet\",
    };

    // Publisher name fragments that identify well-known legitimate vendors.
    // Used by Amcache module to suppress FPs from signed software.
    private static readonly string[] _legitimatePublisherFragments =
    [
        "microsoft", "intel corporation", "advanced micro devices", "amd",
        "nvidia corporation", "realtek semiconductor", "qualcomm",
        "epic games", "rockstar games", "valve corporation",
        "cd projekt", "riot games", "electronic arts", "ea games",
        "bethesda softworks", "activision", "ubisoft", "2k games",
        "blizzard entertainment", "square enix", "sega", "capcom",
        "bandai namco", "thq nordic", "focus entertainment",
        "citizenfx", "cfx.re",
    ];

    public static bool IsKnownLegitimate(string name)
    {
        var lower = name.ToLowerInvariant();
        return _legitimatePatterns.Any(p => lower.Contains(p));
    }

    // Returns true when the publisher string belongs to a known legitimate vendor.
    // Amcache callers should combine this with a non-suspicious-path check before skipping.
    public static bool IsKnownLegitimatePublisher(string publisher)
    {
        if (string.IsNullOrWhiteSpace(publisher)) return false;
        var lower = publisher.ToLowerInvariant();
        return _legitimatePublisherFragments.Any(p => lower.Contains(p));
    }

    public static bool IsKnownCheatExecutable(string filename) =>
        KnownExecutables.ContainsKey(filename);

    // Returns CheatInfo only when the match is credible for the given path.
    // For IsGenericName entries (launcher.exe, dxsetup.exe), requires the path to match
    // a known cheat install location; otherwise returns null to suppress the finding.
    // This is the canonical entry point — all modules with a full path must use this.
    public static CheatInfo? TryGetCredibleCheat(string fileName, string path)
    {
        if (!KnownExecutables.TryGetValue(fileName, out var entry)) return null;
        if (!entry.IsGenericName) return entry;
        var lower = path.ToLowerInvariant();
        return entry.KnownPaths.Any(p => lower.Contains(p.ToLowerInvariant())) ? entry : null;
    }

    public static bool IsKnownCheatDll(string filename) =>
        KnownDlls.ContainsKey(filename);

    public static bool IsSuspiciousPath(string path)
    {
        var lower = path.ToLowerInvariant();
        return HighRiskPaths.Any(p => lower.Contains(p.ToLowerInvariant()));
    }

    public static bool HasSuspiciousKeyword(string name)
    {
        var lower = name.ToLowerInvariant();
        return SuspiciousKeywords.Any(k => lower.Contains(k));
    }

    // Hashes stored in the database are SHA1 — callers must pass GetFileSha1() result
    public static CheatInfo? FindBySha1(string sha1)
    {
        foreach (var cheat in KnownExecutables.Values)
            if (cheat.Hashes?.Contains(sha1, StringComparer.OrdinalIgnoreCase) == true)
                return cheat;
        foreach (var cheat in KnownDlls.Values)
            if (cheat.Hashes?.Contains(sha1, StringComparer.OrdinalIgnoreCase) == true)
                return cheat;
        return null;
    }
}
