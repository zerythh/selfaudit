<#
  SelfAudit - static + live cheat / rootkit / forensics scanner.
  Webhook is pulled from a separate text file so it can be rotated without touching code.
  Partial results are uploaded every ~45s during a run so a killed session still leaves evidence.
#>
[CmdletBinding()]
param(
    [int]$Days = 7,
    [switch]$Shots,
    [switch]$NoShots,
    [switch]$NoPESieve,
    [switch]$NoReputation,
    [switch]$NoLive,
    [int]$LiveSeconds = 0,
    [switch]$SelfExclude,
    [switch]$NoUpload,
    [switch]$NoPause,
    [string]$Webhook = '',
    [string]$WebhookFile = '',
    [string]$Baseline = '',
    [switch]$SaveBaseline,
    [string]$VTApiKey = ''
)

$ErrorActionPreference = 'Continue'
$PSDefaultParameterValues['Invoke-WebRequest:UseBasicParsing'] = $true
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ScanStart = Get-Date
$RepoBase = 'https://raw.githubusercontent.com/zeryth/selfaudit/main'
$DefaultWebhookUrl = "$RepoBase/WebhookUrl.txt"
$DataRoot = Join-Path $env:LOCALAPPDATA 'SelfAudit'
$ToolRoot = Join-Path $DataRoot 'Tools'
$RepCachePath = Join-Path $DataRoot 'repcache.json'
$WebhookCache = Join-Path $DataRoot 'webhook.cache'
try { New-Item -ItemType Directory -Path $DataRoot -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

$ExePath = try { [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName } catch { '' }
$BaseDir = if ($PSScriptRoot) { $PSScriptRoot } elseif ($ExePath) { Split-Path $ExePath -Parent } else { (Get-Location).Path }
$outParent = if ($BaseDir -like "$env:TEMP*" -or $BaseDir -like '*\Temp\*') { [Environment]::GetFolderPath('Desktop') } else { $BaseDir }
$OutDir = Join-Path $outParent "SelfAudit-$Stamp"
$ZipPath = Join-Path ([IO.Path]::GetTempPath()) "SelfAudit-$env:COMPUTERNAME-$Stamp.zip"
$WinRoot = $env:SystemRoot.TrimEnd('\') + '\'
$Findings = [System.Collections.Generic.List[object]]::new()
$Meta = [ordered]@{}
$Stats = [ordered]@{ Processes=0; Modules=0; Files=0; BrowserUrls=0; Downloads=0; Prefetch=0; Amcache=0; Correlated=0; Drivers=0; Pipes=0; Listeners=0; Bam=0; UserAssist=0; MuiCache=0; RegionsScanned=0; RepLookups=0 }
$ScanHealth = [ordered]@{}
$script:TotalScore = 0
$script:EffScore = 0
$script:RepCache = @{}
$script:RepBudget = 15

$Config = @{
    PESieveUrl      = 'https://github.com/hasherezade/pe-sieve/releases/latest/download/pe-sieve64.zip'
    KnownDriversUrl = 'https://raw.githubusercontent.com/Neo23x0/LolDrivers/master/loldrivers.json'
    UploadLimitBytes = 24MB
    LivePollSeconds = 2
    MaxRegions      = 60
    MaxRegionBytes  = 48MB
}

# ============================================================================
# Signatures
# ============================================================================
$CheatHashes = @{
    '6BFC4A2E2F7C7873D82DA806A3517E3B03315B3BF7D0DF7A83BD042E0A20FF7B'='Roblox_Colorbot (PyInstaller colour/aim tool)'
    '28106A98CDCF46CAAB570371AA9E1FC894C86D92A79A588576627664B8C8DCC6'='WARP (external Roblox memory cheat, disguised as warp-svc.exe)'
    'FE8D032FDE42038D8F37D1A93134FE1A2105A0E80259555FD9578AC4F7986666'='SolaraV3.exe (Solara V3 executor)'
    '5E6F74E8C460C747E6CD94CEA8FA21271A83734B791E31A6E3C4D4E5F693EFCB'='Madium-Bootstrapper.exe'
    'E5DE0AB01F45816348F2A6C2C94C03FD5A2067C30B70A37D5994EA9A4A767C26'='Update.exe (disguised executor updater)'
    'C4C0B8E1593BC5481521CECFCE00B953E3EE6D7323B98E7DDF2E8C90A78CE545'='VelocityLite.exe'
    '34E4857E59C56DC488185BDE93EAC78C97F2CCB2F64E9AA1DD7DDB4F91E69611'='Wave.exe'
    '59823C20B3779A17039E171490483C6F0A7714B7FC0486637A0DF81A0BCB5A0E'='XenoExecutor.exe'
    'F1A78FDA695DABF07A1266A25DB3A0C4B7F9694EA762B50E4ED0BCC46118D9B5'='tauri-app.exe (Volt executor)'
}
$UnconfirmedHashes = @{
    'D6312F15E933E88199B52AF5D36C942FDE9FDBA1204FC0CCFF175D215A234632'='newuiv3.exe (unconfirmed)'
    'DCDD638E5066D6DBEA16819D1DCCD60D1FF3D96993995CE9D8E60D458EC13CB0'='oldui.exe (unconfirmed)'
    '3B11B17571B6BCA78E00224C79D0A153313A340D07190F248B98DFF4D4879457'='newui.exe (unconfirmed)'
}

$CheatKeywords = @(
    'synapse x','synapse','krnl','sirhurt','protosmasher','script-ware','scriptware','trigon','evon','celery',
    'sentinel','oxygen u','seliware','xeno','solara','solarav3','wave executor','waveuiauth','delta executor',
    'deltaexecutor','fluxus','arceus','hydrogen','cryptic executor','vega x','swift executor','synx','ronix',
    'krampus','potassium','volt executor','voltbinversioninfo','macsploit','matcha executor','matrixhub','zorara',
    'awp.gg','codex executor','comet executor','electron executor','exloader','exeloader','roexec','jjsploit',
    'lua executor','lua injector','luau executor','robloxplayerexecutor.dll','getsolara','madium','velocitylite',
    'warp-service','warp service','api.projectreal.live','madium-bootstrap','hyperion bypass','byfron bypass',
    'anticheat bypass','executor','aimbot','aim assist','silent aim','silentaim','triggerbot','esp','wallhack',
    'chams','hitbox expander','hitboxexpand','fakedatamodel','walkspeed','jumppower','fly hack','noclip',
    'auto farm','autofarm','autoclicker','auto clicker','macro recorder','pixel bot','colorbot','color bot',
    'radar hack','streamproof','hwid spoofer','hwid spoof','hwid reset','dma cheat','kmbox','kmbox net','makcu',
    'fuser','teensy','arduino hid','xim apex','rewasd','cronus zen','titan two','strike pack','glitcher',
    'kdmapper','process hacker','cheat engine','xmrig','stratum+tcp'
)
$CheatDomains = @(
    'wearedevs.net','scriptblox.com','rscripts.net','weao.xyz','voxlis.net','robloxscripts.com','krnl.cat',
    'fluxus.team','codex.lol','deltaexploits.com','arceusx.net','awp.gg','getsolara.gg','seliware.com',
    'potassium.pro','velocitylite.com','volt.bz','zorara.com','madium.xyz','synapse-x.xyz','sirhurt.net',
    'evon.cc','trigon.wtf','matcha.gg','macsploit.com','roexec.com','krampus.shop','exloader.net',
    'jjsploit.net','rbxscripts.com','bloxscripts.com','rbx.gg'
)
$CheatNameFragments = $CheatKeywords
$StrongKeywords = @(
    'synapse x','krnl','sirhurt','protosmasher','scriptware','trigon','evon','seliware','solara','wave executor',
    'delta executor','fluxus','arceus','hydrogen','cryptic executor','vega x','synx','krampus','potassium',
    'volt executor','macsploit','matcha executor','zorara','roexec','jjsploit','colorbot','madium','velocitylite',
    'getsolara','warp-service','executor','aimbot','silent aim','triggerbot','hitbox expander','streamproof',
    'hwid spoofer','kdmapper'
)

$StringSignatures = @{
    'WARP'=@('WARP-Service','[MEMORY] Attached to Roblox process PID:','Humanoid::Walkspeed','HWID Mismatch! Reset HWID via Discord bot.','AUTHENTICATE LICENSE KEY','Locked Hardware ID (HWID):')
    'SolaraV3'=@('getsolara.gg','SolaraV3.dll','SOLARA_BOOTSTRAPPER','solara:banned')
    'VoltExecutor'=@('RobloxPlayerExecutor.dll','volt.bin','hwidSeed','VoltBinVersionInfo')
    'RealExecutorFamily'=@('api.projectreal.live','Real-Executor\Real-Setup','madium-bootstrap/1.0')
    'WaveExecutor'=@('WaveUIAuth.dll','Wave.runtimeconfig.json','wave.ico')
    'ExternalHitboxExpander'=@('FakeDataModel','HitboxExpand','ChildrenStart','ChildrenEnd','NtReadVirtualMemory','NtWriteVirtualMemory')
}
$SingleMarkerSignatures = @('getsolara.gg','SOLARA_BOOTSTRAPPER','WaveUIAuth.dll','RobloxPlayerExecutor.dll','api.projectreal.live','madium-bootstrap/1.0','FakeDataModel','HitboxExpand')

$KeywordRegex = (@($CheatKeywords + $CheatDomains) | ForEach-Object { if ($_.Length -le 4) { '\b' + [regex]::Escape($_) + '\b' } else { [regex]::Escape($_) } }) -join '|'

$VulnerableDriverNames = @('gdrv.sys','gdrv2.sys','mhyprot2.sys','rtcpx64.sys','iqvw64e.sys','dbk64.sys','dbk32.sys','winring0.sys','winring0x64.sys','capcom.sys','asio.sys','asiodrv.sys','eene.sys','speedfan.sys','atsiv.sys','procexp.sys','rtcore64.sys')

$TrustedModulePublishers = @('Roblox','Microsoft','NVIDIA','Advanced Micro Devices','Intel Corporation','Intel(R)','Valve Corporation','Discord Inc','Discord','Open Broadcaster Software','OBS Project','OBS Studio','Corsair','Razer','Logitech','SteelSeries','ASUSTeK','MSI','Micro-Star','Unwinder','Guru3D','Realtek','Qualcomm','Broadcom','MediaTek','Synaptics','Dell Inc','HP Inc','Hewlett-Packard','Lenovo','Creative Technology','Killer','Rivet Networks','Riot Games','Oracle','SignalRGB')
$HandleOwnerAllowlist = @('RobloxPlayerBeta','System','Registry','csrss','wininit','services','dwm','explorer','svchost','audiodg','conhost','powershell','pwsh','handle64','handle','procexp64','procexp','procexp64a','SearchHost','ShellExperienceHost','ApplicationFrameHost','sihost','RuntimeBroker','smss','lsass','WmiPrvSE','MsMpEng','SecurityHealthService','Discord','GameOverlayUI','obs64','obs32','RTSS','MSIAfterburner','NVIDIA Share','nvcontainer','SteamOverlayRenderer','XboxGameBarWidgets','RobloxCrashHandler','RobloxStudioBeta','Bloxstrap','Fishstrap','obs-studio','Nahimic','iCUE','LGHUB','RazerCentralService','SteelSeriesGG')
$PyInstallerCheatMarkers = @('mss','cv2','win32api.pyd','win32gui.pyd','keyboard','pynput','pyautogui')
$GamingAllowlist = @('armourycrate','asus','icue','corsair','lghub','logitech','razer','steelseries','signalrgb','rtss','msiafterburner','obs','nahimic','nvcontainer','nvidia','wallpaperengine','translucenttb','sharex','discord','spotify','steam','epicgames','riotclient','battle.net','curseforge','mechvibes','customcursor','bakkesmod','onedrive')

# YARA-style rule table: name, weight, minimum distinct patterns, patterns (ASCII or hex bytes)
$Rules = @(
    @{ N='Executor_LuaVM';        W=55; M=2; P=@('lua_pcall','luaL_newstate','luaL_loadbuffer','lua_pushcclosure') }
    @{ N='Executor_RobloxApi';    W=55; M=2; P=@('RobloxPlayerExecutor','GetDataModel','FakeDataModel','RobloxInstance') }
    @{ N='Executor_InjectorStub'; W=45; M=2; P=@('LoadLibraryA','VirtualAllocEx','WriteProcessMemory','CreateRemoteThread') }
    @{ N='Cheat_WARP';            W=60; M=1; P=@('WARP-Service','HWID Mismatch! Reset HWID') }
    @{ N='Cheat_Solara';          W=60; M=1; P=@('getsolara.gg','SolaraV3.dll','SOLARA_BOOTSTRAPPER') }
    @{ N='Cheat_Volt';            W=55; M=2; P=@('RobloxPlayerExecutor.dll','VoltBinVersionInfo','hwidSeed') }
    @{ N='Cheat_Wave';            W=55; M=2; P=@('WaveUIAuth.dll','Wave.runtimeconfig.json','wave.ico') }
    @{ N='Aimbot_Config';         W=30; M=2; P=@('aimbot','silentaim','triggerbot','smoothing','fov') }
    @{ N='ESP_Config';            W=28; M=2; P=@('BoxESP','SkeletonESP','Tracers','ESP Enabled','ChamsESP') }
    @{ N='Hitbox_Expander';       W=40; M=2; P=@('HitboxExpand','ChildrenStart','ChildrenEnd','HitboxExpander') }
    @{ N='HWID_Spoofer';          W=35; M=2; P=@('HWID','spoofer','DiskSerial','VolumeSerial','SmbiosSerial') }
    @{ N='DMA_Bridge';            W=38; M=1; P=@('kmbox','KMBOX','makcu','MakcuBridge') }
    @{ N='ManualMap_PE';          W=30; M=1; P=@('This program cannot be run in DOS mode') }
    @{ N='DotNet_Injected';       W=32; M=2; P=@('BSJB','mscoree.dll','.NETFramework') }
    @{ N='Hook_Trampoline';       W=30; M=1; P=@('48B8FFFFFFFFFFFFFFE0') }
    @{ N='PyInstaller_Runtime';   W=25; M=2; P=@('PYZ-00.pyz','_MEIPASS','pyi_rth_') }
    @{ N='Crypto_Miner';          W=20; M=1; P=@('stratum+tcp','xmrig','RandomX') }
    @{ N='Anti_Debug';            W=15; M=2; P=@('IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess') }
)

$NetworkIocDomains = @()
foreach ($l in $StringSignatures.Values) { foreach ($e in $l) { if ($e -match '^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$' -and $e -notmatch '\\|/') { $NetworkIocDomains += $e.ToLower() } } }
$NetworkIocDomains = @($NetworkIocDomains | Select-Object -Unique)

$script:KnownDriversCache = @{}
$script:KnownDriversHashCache = @{}
$HashCache = @{}
$SigCache = @{}
$SeenKeys = [System.Collections.Generic.HashSet[string]]::new()
$SeenPipes = [System.Collections.Generic.HashSet[string]]::new()
$DnsCache = @{}
$BaselineKeys = @{}
$script:HasBaseline = $false

# ============================================================================
# Helpers
# ============================================================================
$ErrorLogPath = Join-Path $OutDir "SelfAudit-errors-$Stamp.log"
$script:AuditLoggedErrors = [System.Collections.Generic.HashSet[string]]::new()

function Write-AuditError {
    param([Parameter(Mandatory=$true)]$Record, [string]$Stage = 'PowerShell')
    try {
        $m = if ($Record.Exception) { $Record.Exception.Message } else { [string]$Record }
        $inv = $Record.InvocationInfo
        if ($script:AuditLoggedErrors.Add("$m|$(if ($inv) { $inv.ScriptLineNumber } else { 0 })")) {
            Add-Content -LiteralPath $ErrorLogPath -Encoding UTF8 -ErrorAction SilentlyContinue -Value (@(
                ('[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Stage, $m)
                ('Line: {0}' -f $(if ($inv) { $inv.ScriptLineNumber } else { 0 }))
                ''
            ) -join [Environment]::NewLine)
            Write-Host "[ERROR] $m" -ForegroundColor Red
        }
    } catch {}
}
trap { Write-AuditError -Record $_ -Stage 'Terminating error'; continue }

function Set-Phase { param([string]$Name, [ValidateSet('Completed','Partial','Failed','Skipped')][string]$State, [string]$Note = '') $ScanHealth[$Name] = [pscustomobject]@{ State=$State; Note=$Note }; try { Send-Partial $Name } catch {} }
function Set-AuditProgress { param([int]$P,[string]$A,[string]$S) Write-Progress -Activity $A -Status $S -PercentComplete $P; Write-Host ("`n[{0,3}%] {1} - {2}" -f $P,$A,$S) -ForegroundColor Cyan }
function Get-Band([int]$S) { if ($S -ge 60) { 'CRITICAL' } elseif ($S -ge 30) { 'HIGH' } elseif ($S -ge 12) { 'MEDIUM' } elseif ($S -ge 4) { 'LOW' } else { 'INFO' } }
function Test-SeenOnce([string]$K) { return $SeenKeys.Add($K) }

function Add-Finding {
    param(
        [ValidateSet('Detected','Review','Info')][string]$Severity,
        [string]$Category,[string]$Name,[string]$Path,[string]$Reason,
        [string]$When = '',[string]$Fix = '',[int]$Score = -1,
        [ValidateSet('High','Medium','Low')][string]$Confidence = 'Medium',
        [string[]]$Evidence = @(),[string[]]$Timeline = @()
    )
    if ($Score -lt 0) { $Score = switch ($Severity) { 'Detected' { 25 } 'Review' { 8 } default { 0 } } }
    $key = "$Category|$Name"
    $isNew = -not $BaselineKeys.ContainsKey($key)
    $eff = if ($script:HasBaseline -and -not $isNew) { [int]($Score * 0.35) } else { $Score }
    $band = Get-Band $Score
    $Findings.Add([pscustomobject]@{ Severity=$Severity; Band=$band; Score=$Score; EffScore=$eff; New=$isNew; Confidence=$Confidence; Category=$Category; Name=$Name; Path=$Path; Reason=$Reason; Evidence=@($Evidence); When=$When; Timeline=@($Timeline); Fix=$Fix })
    $script:TotalScore += $Score; $script:EffScore += $eff
    if ($Severity -ne 'Info') {
        $c = if ($band -in 'CRITICAL','HIGH') { 'Red' } elseif ($band -eq 'MEDIUM') { 'Yellow' } else { 'DarkGray' }
        Write-Host ("    [{0}/{1}/{2}]{3} {4}: {5} - {6}" -f $band,$Score,$Confidence,$(if ($isNew) { ' NEW' } else { '' }),$Category,$Name,$Reason) -ForegroundColor $c
    }
}

function Get-CachedHostname([string]$Ip) {
    if ($DnsCache.ContainsKey($Ip)) { return $DnsCache[$Ip] }
    $n = $null; try { $t = [Net.Dns]::GetHostEntryAsync($Ip); if ($t.Wait(800)) { $n = $t.Result.HostName } } catch {}
    $DnsCache[$Ip] = $n; return $n
}
function Test-IsPrivateIp([string]$Ip) {
    if ($Ip -in @('127.0.0.1','::1','0.0.0.0')) { return $true }
    return ($Ip -match '^169\.254\.' -or $Ip -match '^10\.' -or $Ip -match '^192\.168\.' -or $Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.')
}
function Get-KeywordMatch([string]$T) { if (-not $T) { return $null }; $m = [regex]::Match($T, $KeywordRegex, 'IgnoreCase'); if ($m.Success) { return $m.Value.ToLower() }; return $null }
function Test-StrongKeyword([string]$T) { if (-not $T) { return $null }; $l = $T.ToLower(); foreach ($k in $StrongKeywords) { if ($l -match [regex]::Escape($k)) { return $k } }; return $null }
function Test-GamingAllowlist([string]$T) { if (-not $T) { return $false }; $l = $T.ToLower(); foreach ($k in $GamingAllowlist) { if ($l -match [regex]::Escape($k)) { return $true } }; return $false }

# ---------------------------------------------------------------------------
# Archive + delivery (defined early so Set-Phase can checkpoint)
# ---------------------------------------------------------------------------
function New-Zip {
    param([string]$Dest,[switch]$TextOnly)
    if (Test-Path $Dest) { Remove-Item $Dest -Force -ErrorAction SilentlyContinue }
    $te = @('.txt','.log','.json','.html','.csv')
    $files = Get-ChildItem $OutDir -File -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $TextOnly -or $te -contains $_.Extension.ToLower() }
    $fs = [IO.File]::Create($Dest)
    try {
        $a = [IO.Compression.ZipArchive]::new($fs,[IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($f in $files) {
                try {
                    $e = $a.CreateEntry($f.FullName.Substring($OutDir.Length).TrimStart('\'),[IO.Compression.CompressionLevel]::Optimal)
                    $es = $e.Open()
                    try { $ins = [IO.File]::OpenRead($f.FullName); try { $ins.CopyTo($es) } finally { $ins.Dispose() } } finally { $es.Dispose() }
                } catch {}
            }
        } finally { $a.Dispose() }
    } finally { $fs.Dispose() }
}

function Send-Webhook {
    param([string]$Path,[string]$Summary)
    if ($NoUpload) { return $false }
    if (-not $script:WebhookValid) { Write-Host '  [WARN] No valid webhook.' -ForegroundColor Yellow; return $false }
    $payload = @{ username='SelfAudit'; content=$Summary; allowed_mentions=@{ parse=@() } } | ConvertTo-Json -Depth 4
    for ($n = 1; $n -le 3; $n++) {
        $cl = $null; $fm = $null
        try {
            $cl = [Net.Http.HttpClient]::new(); $cl.Timeout = [TimeSpan]::FromSeconds(180)
            $fm = [Net.Http.MultipartFormDataContent]::new()
            $fm.Add([Net.Http.StringContent]::new($payload,[Text.Encoding]::UTF8,'application/json'),'payload_json')
            $bc = [Net.Http.ByteArrayContent]::new([IO.File]::ReadAllBytes($Path))
            $bc.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/zip')
            $fm.Add($bc,'files[0]',[IO.Path]::GetFileName($Path))
            $r = $cl.PostAsync($Webhook,$fm).GetAwaiter().GetResult(); $c = [int]$r.StatusCode
            if ($c -ge 200 -and $c -lt 300) { Write-Host '  [OK] Uploaded.' -ForegroundColor Green; return $true }
            if ($c -eq 429) { $w=5; try { $w=[int]$r.Headers.GetValues('Retry-After')|Select-Object -First 1 } catch {}; Start-Sleep ([Math]::Min(30,[Math]::Max(2,$w))); continue }
            Write-Host "  [WARN] HTTP $c" -ForegroundColor Yellow; return $false
        } catch { Write-Host "  [WARN] Attempt $n`: $($_.Exception.Message)" -ForegroundColor Yellow; Start-Sleep 3 }
        finally { if ($fm) { $fm.Dispose() }; if ($cl) { $cl.Dispose() } }
    }
    return $false
}

$script:LastPartial = Get-Date
function Send-Partial {
    param([string]$Tag)
    if ($NoUpload -or -not $script:WebhookValid) { return }
    if (((Get-Date) - $script:LastPartial).TotalSeconds -lt 45) { return }
    $script:LastPartial = Get-Date
    try {
        $p = Join-Path $env:TEMP ("partial_$(Get-Random).zip")
        New-Zip -Dest $p -TextOnly
        Send-Webhook -Path $p -Summary "**PARTIAL - $Tag** | ``$env:COMPUTERNAME`` / ``$env:USERNAME`` | still running" | Out-Null
        Remove-Item $p -Force -ErrorAction SilentlyContinue
    } catch {}
}

# ============================================================================
# Webhook resolution
# ============================================================================
function Resolve-Webhook {
    if ($Webhook) { return }
    if ($WebhookFile) {
        try {
            $raw = if ($WebhookFile -match '^https?://') { (Invoke-WebRequest -Uri $WebhookFile -UseBasicParsing -TimeoutSec 10 -EA Stop).Content } else { Get-Content -LiteralPath $WebhookFile -Raw -EA Stop }
            $Webhook = ($raw -split "`n" | Where-Object { $_ -match 'discord(app)?\.com/api/webhooks/' } | Select-Object -First 1).Trim()
        } catch { Write-Host "[WARN] Webhook file unreadable: $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    if (-not $Webhook -and $DefaultWebhookUrl) {
        try {
            $raw = (Invoke-WebRequest -Uri $DefaultWebhookUrl -UseBasicParsing -TimeoutSec 10 -EA Stop).Content
            $c = ($raw -split "`n" | Where-Object { $_ -match 'discord(app)?\.com/api/webhooks/' } | Select-Object -First 1).Trim()
            if ($c) { $Webhook = $c; Set-Content -LiteralPath $WebhookCache -Value $c -Encoding ASCII -EA SilentlyContinue }
        } catch {
            if (Test-Path $WebhookCache) { $Webhook = (Get-Content -LiteralPath $WebhookCache -Raw).Trim(); Write-Host '  [INFO] Using cached webhook.' -ForegroundColor DarkGray }
        }
    }
    $script:WebhookValid = $Webhook -match '^https://(canary\.|ptb\.)?discord(app)?\.com/api/webhooks/\d+/[\w\-]+'
}

# ============================================================================
# Elevation / output
# ============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host '[!] Not elevated. Re-launching with a UAC prompt...' -ForegroundColor Yellow
    try {
        $a = @()
        foreach ($kv in $PSBoundParameters.GetEnumerator()) {
            if ($kv.Value -is [switch]) { if ($kv.Value.IsPresent) { $a += "-$($kv.Key)" } } elseif ($kv.Value -ne '') { $a += @("-$($kv.Key)", "$($kv.Value)") }
        }
        if ($ExePath -match '\.exe$') { Start-Process -FilePath $ExePath -Verb RunAs -ArgumentList $a | Out-Null }
        elseif ($PSCommandPath) { Start-Process powershell.exe -Verb RunAs -ArgumentList (@('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $a) | Out-Null }
        exit 0
    } catch { Write-Host '[ERROR] Elevation failed.' -ForegroundColor Red; if (-not $NoPause) { [void][Console]::ReadLine() }; exit 1 }
}

$made = $false
foreach ($c in @($OutDir, (Join-Path ([Environment]::GetFolderPath('Desktop')) "SelfAudit-$Stamp"), (Join-Path ([IO.Path]::GetTempPath()) "SelfAudit-$Stamp"))) {
    try { New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null; $OutDir = $c; $made = $true; break } catch {}
}
if (-not $made) { Write-Host '[ERROR] No writable output folder.' -ForegroundColor Red; exit 1 }
$ErrorLogPath = Join-Path $OutDir "SelfAudit-errors-$Stamp.log"
try { Set-Content -LiteralPath $ErrorLogPath -Value "SelfAudit error log - $Stamp" -Encoding UTF8 } catch {}

$LogPath = Join-Path $OutDir 'audit.log'
try { Start-Transcript -Path $LogPath -Append -Force -ErrorAction Stop | Out-Null } catch {}
Write-Host "[INFO] Output: $OutDir" -ForegroundColor Cyan

Resolve-Webhook
if ($SelfExclude) { try { Add-MpPreference -ExclusionPath $BaseDir -EA Stop; Write-Host "[INFO] Self-exclusion added." -ForegroundColor Cyan } catch {} }

if ($Baseline -and (Test-Path $Baseline)) {
    try {
        $bj = Get-Content -LiteralPath $Baseline -Raw | ConvertFrom-Json
        foreach ($f in $bj.findings) { $BaselineKeys["$($f.Category)|$($f.Name)"] = $true }
        $script:HasBaseline = $true
        Write-Host "[INFO] Baseline loaded: $($BaselineKeys.Count) known indicators." -ForegroundColor Cyan
    } catch { Write-Host '[WARN] Baseline unreadable.' -ForegroundColor Yellow }
}

# ============================================================================
# Native helpers
# ============================================================================
Add-Type -ReferencedAssemblies @('System','System.Drawing','System.Windows.Forms') -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace SA {
  public class HandleRec { public uint OwnerPid; public string OwnerName; public string OwnerPath; public uint Access; public string AccessDesc; }
  public class UsnRec { public string Name; public string Action; public long FileTime; }
  public class WinRec { public string Title; public string Cls; public string Path; public string Reason; }
  public class HollowRec { public int Pid; public string Name; public ulong Base; }
  public class ModRec { public ulong Base; public ulong Size; public string Name; }
  public class ThreadRec { public int Tid; public ulong Start; public bool Backed; public string Module; }
  public class MemRec { public ulong Base; public ulong Size; public uint Protect; public bool Rwx; }
  public class ProcRec { public int Pid; public string Name; }
  public class RuleHit { public string Rule; public int Weight; public ulong Base; public string Patterns; }

  public static class N {
    [StructLayout(LayoutKind.Sequential)] public struct MBI { public ulong BaseAddress, AllocationBase; public uint AllocProtect, A1; public ulong RegionSize; public uint State, Protect, Type, A2; }
    [StructLayout(LayoutKind.Sequential)] public struct SHE { public IntPtr Object, UniqueProcessId, HandleValue; public uint GrantedAccess; public ushort BT, TypeIndex; public uint Attr, Res; }
    [StructLayout(LayoutKind.Sequential)] public struct THE { public uint Size, Usage, Tid, OwnerPid; public int BasePri, DeltaPri; public uint Flags; }
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] public struct MODW { public uint Size, ModId, Pid, Glbl, Proc; public IntPtr Base; public uint BaseSize; public IntPtr Handle; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=256)] public string Name; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string Path; }
    [StructLayout(LayoutKind.Sequential)] public struct LUID { public uint Low; public int High; }
    [StructLayout(LayoutKind.Sequential)] public struct LAA { public LUID Luid; public uint Attr; }

    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, uint p);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool DuplicateHandle(IntPtr s, IntPtr sh, IntPtr t, out IntPtr th, uint a, bool i, uint o);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] public static extern uint GetProcessId(IntPtr p);
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool QueryFullProcessImageName(IntPtr h, uint f, StringBuilder n, ref uint s);
    [DllImport("ntdll.dll")] public static extern uint NtQuerySystemInformation(int c, IntPtr b, uint l, out uint r);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualQueryEx(IntPtr p, IntPtr a, out MBI m, IntPtr l);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr p, IntPtr a, byte[] b, IntPtr s, out IntPtr r);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr CreateToolhelp32Snapshot(uint f, uint p);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern bool Module32FirstW(IntPtr s, ref MODW e);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern bool Module32NextW(IntPtr s, ref MODW e);
    [DllImport("kernel32.dll")] public static extern bool Thread32First(IntPtr s, ref THE e);
    [DllImport("kernel32.dll")] public static extern bool Thread32Next(IntPtr s, ref THE e);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenThread(uint a, bool i, uint t);
    [DllImport("ntdll.dll")] public static extern int NtQueryInformationThread(IntPtr h, int c, ref IntPtr i, int l, IntPtr r);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string n);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LookupPrivilegeValueW(string s, string n, out LUID l);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool GetTokenInformation(IntPtr t, int c, IntPtr i, int l, out int r);
    [DllImport("psapi.dll", SetLastError=true)] public static extern bool EnumDeviceDrivers(IntPtr[] b, uint cb, out uint need);
    [DllImport("psapi.dll", CharSet=CharSet.Unicode)] public static extern bool GetDeviceDriverFileNameW(IntPtr b, StringBuilder p, uint s);

    public static string PathOf(uint pid) {
      IntPtr h = OpenProcess(0x1000, false, pid);
      if (h == IntPtr.Zero) return "";
      try { var sb = new StringBuilder(1024); uint s = (uint)sb.Capacity; return QueryFullProcessImageName(h, 0, sb, ref s) ? sb.ToString() : ""; }
      finally { CloseHandle(h); }
    }

    public static List<ProcRec> ProcessList() {
      var l = new List<ProcRec>();
      uint sz = 1 << 20, ret;
      IntPtr buf = Marshal.AllocHGlobal((int)sz);
      try {
        uint st = NtQuerySystemInformation(5, buf, sz, out ret);
        while (st == 0xC0000004) { Marshal.FreeHGlobal(buf); sz = Math.Max(sz * 2, ret + (1 << 18)); buf = Marshal.AllocHGlobal((int)sz); st = NtQuerySystemInformation(5, buf, sz, out ret); }
        if (st != 0) return l;
        IntPtr cur = buf;
        for (int g = 0; g < 20000; g++) {
          uint next = (uint)Marshal.ReadInt32(cur);
          int pid = Marshal.ReadInt32(cur, 80);
          ushort nl = (ushort)Marshal.ReadInt16(cur, 56);
          IntPtr nb = Marshal.ReadIntPtr(cur, 64);
          string nm = "";
          if (nb != IntPtr.Zero && nl > 1) { try { nm = Marshal.PtrToStringUni(nb, nl / 2); } catch {} }
          l.Add(new ProcRec { Pid = pid, Name = nm });
          if (next == 0) break;
          cur = new IntPtr(cur.ToInt64() + next);
        }
      } catch {} finally { Marshal.FreeHGlobal(buf); }
      return l;
    }

    public static List<string> KernelModulePaths() {
      var l = new List<string>();
      try {
        uint need;
        EnumDeviceDrivers(null, 0, out need);
        var arr = new IntPtr[need / IntPtr.Size + 8];
        if (!EnumDeviceDrivers(arr, (uint)(arr.Length * IntPtr.Size), out need)) return l;
        int n = (int)(need / IntPtr.Size);
        for (int i = 0; i < n && i < arr.Length; i++) {
          var sb = new StringBuilder(1024);
          if (GetDeviceDriverFileNameW(arr[i], sb, 1024)) l.Add(sb.ToString());
        }
      } catch {}
      return l;
    }

    static string Desc(uint a) {
      if ((a & 0x1FFFFF) == 0x1FFFFF) return "ALL_ACCESS";
      var l = new List<string>();
      if ((a & 0x10) != 0) l.Add("VM_READ");
      if ((a & 0x20) != 0) l.Add("VM_WRITE");
      if ((a & 0x8)  != 0) l.Add("VM_OPERATION");
      if ((a & 0x2)  != 0) l.Add("CREATE_THREAD");
      return l.Count > 0 ? string.Join("|", l.ToArray()) : ("0x" + a.ToString("X"));
    }

    public static List<HandleRec> Handles(HashSet<uint> targets) {
      var outp = new List<HandleRec>();
      uint sz = 1 << 22, ret;
      IntPtr buf = Marshal.AllocHGlobal((int)sz);
      try {
        uint st = NtQuerySystemInformation(64, buf, sz, out ret);
        while (st == 0xC0000004) { Marshal.FreeHGlobal(buf); sz = Math.Max(sz * 2, ret + (1 << 20)); buf = Marshal.AllocHGlobal((int)sz); st = NtQuerySystemInformation(64, buf, sz, out ret); }
        if (st != 0) return outp;
        long count = Marshal.ReadInt64(buf);
        IntPtr cur = new IntPtr(buf.ToInt64() + 16);
        int esz = Marshal.SizeOf(typeof(SHE));
        uint me = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
        var cache = new Dictionary<uint, IntPtr>();
        for (long i = 0; i < count; i++) {
          var e = (SHE)Marshal.PtrToStructure(cur, typeof(SHE));
          cur = new IntPtr(cur.ToInt64() + esz);
          uint owner = (uint)e.UniqueProcessId.ToInt64();
          if (owner <= 4 || owner == me) continue;
          uint a = e.GrantedAccess;
          if ((a & 0x10) == 0 && (a & 0x20) == 0 && (a & 0x8) == 0 && (a & 0x2) == 0 && (a & 0x1FFFFF) != 0x1FFFFF) continue;
          IntPtr ho;
          if (!cache.TryGetValue(owner, out ho)) { ho = OpenProcess(0x40, false, owner); cache[owner] = ho; }
          if (ho == IntPtr.Zero) continue;
          IntPtr dup;
          if (DuplicateHandle(ho, e.HandleValue, GetCurrentProcess(), out dup, 0, false, 2)) {
            try {
              if (targets.Contains(GetProcessId(dup))) {
                string nm = "Unknown";
                try { nm = System.Diagnostics.Process.GetProcessById((int)owner).ProcessName; } catch {}
                outp.Add(new HandleRec { OwnerPid = owner, OwnerName = nm, OwnerPath = PathOf(owner), Access = a, AccessDesc = Desc(a) });
              }
            } finally { CloseHandle(dup); }
          }
        }
        foreach (var kv in cache) if (kv.Value != IntPtr.Zero) CloseHandle(kv.Value);
      } catch {} finally { Marshal.FreeHGlobal(buf); }
      return outp;
    }

    public static List<HollowRec> Hollow(int pid, string name) {
      var l = new List<HollowRec>();
      IntPtr h = OpenProcess(0x410, false, (uint)pid);
      if (h == IntPtr.Zero) return l;
      try {
        IntPtr a = IntPtr.Zero; IntPtr msz = new IntPtr(Marshal.SizeOf(typeof(MBI)));
        byte[] hdr = new byte[0x200]; int guard = 0;
        while (guard++ < 100000) {
          MBI m;
          if (VirtualQueryEx(h, a, out m, msz) == IntPtr.Zero) break;
          if (m.State == 0x1000 && m.Type == 0x20000 && (m.Protect & 0xF0) != 0) {
            IntPtr got;
            if (ReadProcessMemory(h, (IntPtr)m.BaseAddress, hdr, (IntPtr)hdr.Length, out got) && got.ToInt64() == hdr.Length) {
              if (hdr[0] == 0x4D && hdr[1] == 0x5A) {
                int lf = BitConverter.ToInt32(hdr, 0x3C);
                if (lf > 0 && lf < 0x1F8 && hdr[lf] == 0x50 && hdr[lf+1] == 0x45) l.Add(new HollowRec { Pid = pid, Name = name, Base = m.BaseAddress });
              }
            }
          }
          long nx = (long)(m.BaseAddress + m.RegionSize);
          if (nx <= a.ToInt64()) break;
          a = new IntPtr(nx);
        }
      } catch {} finally { CloseHandle(h); }
      return l;
    }

    public static List<ModRec> Modules(int pid) {
      var l = new List<ModRec>();
      IntPtr s = CreateToolhelp32Snapshot(0x8 | 0x10, (uint)pid);
      if (s == IntPtr.Zero || s.ToInt64() == -1) return l;
      try {
        var e = new MODW(); e.Size = (uint)Marshal.SizeOf(typeof(MODW));
        if (Module32FirstW(s, ref e)) { do { l.Add(new ModRec { Base = (ulong)e.Base.ToInt64(), Size = e.BaseSize, Name = e.Name }); } while (Module32NextW(s, ref e)); }
      } catch {} finally { CloseHandle(s); }
      return l;
    }

    public static List<ThreadRec> Threads(int pid) {
      var l = new List<ThreadRec>();
      var mods = Modules(pid);
      IntPtr s = CreateToolhelp32Snapshot(0x4, 0);
      if (s == IntPtr.Zero || s.ToInt64() == -1) return l;
      try {
        var e = new THE(); e.Size = (uint)Marshal.SizeOf(typeof(THE));
        if (Thread32First(s, ref e)) {
          do {
            if ((int)e.OwnerPid != pid) continue;
            IntPtr h = OpenThread(0x0800, false, e.Tid);
            if (h == IntPtr.Zero) continue;
            try {
              IntPtr start = IntPtr.Zero;
              if (NtQueryInformationThread(h, 9, ref start, IntPtr.Size, IntPtr.Zero) == 0 && start != IntPtr.Zero) {
                ulong v = (ulong)start.ToInt64(); string owner = null;
                foreach (var m in mods) { if (v >= m.Base && v < m.Base + m.Size) { owner = m.Name; break; } }
                l.Add(new ThreadRec { Tid = (int)e.Tid, Start = v, Backed = owner != null, Module = owner });
              }
            } catch {} finally { CloseHandle(h); }
          } while (Thread32Next(s, ref e));
        }
      } catch {} finally { CloseHandle(s); }
      return l;
    }

    public static List<MemRec> Regions(int pid, int max) {
      var l = new List<MemRec>();
      IntPtr h = OpenProcess(0x410, false, (uint)pid);
      if (h == IntPtr.Zero) return l;
      try {
        IntPtr a = IntPtr.Zero; IntPtr msz = new IntPtr(Marshal.SizeOf(typeof(MBI)));
        int guard = 0;
        while (guard++ < max) {
          MBI m;
          if (VirtualQueryEx(h, a, out m, msz) == IntPtr.Zero) break;
          if (m.State == 0x1000) {
            bool rwx = (m.Protect & 0x40) != 0 || (m.Protect & 0x80) != 0;
            bool privExec = m.Type == 0x20000 && ((m.Protect & 0x10) != 0 || (m.Protect & 0x20) != 0);
            if (rwx || privExec) l.Add(new MemRec { Base = m.BaseAddress, Size = m.RegionSize, Protect = m.Protect, Rwx = rwx });
          }
          long nx = (long)(m.BaseAddress + m.RegionSize);
          if (nx <= a.ToInt64()) break;
          a = new IntPtr(nx);
        }
      } catch {} finally { CloseHandle(h); }
      return l;
    }

    public static byte[] ReadMem(IntPtr h, ulong addr, int len) {
      byte[] b = new byte[len]; IntPtr got;
      if (!ReadProcessMemory(h, new IntPtr((long)addr), b, (IntPtr)len, out got)) return null;
      if (got.ToInt64() != len) return null;
      return b;
    }

    public static bool DebugPriv(int pid) {
      IntPtr h = OpenProcess(0x1000, false, (uint)pid);
      if (h == IntPtr.Zero) return false;
      IntPtr t = IntPtr.Zero;
      try {
        if (!OpenProcessToken(h, 0x8, out t)) return false;
        LUID luid;
        if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out luid)) return false;
        int need; GetTokenInformation(t, 3, IntPtr.Zero, 0, out need);
        if (need <= 0) return false;
        IntPtr buf = Marshal.AllocHGlobal(need);
        try {
          if (!GetTokenInformation(t, 3, buf, need, out need)) return false;
          int cnt = Marshal.ReadInt32(buf); int esz = Marshal.SizeOf(typeof(LAA));
          for (int i = 0; i < cnt; i++) {
            IntPtr off = new IntPtr(buf.ToInt64() + 4 + (i * esz));
            var e = (LAA)Marshal.PtrToStructure(off, typeof(LAA));
            if (e.Luid.Low == luid.Low && e.Luid.High == luid.High) return (e.Attr & 2) != 0;
          }
          return false;
        } finally { Marshal.FreeHGlobal(buf); }
      } catch { return false; } finally { if (t != IntPtr.Zero) CloseHandle(t); CloseHandle(h); }
    }
  }

  public static class Y {
    static int Find(byte[] b, byte[] p) {
      if (p.Length == 0 || p.Length > b.Length) return -1;
      byte f = p[0]; int lim = b.Length - p.Length;
      for (int i = 0; i <= lim; i++) {
        if (b[i] != f) continue;
        int j = 1;
        while (j < p.Length && b[i + j] == p[j]) j++;
        if (j == p.Length) return i;
      }
      return -1;
    }

    public static List<RuleHit> Scan(int pid, string[] names, int[] weights, int[] mins, byte[][] pats, int[] patRule, int maxRegions, long maxBytes) {
      var hits = new List<RuleHit>();
      IntPtr h = N.OpenProcess(0x410, false, (uint)pid);
      if (h == IntPtr.Zero) return hits;
      try {
        IntPtr a = IntPtr.Zero; IntPtr msz = new IntPtr(Marshal.SizeOf(typeof(N.MBI)));
        long used = 0; int scanned = 0;
        while (scanned < maxRegions && used < maxBytes) {
          N.MBI m;
          if (N.VirtualQueryEx(h, a, out m, msz) == IntPtr.Zero) break;
          long nx = (long)(m.BaseAddress + m.RegionSize);
          bool ok = m.State == 0x1000 && m.Type == 0x20000 && m.RegionSize >= 0x400 && m.RegionSize <= 0x800000
                    && ((m.Protect & 0x10) != 0 || (m.Protect & 0x20) != 0 || (m.Protect & 0x40) != 0 || (m.Protect & 0x80) != 0);
          if (ok) {
            scanned++; used += (long)m.RegionSize;
            var buf = N.ReadMem(h, m.BaseAddress, (int)m.RegionSize);
            if (buf != null) {
              var count = new int[names.Length];
              var first = new int[names.Length];
              for (int i = 0; i < names.Length; i++) first[i] = -1;
              var seenPat = new bool[pats.Length];
              for (int p = 0; p < pats.Length; p++) {
                int off = Find(buf, pats[p]);
                if (off < 0) continue;
                seenPat[p] = true;
                int r = patRule[p];
                count[r]++;
                if (first[r] < 0) first[r] = off;
              }
              for (int r = 0; r < names.Length; r++) {
                if (count[r] >= mins[r] && count[r] > 0) {
                  var sb = new StringBuilder();
                  int shown = 0;
                  for (int p = 0; p < pats.Length && shown < 4; p++) {
                    if (patRule[p] == r && seenPat[p]) { if (sb.Length > 0) sb.Append(", "); sb.Append(Encoding.ASCII.GetString(pats[p])); shown++; }
                  }
                  hits.Add(new RuleHit { Rule = names[r], Weight = weights[r], Base = m.BaseAddress + (ulong)first[r], Patterns = sb.ToString() });
                }
              }
            }
          }
          if (nx <= a.ToInt64()) break;
          a = new IntPtr(nx);
        }
      } catch {} finally { N.CloseHandle(h); }
      return hits;
    }
  }

  public static class W {
    delegate bool EnumProc(IntPtr h, IntPtr l);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool GetWindowDisplayAffinity(IntPtr h, out uint a);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
    [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW")] static extern IntPtr GetWindowLongPtr(IntPtr h, int i);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int m);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassNameW(IntPtr h, StringBuilder s, int m);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }

    public static List<WinRec> Scan() {
      var l = new List<WinRec>();
      uint me = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
      var seen = new HashSet<uint>();
      EnumWindows(delegate(IntPtr h, IntPtr x) {
        try {
          if (!IsWindowVisible(h)) return true;
          uint pid; GetWindowThreadProcessId(h, out pid);
          if (pid == me || !seen.Add(pid)) return true;
          string path = N.PathOf(pid);
          if (path == "") return true;
          var t = new StringBuilder(256); GetWindowTextW(h, t, 256);
          var c = new StringBuilder(256); GetClassNameW(h, c, 256);
          uint aff;
          if (GetWindowDisplayAffinity(h, out aff) && aff != 0) l.Add(new WinRec { Title = t.ToString(), Cls = c.ToString(), Path = path, Reason = (aff == 0x11 ? "WindowExcludedFromCapture" : "WindowBlackedOut") });
          else {
            long ex = GetWindowLongPtr(h, -20).ToInt64(); RECT r;
            if ((ex & 0x80000) != 0 && (ex & 0x20) != 0 && (ex & 0x8) != 0 && GetWindowRect(h, out r) && r.R - r.L >= 300 && r.B - r.T >= 300)
              l.Add(new WinRec { Title = t.ToString(), Cls = c.ToString(), Path = path, Reason = string.Format("ClickThroughOverlay {0}x{1}", r.R - r.L, r.B - r.T) });
          }
        } catch {}
        return true;
      }, IntPtr.Zero);
      return l;
    }
  }

  public static class U {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern SafeFileHandle CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool DeviceIoControl(SafeFileHandle d, uint c, byte[] i, int il, byte[] o, int ol, out int r, IntPtr ov);

    public static List<UsnRec> Read(TimeSpan window, int max) {
      var l = new List<UsnRec>();
      string drive = System.IO.Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).TrimEnd('\\');
      using (var v = CreateFileW(@"\\.\" + drive, 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
        if (v.IsInvalid) return l;
        byte[] q = new byte[80]; int got;
        if (!DeviceIoControl(v, 0x000900F4, null, 0, q, q.Length, out got, IntPtr.Zero)) return l;
        ulong jid = BitConverter.ToUInt64(q, 0);
        long next = BitConverter.ToInt64(q, 8);
        DateTime since = DateTime.UtcNow - window;
        byte[] req = new byte[40]; byte[] buf = new byte[1 << 20];
        var clock = System.Diagnostics.Stopwatch.StartNew();
        while (clock.Elapsed.TotalSeconds < 15 && l.Count < max) {
          BitConverter.GetBytes(next).CopyTo(req, 0);
          BitConverter.GetBytes(0x100 | 0x200 | 0x2000).CopyTo(req, 8);
          BitConverter.GetBytes(jid).CopyTo(req, 32);
          if (!DeviceIoControl(v, 0x000900BB, req, req.Length, buf, buf.Length, out got, IntPtr.Zero) || got <= 8) break;
          long nn = BitConverter.ToInt64(buf, 0);
          int o = 8;
          while (o + 60 <= got) {
            int len = BitConverter.ToInt32(buf, o);
            if (len <= 0 || o + len > got) break;
            int maj = BitConverter.ToUInt16(buf, o + 4);
            int to = maj >= 3 ? 48 : 32;
            long ts = BitConverter.ToInt64(buf, o + to);
            uint rs = BitConverter.ToUInt32(buf, o + to + 8);
            int nl = BitConverter.ToUInt16(buf, o + to + 24);
            int no = BitConverter.ToUInt16(buf, o + to + 26);
            string nm = Encoding.Unicode.GetString(buf, o + no, nl);
            o += len;
            DateTime w; try { w = DateTime.FromFileTimeUtc(ts); } catch { continue; }
            if (w < since) continue;
            l.Add(new UsnRec { Name = nm, Action = (rs & 0x200) != 0 ? "Deleted" : (rs & 0x2000) != 0 ? "Renamed to" : "Created", FileTime = ts });
          }
          if (nn <= next) break;
          next = nn;
        }
      }
      return l;
    }
  }

  public static class Shot {
    public static void Save(string path, int x, int y, int w, int h) {
      using (var b = new Bitmap(w, h, PixelFormat.Format24bppRgb))
      using (var g = Graphics.FromImage(b)) { g.CopyFromScreen(x, y, 0, 0, new Size(w, h)); b.Save(path, ImageFormat.Png); }
    }
  }
}
'@

# ============================================================================
# Signature / reputation engines
# ============================================================================
$LeakedSerials = @('43BB437D609866286DD839E1D00309F5','14781BC862E8DC503A559346F5DCC518')
$SystemNames = @('svchost','csrss','lsass','smss','wininit','winlogon','services','dwm','conhost','rundll32','taskhostw','spoolsv','runtimebroker','sihost','fontdrvhost','dllhost','ctfmon','searchindexer','wmiprvse','lsaiso','audiodg')

function Get-SigVerdict([string]$Path) {
    $r = @{ Verdict='Unsigned'; Publisher='Unknown' }
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { $r.Verdict='Missing'; return $r }
    if ($SigCache.ContainsKey($Path)) { return $SigCache[$Path] }
    if ($Path -like '*\WindowsApps\*' -or $Path -like '*\SystemApps\*' -or $Path -like '*\System32\*' -or $Path -like '*\SysWOW64\*') {
        $vi = try { (Get-Item -LiteralPath $Path).VersionInfo } catch { $null }
        $r.Verdict='Valid'; $r.Publisher = if ($vi -and $vi.CompanyName) { $vi.CompanyName } else { 'Windows component' }
        $SigCache[$Path]=$r; return $r
    }
    $sig = try { Get-AuthenticodeSignature -LiteralPath $Path -EA Stop } catch { $null }
    $cert = if ($sig) { $sig.SignerCertificate } else { $null }
    if (-not $cert) { try { $raw=[Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($Path); if ($raw) { $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($raw) } } catch {} }
    $vi2 = try { (Get-Item -LiteralPath $Path).VersionInfo } catch { $null }
    if ($vi2 -and $vi2.CompanyName) { $r.Publisher = $vi2.CompanyName }
    if (-not $cert) { $SigCache[$Path]=$r; return $r }
    $r.Publisher = ($cert.Subject -replace '^CN="?([^",]+)"?.*','$1')
    if ($LeakedSerials -contains $cert.SerialNumber) { $r.Verdict='LeakedCertificate'; $SigCache[$Path]=$r; return $r }
    $ch = [Security.Cryptography.X509Certificates.X509Chain]::new()
    $ch.ChainPolicy.RevocationMode = 'NoCheck'
    $null = $ch.Build($cert)
    $n = $ch.ChainElements.Count
    $root = if ($n -gt 0) { $ch.ChainElements[$n-1].Certificate } else { $null }
    $genuine = $false
    if ($root) { $genuine = (Test-Path "Cert:\LocalMachine\AuthRoot\$($root.Thumbprint)") -or ($root.Subject -like '*Microsoft*') }
    if ($cert.Subject -eq $cert.Issuer -or $n -le 1) { $r.Verdict = if ($genuine) { 'Valid' } else { 'SelfSignedCert' }; $SigCache[$Path]=$r; return $r }
    if ($sig -and $sig.Status -eq 'HashMismatch') { $r.Verdict='TamperedBinary'; $SigCache[$Path]=$r; return $r }
    if ($sig -and ($sig.Status -eq 'NotTrusted' -or $sig.StatusMessage -like '*untrusted root*')) { $r.Verdict='UntrustedRoot'; $SigCache[$Path]=$r; return $r }
    if ($sig -and $sig.Status -ne 'Valid' -and -not $sig.TimeStamperCertificate -and $cert.NotAfter -lt (Get-Date) -and -not $Path.StartsWith($WinRoot,'OrdinalIgnoreCase')) { $r.Verdict='ExpiredCertificate'; $SigCache[$Path]=$r; return $r }
    $r.Verdict = if ($genuine) { 'Valid' } else { 'RogueRootCA' }
    $SigCache[$Path]=$r; return $r
}

function Get-CachedHash([string]$Path) {
    try {
        $fi = Get-Item -LiteralPath $Path -EA Stop
        $k = '{0}|{1}|{2}' -f $Path,$fi.Length,$fi.LastWriteTimeUtc.Ticks
        if ($HashCache.ContainsKey($k)) { return $HashCache[$k] }
        $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -EA Stop).Hash
        $HashCache[$k] = $h; return $h
    } catch { return $null }
}

function Get-HashReputation([string]$Sha) {
    if ($script:RepCache.ContainsKey($Sha)) { return $script:RepCache[$Sha] }
    if ($script:RepBudget -le 0) { return $null }
    $script:RepBudget--; $Stats.RepLookups++
    $res = @{ Verdict='unknown'; Detail='' }
    try {
        if ($VTApiKey) {
            $vt = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$Sha" -Headers @{ 'x-apikey' = $VTApiKey } -TimeoutSec 10 -EA Stop
            $st = $vt.data.attributes.last_analysis_stats
            $mal = [int]$st.malicious
            $res.Verdict = if ($mal -ge 3) { 'malicious' } elseif ($mal -ge 1) { 'suspicious' } else { 'clean' }
            $res.Detail = "VirusTotal: $mal malicious / $([int]$st.suspicious) suspicious of $([int]$st.harmless + [int]$st.undetected + $mal)"
        } else {
            $r = Invoke-RestMethod -Uri 'https://mb-api.abuse.ch/api/v1/' -Method Post -Body @{ query='get_info'; hash=$Sha } -TimeoutSec 10 -EA Stop
            if ($r.query_status -eq 'ok' -and $r.data) {
                $res.Verdict='malicious'; $res.Detail = "MalwareBazaar: $($r.data[0].signature) [$($r.data[0].file_type)] first seen $($r.data[0].first_seen)"
            } else { $res.Verdict='clean'; $res.Detail='MalwareBazaar: not present' }
        }
    } catch { $res.Verdict='error' }
    $script:RepCache[$Sha] = $res
    return $res
}

function Get-CheatStrings([string]$Path) {
    try {
        $fi = Get-Item -LiteralPath $Path -EA Stop
        if ($fi.Length -le 0 -or $fi.Length -gt 64MB) { return $null }
        $b = [IO.File]::ReadAllBytes($Path)
        for ($i=0;$i -lt $b.Length;$i++) { if ($b[$i] -ge 65 -and $b[$i] -le 90) { $b[$i] = $b[$i] + 32 } }
        $hay = [Text.Encoding]::GetEncoding(28591).GetString($b)
        foreach ($m in $SingleMarkerSignatures) {
            $l = $m.ToLower()
            if ($hay.Contains($l) -or $hay.Contains((($l.ToCharArray() | ForEach-Object { "$_`0" }) -join ''))) { return [pscustomobject]@{ Family='single-marker'; Markers=@($m); Strong=$true } }
        }
        foreach ($f in $StringSignatures.Keys) {
            $hits = @()
            foreach ($m in $StringSignatures[$f]) {
                $l = $m.ToLower()
                if ($hay.Contains($l) -or $hay.Contains((($l.ToCharArray() | ForEach-Object { "$_`0" }) -join ''))) { $hits += $m }
            }
            if ($hits.Count -ge 2) { return [pscustomobject]@{ Family=$f; Markers=$hits; Strong=$true } }
            if ($hits.Count -eq 1) { return [pscustomobject]@{ Family=$f; Markers=$hits; Strong=$false } }
        }
    } catch {}
    return $null
}

function Get-Tool {
    param([string]$Name,[string]$Url,[string]$Exe)
    $dir = Join-Path $ToolRoot $Name; $p = Join-Path $dir $Exe
    if (Test-Path -LiteralPath $p) { return $p }
    try {
        New-Item -ItemType Directory -Path $ToolRoot -Force -EA Stop | Out-Null
        $z = Join-Path $ToolRoot "$Name.zip"
        Invoke-WebRequest -Uri $Url -OutFile $z -UseBasicParsing -TimeoutSec 30 -EA Stop
        if (Test-Path $dir) { Remove-Item -LiteralPath $dir -Recurse -Force -EA SilentlyContinue }
        [IO.Compression.ZipFile]::ExtractToDirectory($z, $dir)
        Remove-Item -LiteralPath $z -Force -EA SilentlyContinue
        $f = Get-ChildItem -Path $dir -Filter $Exe -Recurse -EA SilentlyContinue | Select-Object -First 1
        if ($f) { return $f.FullName }
    } catch { Write-Host "  [WARN] $Name fetch failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    return $null
}

function Invoke-BinaryEvaluation {
    param([string]$Name,[string]$Path,[string]$Pid = '',[string]$Source = 'Process')
    if (-not $Path) { return }
    $sig = Get-SigVerdict $Path
    $hash = Get-CachedHash $Path
    if ($hash -and $CheatHashes.ContainsKey($hash)) { Add-Finding Detected $Source $Name "PID $Pid" "Known cheat hash: $($CheatHashes[$hash])" '' 'Verify hash and source' -Score 70 -Confidence High -Evidence @("SHA256 $hash"); return }
    if ($hash -and $UnconfirmedHashes.ContainsKey($hash)) { Add-Finding Review $Source $Name "PID $Pid" "Unconfirmed sample hash: $($UnconfirmedHashes[$hash])" '' 'Confirm manually' -Score 25 -Confidence Medium -Evidence @("SHA256 $hash"); return }
    $str = Get-CheatStrings $Path
    if ($str -and $str.Strong) { Add-Finding Detected $Source $Name "PID $Pid" "Cheat string signature: $($str.Family) [$($str.Markers -join ', ')]" '' 'Verify origin' -Score 55 -Confidence High -Evidence @("Markers: $($str.Markers -join ', ')"); return }
    $strong = Test-StrongKeyword $Name
    if ($strong) { Add-Finding Detected $Source $Name "PID $Pid" "Strong cheat keyword in name: $strong" '' 'A name match alone is not proof' -Score 30 -Confidence Medium -Evidence @("Keyword '$strong'"); return }
    if ($str) { Add-Finding Review $Source $Name "PID $Pid" "Single string marker: $($str.Family) [$($str.Markers -join ', ')]" '' '' -Score 12 -Confidence Low; return }
    $weak = Get-KeywordMatch $Name
    if ($weak) { Add-Finding Review $Source $Name "PID $Pid" "Weak cheat keyword in name: $weak" '' '' -Score 10 -Confidence Low; return }
    if ($sig.Verdict -eq 'Valid' -or $Path -match '\\Program Files') { return }
    if (Test-GamingAllowlist $Name) { Add-Finding Info $Source $Name "PID $Pid" "Unsigned but allowlisted gaming software" '' '' -Score 0; return }
    $rep = if ($hash -and -not $NoReputation) { Get-HashReputation $hash } else { $null }
    if ($rep -and $rep.Verdict -eq 'malicious') { Add-Finding Detected $Source $Name "PID $Pid" "Reputation hit: $($rep.Detail)" '' 'Check the source' -Score 55 -Confidence High -Evidence @($rep.Detail,"SHA256 $hash"); return }
    if ($rep -and $rep.Verdict -eq 'suspicious') { Add-Finding Detected $Source $Name "PID $Pid" "Reputation: $($rep.Detail)" '' 'Check the source' -Score 30 -Confidence Medium; return }
    Add-Finding Detected $Source $Name "PID $Pid" "Unsigned binary, unknown reputation ($($sig.Verdict))" '' 'Review the publisher and origin' -Score 20 -Confidence Low -Evidence @("Signature: $($sig.Verdict)")
}

# ============================================================================
# 1. Security posture + boot integrity
# ============================================================================
Set-AuditProgress 4 'Self-audit' 'Checking security posture and boot integrity...'
Write-Host "`n=== Security posture ===" -ForegroundColor Magenta
$ci = try { Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard -EA Stop } catch { $null }
$hvci = $false
if ($ci -and ($ci.SecurityServicesRunning -contains 2)) { $hvci = $true }
if (-not $hvci) { $k = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -EA SilentlyContinue; if ($k -and $k.Enabled -eq 1) { $hvci = $true } }
$Meta['coreIsolation'] = $hvci
if ($hvci) { Write-Host '  HVCI: ON' -ForegroundColor Green } else { Add-Finding Detected 'Security' 'Core Isolation' 'DeviceGuard' 'Memory Integrity is OFF' '' 'Enable Memory Integrity, reboot' -Score 18 -Confidence High }

try { if (Confirm-SecureBootUEFI -EA Stop) { Write-Host '  Secure Boot: ON' -ForegroundColor Green; $Meta['secureBoot'] = $true } }
catch { Add-Finding Review 'Security' 'Secure Boot' 'UEFI' 'Secure Boot is off or unavailable' '' 'Enable Secure Boot' -Score 10 -Confidence Medium; $Meta['secureBoot'] = $false }

try {
    $bcd = (& bcdedit /enum '{current}' 2>$null) -join "`n"
    if ($bcd -match 'testsigning\s+Yes') { Add-Finding Detected 'Security' 'Test signing' 'bcdedit' 'Test signing is enabled' '' 'bcdedit /set testsigning off' -Score 20 -Confidence High }
    if ($bcd -match 'nointegritychecks\s+Yes') { Add-Finding Detected 'Security' 'Integrity checks' 'bcdedit' 'Driver integrity checks disabled' '' 'bcdedit /set nointegritychecks off' -Score 25 -Confidence High }
    if ($bcd -match 'hypervisorlaunchtype\s+Off') { Add-Finding Review 'Security' 'Hypervisor' 'bcdedit' 'Hypervisor launch disabled' '' 'bcdedit /set hypervisorlaunchtype auto' -Score 8 -Confidence Medium }
} catch {}

$mp = try { Get-MpComputerStatus -EA Stop } catch { $null }
if ($mp) {
    if ($mp.RealTimeProtectionEnabled) { Write-Host '  Real-time protection: ON' -ForegroundColor Green }
    else { Add-Finding Detected 'Security' 'Antivirus' 'Defender' 'Real-time protection is OFF' '' 'Turn it back on' -Score 20 -Confidence High }
    if (-not $mp.IsTamperProtected) { Add-Finding Review 'Security' 'Tamper protection' 'Defender' 'Tamper protection is OFF' '' 'Enable it in Windows Security' -Score 10 -Confidence High }
    if ($mp.AntivirusSignatureAge -gt 7) { Add-Finding Review 'Security' 'Signatures' 'Defender' "Signatures $($mp.AntivirusSignatureAge)d old" '' 'Update' -Score 6 }
    $Meta['defender'] = @{ rtp=$mp.RealTimeProtectionEnabled; tamper=$mp.IsTamperProtected; sigAge=$mp.AntivirusSignatureAge }
} else { Set-Phase 'Defender' 'Failed' 'Get-MpComputerStatus unavailable' }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -EA SilentlyContinue).DisableAntiSpyware -eq 1) { Add-Finding Detected 'Security' 'Defender policy' 'DisableAntiSpyware' 'Defender disabled by policy' '' '' -Score 22 -Confidence High }

$ex = @()
try {
    $pp = Get-MpPreference -EA Stop
    foreach ($x in $pp.ExclusionPath) { if ($x) { $ex += "Path: $x" } }
    foreach ($x in $pp.ExclusionProcess) { if ($x) { $ex += "Process: $x" } }
    foreach ($x in $pp.ExclusionExtension) { if ($x) { $ex += "Extension: $x" } }
} catch {}
foreach ($h in @('HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths','HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes')) { if (Test-Path $h) { (Get-Item $h).GetValueNames() | ForEach-Object { if ($_) { $ex += "Reg: $_" } } } }
$ex = @($ex | Select-Object -Unique)
$Meta['exclusions'] = $ex
foreach ($x in $ex) { Add-Finding Detected 'Security' 'AV exclusion' $x 'Exclusion creates a scanner blind spot' '' 'Remove unless intentional' -Score 14 -Confidence High }

foreach ($pth in @('HKLM:\SOFTWARE\NVIDIA Corporation\Global\NvApp\ShadowPlay\FTS','HKCU:\SOFTWARE\NVIDIA Corporation\Global\NvApp\ShadowPlay\FTS')) {
    if (-not (Test-Path $pth)) { continue }
    $it = Get-Item $pth
    foreach ($v in $it.GetValueNames()) { if ($v.Trim('{}').ToUpper() -eq '497B8458-4244-4EE6-BFEA-F3D2BA294F21' -and (@(36,0x24) -contains [int]$it.GetValue($v))) { Add-Finding Detected 'Security' 'Streamproof' $pth "FTS override=$($it.GetValue($v))" '' 'Delete that value' -Score 12 -Confidence High } }
}

$mons = [Windows.Forms.Screen]::AllScreens
$Meta['monitors'] = @($mons | ForEach-Object { "$($_.DeviceName) $($_.Bounds.Width)x$($_.Bounds.Height) primary=$($_.Primary)" })
if ($mons.Count -gt 1) { Add-Finding Detected 'Hardware' 'Multi-monitor' "$($mons.Count) displays" 'More than one active display' '' 'Unplug the second monitor' -Score 10 -Confidence High }

foreach ($d in (Get-CimInstance Win32_PnPEntity -EA SilentlyContinue | Where-Object { $_.DeviceID -like 'PCI\*' })) {
    if ($d.DeviceID -match 'VEN_0403&DEV_601F|VEN_10EE&DEV_(70|00|90)|VEN_10EE') { Add-Finding Detected 'Hardware' 'DMA card' $d.Name 'Known DMA FPGA vendor/device signature' '' 'Expected on DMA' -Score 22 -Confidence High }
    elseif ([int]$d.ConfigManagerErrorCode -ne 0 -and $d.Name -eq 'PCI Device' -and $d.DeviceID -notmatch 'VEN_(8086|1022|10EC|10DE)') { Add-Finding Review 'Hardware' 'Driverless PCIe device' $d.DeviceID 'Possible custom DMA firmware' '' '' -Score 8 -Confidence Low }
}

try {
    $hdr = (Invoke-WebRequest -Uri 'https://www.cloudflare.com' -Method Head -TimeoutSec 6 -EA Stop).Headers
    if ($hdr.Date) { $skew = [Math]::Abs(((Get-Date).ToUniversalTime() - $hdr.Date.ToUniversalTime()).TotalMinutes); $Meta['clockSkewMinutes'] = [int]$skew; if ($skew -gt 5) { Add-Finding Detected 'Tamper' 'System clock' 'ClockSkew' "Clock is off by $([int]$skew) minutes - timeline evidence is unreliable" '' 'Sync the clock' -Score 18 -Confidence High } }
} catch {}
Set-Phase 'Security posture' 'Completed'

# ============================================================================
# 2. Identity
# ============================================================================
Set-AuditProgress 8 'Self-audit' 'Collecting identity...'
$idLines = [System.Collections.Generic.List[string]]::new(); $idLines.Add("Identity - $Stamp")
function Add-IdLine([string]$T) { $idLines.Add($T); Write-Host "  $T" -ForegroundColor DarkGray }
Add-IdLine "User: $env:USERNAME"; Add-IdLine "Computer: $env:COMPUTERNAME"
try { $mg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -EA Stop).MachineGuid; Add-IdLine "Machine GUID: $mg"; $Meta['machineGuid']=$mg } catch {}
try { $c = Get-CimInstance Win32_Processor -EA Stop | Select-Object -First 1; Add-IdLine "CPU: $($c.Name) | $($c.ProcessorId)" } catch {}
try { $b = Get-CimInstance Win32_BaseBoard -EA Stop | Select-Object -First 1; Add-IdLine "Board: $($b.Manufacturer) $($b.Product)" } catch {}
try { foreach ($m in @(Get-CimInstance Win32_NetworkAdapter -EA Stop | Where-Object { $_.MACAddress -and $_.PhysicalAdapter })) { Add-IdLine "MAC: $($m.MACAddress) ($($m.Name))" } } catch {}
try { foreach ($l in @(Get-NetIPAddress -AddressFamily IPv4 -EA Stop | Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -ExpandProperty IPAddress)) { Add-IdLine "Local IP: $l" } } catch {}
try { $pub = (Invoke-RestMethod 'https://api.ipify.org?format=json' -TimeoutSec 5 -EA Stop).ip; Add-IdLine "Public IP: $pub"; $Meta['publicIp']=$pub; Set-Phase 'Public IP' 'Completed' } catch { Set-Phase 'Public IP' 'Failed' }
try { $s = Get-ItemProperty 'HKCU:\Software\Valve\Steam' -EA Stop; if ($s.AutoLoginUser) { Add-IdLine "Steam: $($s.AutoLoginUser)" }; $a2 = Get-ItemProperty 'HKCU:\Software\Valve\Steam\ActiveProcess' -EA SilentlyContinue; if ($a2 -and $a2.ActiveUser) { Add-IdLine "SteamID64: $($a2.ActiveUser)" } } catch {}
try {
    $ldb = Join-Path $env:APPDATA 'discord\Local Storage\leveldb'
    if (Test-Path $ldb) { $f2 = @(); foreach ($f in (Get-ChildItem $ldb -File -EA SilentlyContinue | Select-Object -First 20)) { try { $t = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($f.FullName)); foreach ($m in [regex]::Matches($t,'"user_id":"(\d{17,20})"')) { $f2 += $m.Groups[1].Value } } catch {} }; $f2 = @($f2 | Select-Object -Unique -First 3); if ($f2.Count) { Add-IdLine "Discord IDs: $($f2 -join ', ')" } }
} catch {}
try { $idLines | Set-Content -LiteralPath (Join-Path $OutDir 'identity.txt') -Encoding UTF8 -EA Stop; Set-Phase 'Identity' 'Completed' } catch { Set-Phase 'Identity' 'Failed' }

# ============================================================================
# 3. Rootkit checks: hidden processes and hidden drivers
# ============================================================================
Set-AuditProgress 11 'Self-audit' 'Running rootkit cross-view checks...'
Write-Host "`n=== Rootkit cross-view ===" -ForegroundColor Magenta
$umPids = @(Get-Process -EA SilentlyContinue | Select-Object -ExpandProperty Id)
$cimPids = @(Get-CimInstance Win32_Process -EA SilentlyContinue | Select-Object -ExpandProperty ProcessId)
$krnl = @([SA.N]::ProcessList())
$hidden = @($krnl | Where-Object { $_.Pid -gt 4 -and $_.Pid -ne $PID -and ($umPids -notcontains $_.Pid) -and ($cimPids -notcontains $_.Pid) })
foreach ($h in $hidden) { Add-Finding Detected 'Rootkit' "$($h.Name) (PID $($h.Pid))" 'NtQuerySystemInformation' 'Process is visible to the kernel but not to user-mode enumeration - hidden process' '' 'Strong rootkit indicator' -Score 65 -Confidence High }
if ($hidden.Count -eq 0) { Write-Host '  No hidden processes' -ForegroundColor Green }
Set-Phase 'Hidden process check' 'Completed'

try {
    $kmods = @([SA.N]::KernelModulePaths() | ForEach-Object { ($_ -replace '^\\\?\?\\','') -replace '^\\SystemRoot\\',$WinRoot })
    $knownDrvFiles = @(Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.PathName } | ForEach-Object { [IO.Path]::GetFileName($_.PathName).ToLower() })
    $hiddenDrv = @($kmods | Where-Object { $b2 = [IO.Path]::GetFileName($_).ToLower(); $b2 -and ($knownDrvFiles -notcontains $b2) -and ($_ -notmatch '\\(ntoskrnl|hal|ci|clfs|win32k|fltmgr|ndis|tcpip)') })
    foreach ($d in $hiddenDrv) { Add-Finding Detected 'Rootkit' 'Hidden kernel module' $d 'Loaded driver with no matching service entry' '' 'Possible DKOM-hidden driver' -Score 55 -Confidence Medium }
    if ($hiddenDrv.Count -eq 0) { Write-Host '  No hidden kernel modules' -ForegroundColor Green }
    Set-Phase 'Hidden driver check' 'Completed'
} catch { Set-Phase 'Hidden driver check' 'Failed' }

# ============================================================================
# 4. Processes
# ============================================================================
Set-AuditProgress 15 'Self-audit' 'Reviewing processes...'
Write-Host "`n=== Processes ===" -ForegroundColor Magenta
$ownPid = $PID
$procRows = [System.Collections.Generic.List[object]]::new()
foreach ($p in (Get-Process -EA SilentlyContinue)) {
    if ($p.Id -le 4 -or $p.Id -eq $ownPid) { continue }
    $Stats.Processes++
    $path = try { $p.Path } catch { '' }
    $nm = $p.ProcessName
    $hc = try { $p.HandleCount } catch { 0 }
    $st = try { $p.StartTime.ToString('yyyy-MM-dd HH:mm') } catch { '' }
    if ($nm.ToLower() -match '^(python|pythonw|py|node)$') { Add-Finding Detected 'Process' $nm "PID $($p.Id)" 'Script runtime running - real scanners terminate these' '' 'Close before a real session' -Score 15 -Confidence Medium }
    if (-not $path) { $procRows.Add([pscustomobject]@{Name=$nm;Pid=$p.Id;Path='';Verdict='Unreadable';Publisher='';Handles=$hc;Started=$st}); continue }
    $sig = Get-SigVerdict $path
    if ($sig.Verdict -eq 'Valid' -and $path.StartsWith($WinRoot,'OrdinalIgnoreCase')) { $procRows.Add([pscustomobject]@{Name=$nm;Pid=$p.Id;Path=$path;Verdict='Valid';Publisher=$sig.Publisher;Handles=$hc;Started=$st}); continue }
    if ($SystemNames -contains $nm.ToLower() -and -not $path.StartsWith($WinRoot,'OrdinalIgnoreCase')) { Add-Finding Detected 'Process' "$nm (masquerade)" $path 'System binary name outside C:\Windows' '' 'Rename or move it' -Score 35 -Confidence High }
    Invoke-BinaryEvaluation -Name $nm -Path $path -Pid $p.Id
    $procRows.Add([pscustomobject]@{Name=$nm;Pid=$p.Id;Path=$path;Verdict=$sig.Verdict;Publisher=$sig.Publisher;Handles=$hc;Started=$st})
}
try { $procRows | Export-Csv -LiteralPath (Join-Path $OutDir 'process_inventory.csv') -NoTypeInformation -Encoding UTF8 -EA Stop; Set-Phase 'Process inventory' 'Completed' } catch { Set-Phase 'Process inventory' 'Partial' }

# ============================================================================
# 5. Modules
# ============================================================================
Set-AuditProgress 20 'Self-audit' 'Reviewing loaded modules...'
Write-Host "`n=== Loaded modules ===" -ForegroundColor Magenta
$seen = @{}
foreach ($p in (Get-Process -EA SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $ownPid })) {
    $game = $p.ProcessName -eq 'RobloxPlayerBeta'
    try { $mods = $p.Modules } catch { continue }
    foreach ($m in $mods) {
        $mp2 = $m.FileName
        if (-not $mp2 -or $seen.ContainsKey($mp2)) { continue }
        $seen[$mp2] = 1; $Stats.Modules++
        $inWin = $mp2.StartsWith($WinRoot,'OrdinalIgnoreCase')
        if (-not $game -and $inWin) { continue }
        if ($game -and $inWin -and $mp2.EndsWith('.mui')) { continue }
        if ((Get-SigVerdict $mp2).Verdict -eq 'Valid') { continue }
        $s = 30; $sev = 'Detected'; $why = 'Unsigned module'
        if ($mp2 -match '\\(Temp|Downloads)\\') { $why = 'Unsigned module loaded from Temp/Downloads'; $s = 45 } elseif (Test-GamingAllowlist $mp2) { $sev='Review'; $s = 12 } else { $sev='Review'; $s=15 }
        Add-Finding $sev 'Module' $m.ModuleName "$mp2 (in $($p.ProcessName))" $why '' 'Identify the owner and close it' -Score $s -Confidence Medium
    }
}
Set-Phase 'Loaded modules' 'Completed'

# ============================================================================
# 6. Memory / injection / rules
# ============================================================================
Set-AuditProgress 27 'Self-audit' 'Analysing process memory and scanning regions...'
Write-Host "`n=== Memory / injection / rule scan ===" -ForegroundColor Magenta
$roblox = @(Get-Process -Name RobloxPlayerBeta,RobloxPlayer,Roblox -EA SilentlyContinue)
if ($roblox.Count -gt 0) {
    $tp = [Collections.Generic.HashSet[uint32]]::new(); foreach ($r in $roblox) { [void]$tp.Add([uint32]$r.Id) }
    $hs = @{}
    foreach ($h in [SA.N]::Handles($tp)) {
        $k = "$($h.OwnerPid)-$($h.Access)"; if ($hs.ContainsKey($k)) { continue }; $hs[$k]=1
        $sv = Get-SigVerdict $h.OwnerPath
        if ($sv.Verdict -eq 'Valid' -and $h.OwnerPath.StartsWith($WinRoot,'OrdinalIgnoreCase')) { continue }
        if ($h.OwnerName -eq 'RobloxCrashHandler') { continue }
        if (($HandleOwnerAllowlist -contains $h.OwnerName) -and $sv.Verdict -ne 'Valid') { Add-Finding Detected 'Memory' "$($h.OwnerName) (identity mismatch)" $h.OwnerPath "Trusted name, signature $($sv.Verdict) [$($h.AccessDesc)]" '' 'Renamed binary holding Roblox handles' -Score 55 -Confidence High }
        else { Add-Finding Detected 'Memory' "$($h.OwnerName) (PID $($h.OwnerPid))" $h.OwnerPath "Handle to Roblox: $($h.AccessDesc) [sig: $($sv.Verdict)]" '' 'Review owner and signature' -Score 30 -Confidence Medium }
        if ([SA.N]::DebugPriv([int]$h.OwnerPid)) { Add-Finding Detected 'Memory' "$($h.OwnerName) (PID $($h.OwnerPid))" $h.OwnerPath 'SeDebugPrivilege held with a Roblox handle' '' '' -Score 20 -Confidence High }
    }
    Set-Phase 'Handle analysis' 'Completed'
} else { Write-Host '  Roblox not running' -ForegroundColor DarkGray; Set-Phase 'Handle analysis' 'Skipped' }

foreach ($p in (Get-Process -EA SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $ownPid })) {
    foreach ($h in [SA.N]::Hollow($p.Id, $p.ProcessName)) { Add-Finding Detected 'Injection' $h.Name "PID $($h.Pid)" ("Private executable PE at 0x{0:X}" -f $h.Base) '' 'Manual-mapped image' -Score 30 -Confidence High }
}

function Test-RobloxThreads { foreach ($rp in @(Get-Process -Name RobloxPlayerBeta -EA SilentlyContinue)) { try { if ([SA.N]::Modules($rp.Id).Count -eq 0) { continue }; foreach ($t in @([SA.N]::Threads($rp.Id) | Where-Object { -not $_.Backed })) { Add-Finding Detected 'Thread' "Thread $($t.Tid)" "PID $($rp.Id)" ("Start 0x{0:X} outside every module" -f $t.Start) '' 'Unbacked thread start is a strong executor signal' -Score 45 -Confidence High } } catch {} } }
function Test-RobloxRegions { foreach ($rp in @(Get-Process -Name RobloxPlayerBeta -EA SilentlyContinue)) { try { $r = @([SA.N]::Regions($rp.Id, 20000) | Where-Object { $_.Rwx }); if ($r.Count) { Add-Finding Review 'Memory' "RWX regions PID $($rp.Id)" 'RobloxPlayerBeta' "$($r.Count) RWX region(s)" '' 'High private RWX counts are worth a look' -Score 8 -Confidence Low } } catch {} } }
function Test-RobloxHooks {
    $tg = @(@{M='ntdll.dll';F='NtReadVirtualMemory'},@{M='ntdll.dll';F='NtWriteVirtualMemory'},@{M='ntdll.dll';F='NtProtectVirtualMemory'},@{M='ntdll.dll';F='NtQuerySystemInformation'},@{M='kernel32.dll';F='VirtualProtect'},@{M='kernel32.dll';F='CreateRemoteThread'})
    foreach ($rp in @(Get-Process -Name RobloxPlayerBeta -EA SilentlyContinue)) {
        $h = [SA.N]::OpenProcess(0x410,$false,[uint32]$rp.Id); if ($h -eq [IntPtr]::Zero) { continue }
        try {
            foreach ($t in $tg) { try {
                $hm = [SA.N]::GetModuleHandleW($t.M); if ($hm -eq [IntPtr]::Zero) { continue }
                $ad = [SA.N]::GetProcAddress($hm,$t.F); if ($ad -eq [IntPtr]::Zero) { continue }
                $loc = New-Object byte[] 16; [Runtime.InteropServices.Marshal]::Copy($ad,$loc,0,16)
                $rem = [SA.N]::ReadMem($h,[uint64]$ad.ToInt64(),16); if (-not $rem) { continue }
                $d=$false; for ($i=0;$i -lt 16;$i++) { if ($loc[$i] -ne $rem[$i]) { $d=$true; break } }; if (-not $d) { continue }
                $b0 = $rem[0]
                if (($b0 -eq 0xE9) -or ($b0 -eq 0xE8) -or ($b0 -eq 0xFF -and ($rem[1] -eq 0x25 -or $rem[1] -eq 0x15)) -or ($b0 -eq 0x48 -and $rem[1] -eq 0xB8 -and $rem[10] -eq 0xFF -and $rem[11] -eq 0xE0)) {
                    Add-Finding Detected 'Hook' "$($t.M)!$($t.F)" "PID $($rp.Id)" ('Prologue differs: [' + (($rem | ForEach-Object { $_.ToString('X2') }) -join ' ') + ']') '' 'API hook in game process' -Score 35 -Confidence High
                }
            } catch {} }
        } finally { [SA.N]::CloseHandle($h) | Out-Null }
    }
}
function Test-RobloxIat {
    foreach ($rp in @(Get-Process -Name RobloxPlayerBeta -EA SilentlyContinue)) {
        try {
            $exe = $rp.MainModule.FileName; if (-not (Test-Path $exe)) { continue }
            $mods = [SA.N]::Modules($rp.Id); if ($mods.Count -eq 0) { continue }
            $rg = @{}; foreach ($m in $mods) { $rg[$m.Name.ToLower()] = $m }
            $by = [IO.File]::ReadAllBytes($exe); $pe = [BitConverter]::ToInt32($by,0x3C)
            if ($pe -le 0 -or $pe -ge ($by.Length-8)) { continue }
            $opt = $pe+24; $is64 = ([BitConverter]::ToUInt16($by,$opt) -eq 0x20B)
            $irva = [BitConverter]::ToInt32($by,$(if($is64){$opt+112}else{$opt+96})); if ($irva -eq 0) { continue }
            $ns = [BitConverter]::ToUInt16($by,$pe+6); $so2 = [BitConverter]::ToUInt16($by,$pe+20); $seco = $opt+$so2; $secs=@()
            for ($i=0;$i -lt $ns;$i++) { $o2=$seco+($i*40); if ($o2+40 -gt $by.Length) { break }; $secs += [pscustomobject]@{VA=[BitConverter]::ToInt32($by,$o2+12);VS=[BitConverter]::ToInt32($by,$o2+8);R=[BitConverter]::ToInt32($by,$o2+20)} }
            $r2o = { param([int]$rva) foreach ($s in $secs) { if ($rva -ge $s.VA -and $rva -lt ($s.VA+$s.VS)) { return ($s.R + ($rva-$s.VA)) } } return -1 }
            $base = [uint64]$rp.MainModule.BaseAddress.ToInt64(); $pt = if ($is64) { 8 } else { 4 }; $d = & $r2o $irva
            $h = [SA.N]::OpenProcess(0x410,$false,[uint32]$rp.Id); if ($h -eq [IntPtr]::Zero) { continue }
            try {
                while ($d -ge 0 -and ($d+20) -le $by.Length) {
                    $nr = [BitConverter]::ToInt32($by,$d+12); $ft = [BitConverter]::ToInt32($by,$d+16)
                    if ($nr -eq 0 -and $ft -eq 0) { break }
                    $no = & $r2o $nr; $dll = $null
                    if ($no -ge 0 -and $no -lt $by.Length) { $e2=$no; while ($e2 -lt [Math]::Min($by.Length,$no+260) -and $by[$e2] -ne 0) { $e2++ }; if ($e2 -gt $no) { $dll = [Text.Encoding]::ASCII.GetString($by,$no,$e2-$no) } }
                    if ($dll -and $rg.ContainsKey($dll.ToLower())) {
                        $ex = $rg[$dll.ToLower()]; $sl=0
                        while ($sl -lt 0x4000) {
                            $buf = [SA.N]::ReadMem($h,[uint64]($base+$ft+$sl),$pt); if (-not $buf) { break }
                            $v = if ($is64) { [uint64][BitConverter]::ToInt64($buf,0) } else { [uint64][BitConverter]::ToUInt32($buf,0) }
                            if ($v -eq 0) { break }
                            if (-not ($v -ge $ex.Base -and $v -lt ($ex.Base+$ex.Size))) { foreach ($kv in $rg.GetEnumerator()) { if ($v -ge $kv.Value.Base -and $v -lt ($kv.Value.Base+$kv.Value.Size)) { Add-Finding Detected 'IAT hook' "$dll -> $($kv.Key)" "PID $($rp.Id)" ("Import resolves into {0}" -f $kv.Key) '' 'Import redirection' -Score 35 -Confidence High; break } } }
                            $sl += $pt
                        }
                    }
                    $d += 20
                }
            } finally { [SA.N]::CloseHandle($h) | Out-Null }
        } catch {}
    }
}
function Test-PESieve { param([int]$P,[string]$T='')
    if ($NoPESieve) { return }
    $exe = Get-Tool -Name 'PESieve' -Url $Config.PESieveUrl -Exe 'pe-sieve64.exe'; if (-not $exe) { return }
    $j = Join-Path $env:TEMP ("ps_$P`_$(Get-Random).json")
    try {
        & $exe -pid $P -sc -o $j -silent 2>$null | Out-Null; Start-Sleep -Milliseconds 300
        if (-not (Test-Path $j)) { return }
        if ((Get-Content -LiteralPath $j -Raw) -match '"(injected|manual_map|iat_hooked|hdr_modified|suspicious)') {
            Copy-Item -LiteralPath $j -Destination (Join-Path $OutDir "pesieve_${P}_$Stamp.json") -Force -EA SilentlyContinue
            Add-Finding Detected 'PE-sieve' "PID $P" $T 'PE-sieve reported injected/manual-mapped/suspicious content' '' 'See PE-sieve JSON' -Score 60 -Confidence High
        }
    } catch {} finally { Remove-Item -LiteralPath $j -Force -EA SilentlyContinue }
}

$rNames = @($Rules | ForEach-Object { $_.N })
$rWeights = @($Rules | ForEach-Object { $_.W })
$rMins = @($Rules | ForEach-Object { $_.M })
$pats = [System.Collections.Generic.List[byte[]]]::new()
$patRule = [System.Collections.Generic.List[int]]::new()
for ($ri = 0; $ri -lt $Rules.Count; $ri++) {
    foreach ($pt in $Rules[$ri].P) {
        if ($pt -match '^[0-9A-Fa-f]+$' -and $pt.Length % 2 -eq 0 -and $pt.Length -ge 8) {
            $bytes = [byte[]]::new($pt.Length / 2)
            for ($bi = 0; $bi -lt $bytes.Length; $bi++) { $bytes[$bi] = [Convert]::ToByte($pt.Substring($bi*2,2),16) }
            $pats.Add($bytes); $patRule.Add($ri)
        } else { $pats.Add([Text.Encoding]::ASCII.GetBytes($pt)); $patRule.Add($ri) }
    }
}
foreach ($p in (Get-Process -EA SilentlyContinue | Where-Object { $_.Id -gt 4 -and $_.Id -ne $ownPid })) {
    $path = try { $p.Path } catch { '' }
    if ($path -and $path.StartsWith($WinRoot,'OrdinalIgnoreCase') -and $p.ProcessName -notmatch 'Roblox|explorer|svchost') { continue }
    try {
        foreach ($hit in [SA.Y]::Scan($p.Id, $rNames, $rWeights, $rMins, $pats.ToArray(), $patRule.ToArray(), $Config.MaxRegions, $Config.MaxRegionBytes)) {
            $Stats.RegionsScanned++
            $conf = if ($hit.Weight -ge 50) { 'High' } elseif ($hit.Weight -ge 30) { 'Medium' } else { 'Low' }
            $sev = if ($hit.Weight -ge 30) { 'Detected' } else { 'Review' }
            Add-Finding $sev 'Memory rule' "$($hit.Rule) in $($p.ProcessName)" ("PID $($p.Id) @ 0x{0:X}" -f $hit.Base) "Rule matched [$($hit.Patterns)]" '' 'Rule hit inside a private region' -Score $hit.Weight -Confidence $conf -Evidence @("Patterns: $($hit.Patterns)")
        }
    } catch { Write-AuditError -Record $_ -Stage "Rule scan PID $($p.Id)" }
}
Set-Phase 'Memory rule scan' 'Completed' "$($Stats.RegionsScanned) rule hit(s)"

if ($roblox.Count -gt 0) { Test-RobloxThreads; Test-RobloxRegions; Test-RobloxHooks; Test-RobloxIat; foreach ($r in $roblox) { Test-PESieve -P $r.Id -T 'RobloxPlayerBeta' }; Set-Phase 'Deep Roblox analysis' 'Completed' }
else { Set-Phase 'Deep Roblox analysis' 'Skipped' }

# ============================================================================
# 7. Windows / drivers / persistence / network
# ============================================================================
Set-AuditProgress 42 'Self-audit' 'Reviewing windows, drivers, persistence, listeners...'
Write-Host "`n=== Windows / drivers / persistence / network ===" -ForegroundColor Magenta
foreach ($w in [SA.W]::Scan()) { if ((Get-SigVerdict $w.Path).Verdict -eq 'Valid') { continue }; Add-Finding Detected 'Window' "$($w.Reason) `"$($w.Title)`"" $w.Path "Unsigned overlay, class $($w.Cls)" '' 'Sign or close it' -Score 25 -Confidence Medium }
Set-Phase 'Windows' 'Completed'

try {
    $raw = (Invoke-WebRequest -Uri $Config.KnownDriversUrl -UseBasicParsing -TimeoutSec 10 -EA Stop).Content
    $json = $raw | ConvertFrom-Json
    $entries = if ($json -is [System.Array]) { $json } elseif ($json.PSObject.Properties['Verified']) { $json.Verified } else { @() }
    foreach ($e in $entries) { if ($e.name) { $script:KnownDriversCache[$e.name.ToLower()]=$true }; if ($e.PSObject.Properties['KnownVulnerableSamples'] -and $e.KnownVulnerableSamples) { foreach ($s in $e.KnownVulnerableSamples) { if ($s.SHA256) { $script:KnownDriversHashCache[$s.SHA256.ToString().ToLower()]=$true } } } }
} catch { Write-Host '  [WARN] lolDrivers unavailable' -ForegroundColor Yellow }

foreach ($d in (Get-CimInstance Win32_SystemDriver -EA SilentlyContinue)) {
    $pn = $d.PathName; if (-not $pn) { continue }
    $Stats.Drivers++
    $clean = ($pn.Trim('"') -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\',$WinRoot)
    if ($clean -notmatch '^[A-Za-z]:\\') { $clean = Join-Path $WinRoot $clean }
    $fn = [IO.Path]::GetFileName($pn).ToLower()
    if ($VulnerableDriverNames -contains $fn) { Add-Finding Detected 'Driver' $d.Name $pn 'Known vulnerable driver name' '' 'Unload or note it' -Score 30 -Confidence High }
    if ($script:KnownDriversCache.ContainsKey($fn)) { Add-Finding Detected 'Driver' $d.Name $pn 'Matches the lolDrivers vulnerable list' '' '' -Score 35 -Confidence High }
    if ($d.State -eq 'Running' -and (Test-Path -LiteralPath $clean)) {
        $h = Get-CachedHash $clean
        if ($h -and $script:KnownDriversHashCache.ContainsKey($h.ToLower())) { Add-Finding Detected 'Driver' $d.Name $pn 'Hash matches a known BYOVD sample' '' '' -Score 50 -Confidence High }
        if ($clean -match '\\(Temp|Downloads)\\') { Add-Finding Detected 'Driver' $d.Name $clean 'Running driver from a user-writable path' '' '' -Score 30 -Confidence High }
        try { $age = ((Get-Date) - (Get-Item $clean).LastWriteTime).TotalHours; if ($age -lt 24) { Add-Finding Detected 'Driver' $d.Name $clean "Driver written $([int]$age)h ago" '' 'Freshly dropped drivers are high signal' -Score 20 -Confidence High } } catch {}
        if ((Get-SigVerdict $clean).Verdict -notin 'Valid','Missing') { Add-Finding Detected 'Driver' $d.Name $clean 'Running driver is unsigned/untrusted' '' 'Investigate the source' -Score 40 -Confidence High }
    }
}
Set-Phase 'Drivers' 'Completed'

foreach ($svc in @('SysMain','PcaSvc','DPS','EventLog')) { $s = Get-Service $svc -EA SilentlyContinue; if ($s -and $s.Status -ne 'Running') { Add-Finding Review 'Tamper' $svc $svc "Service $($s.Status)" '' 'Start it' -Score 10 -Confidence Medium } }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -EA SilentlyContinue).EnablePrefetcher -eq 0) { Add-Finding Review 'Tamper' 'Prefetch' 'EnablePrefetcher' 'Prefetch disabled' '' 'Set to 3' -Score 12 -Confidence High }

try { foreach ($pp in [IO.Directory]::GetFiles('\\.\pipe\')) { $n = Split-Path $pp -Leaf; if (-not $SeenPipes.Add($n)) { continue }; $Stats.Pipes++; $hit = Get-KeywordMatch $n; if ($hit) { Add-Finding Detected 'Named pipe' $n $pp "Pipe name matches '$hit'" '' '' -Score 25 -Confidence Medium } }; Set-Phase 'Named pipes' 'Completed' } catch { Set-Phase 'Named pipes' 'Failed' }

$expectedParents = @('explorer','RobloxPlayerLauncher','Bloxstrap','Fishstrap','chrome','msedge','firefox','opera','brave','cmd','powershell','pwsh','WindowsTerminal')
foreach ($r in @(Get-CimInstance Win32_Process -Filter "Name = 'RobloxPlayerBeta.exe'" -EA SilentlyContinue)) {
    $par = try { Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $r.ParentProcessId) -EA SilentlyContinue } catch { $null }
    if ($par -and $expectedParents -notcontains [IO.Path]::GetFileNameWithoutExtension($par.Name)) { Add-Finding Review 'Process tree' "Parent: $($par.Name)" ($par.ExecutablePath -as [string]) 'Roblox launched by an unexpected parent' '' '' -Score 12 -Confidence Medium }
}
Set-Phase 'Process tree' 'Completed'

foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
    if (-not (Test-Path $k)) { continue }
    $it = Get-Item $k
    foreach ($v in $it.GetValueNames()) {
        $cmd = [string]$it.GetValue($v)
        $t = if ($cmd -match '^"([^"]+)"') { $matches[1] } elseif ($cmd -match '^([A-Za-z]:\\[^\s]+\.exe)') { $matches[1] } else { '' }
        if (-not $t -or -not (Test-Path $t)) { continue }
        if ((Get-SigVerdict $t).Verdict -eq 'Valid') { continue }
        if ($t -match '\\AppData\\|\\Temp\\|\\Downloads\\') { Add-Finding Review 'Autorun' $v $t 'Unsigned autorun in a user-writable path' '' '' -Score 15 -Confidence Medium }
    }
}
foreach ($sf in @((Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup'))) { if (Test-Path $sf) { foreach ($f in (Get-ChildItem $sf -File -EA SilentlyContinue)) { Add-Finding Info 'Startup folder' $f.Name $f.FullName 'Startup entry' '' '' -Score 0 } } }
try { foreach ($t in (Get-ScheduledTask -EA SilentlyContinue)) { foreach ($a in $t.Actions) { if ($a.Execute -match '\\AppData\\|\\Temp\\|\\Downloads\\') { Add-Finding Review 'Scheduled task' $t.TaskName $a.Execute "Task runs from a user-writable path ($($t.State))" '' '' -Score 12 -Confidence Medium } } }; Set-Phase 'Persistence' 'Completed' } catch { Set-Phase 'Persistence' 'Partial' }

foreach ($c in (Get-NetTCPConnection -State Listen -EA SilentlyContinue)) {
    if ($c.LocalAddress -notin @('127.0.0.1','::1','0.0.0.0','::')) { continue }
    $Stats.Listeners++
    $pp = try { Get-Process -Id $c.OwningProcess -EA Stop } catch { $null }; if (-not $pp) { continue }
    $ppath = try { $pp.Path } catch { '' }
    if ($ppath -and ($ppath.StartsWith($WinRoot,'OrdinalIgnoreCase') -or $ppath -like '*\Program Files*')) { continue }
    $why = @()
    if ($c.LocalPort -in @(1337,3000,5000,6000,7777,8000,8080,8888,9000,9001,9999,27015)) { $why += "known port $($c.LocalPort)" }
    if ($pp.ProcessName -match '^(python|pythonw|node|cmd|powershell)$') { $why += 'script runtime' }
    if ($ppath -match '\\AppData\\|\\Temp\\|\\Downloads\\|\\Desktop\\') { $why += 'user-writable path' }
    if ($why.Count) { Add-Finding Detected 'Network' $pp.ProcessName "$($c.LocalAddress):$($c.LocalPort)" ("Listener: " + ($why -join ', ')) '' 'Close the radar/config server' -Score 22 -Confidence Medium }
}

if ($roblox.Count -gt 0) {
    $pids = @($roblox | ForEach-Object { $_.Id })
    try {
        foreach ($rem in @(Get-NetTCPConnection -State Established -EA Stop | Where-Object { $pids -contains $_.OwningProcess } | Where-Object { -not (Test-IsPrivateIp $_.RemoteAddress) } | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 40)) {
            $n = Get-CachedHostname $rem; if (-not $n) { continue }; $low = $n.ToLower().TrimEnd('.')
            foreach ($d in $NetworkIocDomains) { if ($low -eq $d -or $low.EndsWith(".$d")) { Add-Finding Detected 'Network IOC' $low $rem "Roblox endpoint resolved to '$d'" '' '' -Score 40 -Confidence High; break } }
        }
        Set-Phase 'Network IOC' 'Completed'
    } catch { Set-Phase 'Network IOC' 'Partial' }
} else { Set-Phase 'Network IOC' 'Skipped' }

# ============================================================================
# 8. PyInstaller / droppers
# ============================================================================
Set-AuditProgress 55 'Self-audit' 'Reviewing extraction artifacts...'
foreach ($root in @($env:TEMP,(Join-Path $env:LOCALAPPDATA 'Temp')) | Select-Object -Unique) {
    if (-not (Test-Path $root)) { continue }
    foreach ($dir in (Get-ChildItem $root -Directory -Filter '_MEI*' -EA SilentlyContinue)) {
        $names = @(Get-ChildItem $dir.FullName -Recurse -EA SilentlyContinue | Select-Object -ExpandProperty Name)
        $hits = @($PyInstallerCheatMarkers | Where-Object { $n = $_; $names | Where-Object { $_ -like "*$n*" } | Select-Object -First 1 })
        if ($hits.Count -lt 2) { continue }
        $owner = $null; foreach ($c in (Get-Process -EA SilentlyContinue)) { try { if ($c.Modules | Where-Object { $_.FileName -and $_.FileName.StartsWith($dir.FullName,'OrdinalIgnoreCase') } | Select-Object -First 1) { $owner = $c; break } } catch {} }
        Add-Finding Detected 'PyInstaller' ($hits -join ', ') $dir.FullName "PyInstaller cheat bundle, owner $(if($owner){"$($owner.ProcessName) PID $($owner.Id)"}else{'unresolved'})" '' 'Onefile cheats unpack like this' -Score 50 -Confidence High
    }
}
Set-Phase 'PyInstaller' 'Completed'
try { foreach ($node in (Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -EA SilentlyContinue)) { $par = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $node.ParentProcessId) -EA SilentlyContinue; if ($par -and $par.Name -match '^wscript\.exe$' -and ($node.CommandLine -as [string]) -match '[a-zA-Z0-9]{10,}\.js') { Add-Finding Detected 'Dropper' "node.exe PID $($node.ProcessId)" $node.CommandLine 'Spawned by wscript.exe with a random script name' '' '' -Score 45 -Confidence High } }; Set-Phase 'Droppers' 'Completed' } catch { Set-Phase 'Droppers' 'Failed' }

# ============================================================================
# 9. Forensics: USN, prefetch, BAM, UserAssist, MUICache, recycle, downloads
# ============================================================================
Set-AuditProgress 62 'Self-audit' 'Reviewing execution and file history...'
Write-Host "`n=== Execution / file history ===" -ForegroundColor Magenta
$timeline = [System.Collections.Generic.List[string]]::new()

foreach ($u in [SA.U]::Read([TimeSpan]::FromDays($Days), 4000)) {
    $hit = Get-KeywordMatch ([IO.Path]::GetFileName($u.Name)); if (-not $hit) { continue }
    $when = try { [DateTime]::FromFileTimeUtc($u.FileTime).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } catch { '' }
    $timeline.Add("$when | USN $($u.Action) | $($u.Name)")
    Add-Finding $(if ($u.Action -eq 'Deleted') { 'Detected' } else { 'Review' }) 'File history' $u.Name 'USN journal' "Cheat file $($u.Action) ($hit)" $when 'Trail survives deletion' -Score 20 -Confidence High -Timeline @($when)
}
Set-Phase 'USN journal' 'Completed'

$pfDir = Join-Path $WinRoot 'Prefetch'
$pfAll = [System.Collections.Generic.List[string]]::new()
if (Test-Path $pfDir) {
    $pfs = @(Get-ChildItem "$pfDir\*.pf" -EA SilentlyContinue); $Stats.Prefetch = $pfs.Count
    if ($pfs.Count -lt 15) { Add-Finding Review 'Tamper' 'Prefetch files' $pfDir "$($pfs.Count) files - folder looks emptied" '' '' -Score 15 -Confidence High }
    foreach ($f in ($pfs | Sort-Object LastWriteTime -Descending)) {
        $base = ($f.Name -split '-')[0]
        $ts = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
        $pfAll.Add("$ts | $base"); $timeline.Add("$ts | PREFETCH | $base")
        $hit = Get-KeywordMatch $base; if (-not $hit) { continue }
        $strong = Test-StrongKeyword $base
        Add-Finding $(if ($strong) { 'Detected' } else { 'Review' }) 'Execution history' $f.Name $pfDir "Prefetch shows execution ($hit)" $ts 'Delete only this .pf' -Score $(if ($strong) { 28 } else { 15 }) -Confidence High -Timeline @($ts)
    }
    try { $pfAll | Set-Content -LiteralPath (Join-Path $OutDir 'prefetch_recent.txt') -Encoding UTF8 -EA Stop } catch {}
    Set-Phase 'Prefetch' 'Completed'
} else { Set-Phase 'Prefetch' 'Failed' }

$bamRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
if (-not (Test-Path $bamRoot)) { $bamRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings' }
if (Test-Path $bamRoot) {
    $bl = [System.Collections.Generic.List[string]]::new()
    foreach ($sidKey in (Get-ChildItem $bamRoot -EA SilentlyContinue)) {
        $item = Get-Item $sidKey.PSPath
        foreach ($n in $item.Property) {
            $Stats.Bam++; $exe = ($n -split '\\')[-1]; $when = ''
            try { $raw = $item.GetValue($n); if ($raw -is [byte[]] -and $raw.Length -ge 16) { $when = [DateTime]::FromFileTime([BitConverter]::ToInt64($raw,8)).ToString('yyyy-MM-dd HH:mm') } } catch {}
            $bl.Add("$when | $n"); $timeline.Add("$when | BAM | $n")
            $hit = Get-KeywordMatch $exe; if (-not $hit) { continue }
            Add-Finding Review 'BAM (last run)' $exe $n "BAM records execution ($hit)" $when 'Survives deletion' -Score 22 -Confidence High -Timeline @($when)
        }
    }
    try { $bl | Set-Content -LiteralPath (Join-Path $OutDir 'bam_recent.txt') -Encoding UTF8 -EA Stop } catch {}
    Set-Phase 'BAM' 'Completed'
} else { Set-Phase 'BAM' 'Failed' }

try {
    $ua = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    if (Test-Path $ua) {
        $ul = [System.Collections.Generic.List[string]]::new()
        foreach ($g in (Get-ChildItem $ua -EA SilentlyContinue)) {
            $ck = Join-Path $g.PSPath 'Count'; if (-not (Test-Path $ck)) { continue }
            $key = Get-Item $ck
            foreach ($n in $key.Property) {
                $Stats.UserAssist++
                $dec = -join ($n.ToCharArray() | ForEach-Object { $c = [int][char]$_; if ($c -ge 97 -and $c -le 109) { [char]($c+13) } elseif ($c -ge 110 -and $c -le 122) { [char]($c-13) } elseif ($c -ge 65 -and $c -le 77) { [char]($c+13) } elseif ($c -ge 78 -and $c -le 90) { [char]($c-13) } else { $_ } })
                $when = ''
                try { $raw = $key.GetValue($n); if ($raw -is [byte[]] -and $raw.Length -ge 68) { $when = [DateTime]::FromFileTime([BitConverter]::ToInt64($raw,60)).ToString('yyyy-MM-dd HH:mm') } } catch {}
                $ul.Add("$when | $dec"); $timeline.Add("$when | USERASSIST | $dec")
                $hit = Get-KeywordMatch $dec; if (-not $hit) { continue }
                Add-Finding Review 'UserAssist' (Split-Path $dec -Leaf) $dec "UserAssist records execution ($hit)" $when 'Survives deletion' -Score 20 -Confidence High -Timeline @($when)
            }
        }
        try { $ul | Set-Content -LiteralPath (Join-Path $OutDir 'userassist_recent.txt') -Encoding UTF8 -EA Stop } catch {}
        Set-Phase 'UserAssist' 'Completed'
    } else { Set-Phase 'UserAssist' 'Failed' }
} catch { Set-Phase 'UserAssist' 'Failed' }

try {
    $mui = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'
    if (Test-Path $mui) { $k = Get-Item $mui; foreach ($n in $k.Property) { $Stats.MuiCache++; $hit = Get-KeywordMatch $n; if ($hit) { Add-Finding Review 'MUICache' (Split-Path $n -Leaf) $n "MUICache holds this executable ($hit)" '' 'Survives deletion' -Score 15 -Confidence Medium } }; Set-Phase 'MUICache' 'Completed' }
    else { Set-Phase 'MUICache' 'Failed' }
} catch { Set-Phase 'MUICache' 'Failed' }

foreach ($dr in (Get-PSDrive -PSProvider FileSystem -EA SilentlyContinue | Where-Object { $_.Root -match '^[A-Z]:\\$' })) {
    $bin = Join-Path $dr.Root '$Recycle.Bin'; if (-not (Test-Path $bin)) { continue }
    foreach ($sid in (Get-ChildItem $bin -Directory -Force -EA SilentlyContinue)) {
        foreach ($i in (Get-ChildItem $sid.FullName -Filter '$I*' -Force -EA SilentlyContinue)) {
            try {
                $b = [IO.File]::ReadAllBytes($i.FullName); if ($b.Length -lt 28) { continue }
                $v = [BitConverter]::ToInt64($b,0); $l = [BitConverter]::ToInt32($b,24)
                $o = if ($v -ge 2) { [Text.Encoding]::Unicode.GetString($b,28,[Math]::Min($l*2,$b.Length-28)) } else { [Text.Encoding]::Unicode.GetString($b,24,[Math]::Min(520,$b.Length-24)) }
                $o = $o.TrimEnd([char]0)
                $hit = Get-KeywordMatch ([IO.Path]::GetFileName($o)); if ($hit) { Add-Finding Review 'Recycle Bin' ([IO.Path]::GetFileName($o)) $o "Cheat file in Recycle Bin ($hit)" '' 'Empty the bin' -Score 12 -Confidence Medium }
            } catch {}
        }
    }
}
Set-Phase 'Recycle Bin' 'Completed'

foreach ($root in @((Join-Path $env:USERPROFILE 'Downloads'), ([Environment]::GetFolderPath('Desktop')), $env:TEMP)) {
    if (-not (Test-Path $root)) { continue }
    foreach ($f in (Get-ChildItem $root -File -Recurse -Depth 1 -EA SilentlyContinue | Where-Object { $_.Extension -in '.exe','.dll','.sys','.zip','.rar','.7z','.lua','.py','.msi','.ps1','.bat','.txt' })) {
        $Stats.Downloads++; $ts = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); $timeline.Add("$ts | FILE | $($f.FullName)")
        $z = try { Get-Content -LiteralPath "$($f.FullName):Zone.Identifier" -EA Stop } catch { $null }
        if ($z) { $hu = ($z | Where-Object { $_ -match '^HostUrl=' }) -replace '^HostUrl=',''; $hit = Get-KeywordMatch "$hu $($f.Name)"; if ($hit -and $hu -match 'https?://') { Add-Finding Review 'Download origin' $f.Name $f.FullName "Downloaded from a cheat host ($hit): $hu" $ts 'Review the source' -Score 20 -Confidence Medium -Timeline @($ts) } }
        $nh = Get-KeywordMatch $f.Name; if ($nh) { Add-Finding Review 'Download name' $f.Name $f.FullName "Filename matches '$nh'" $ts '' -Score 12 -Confidence Low }
    }
}
Set-Phase 'Downloads' 'Completed'

# ============================================================================
# 10. Browsers
# ============================================================================
Set-AuditProgress 70 'Self-audit' 'Hunting cheat keywords across browser databases...'
Write-Host "`n=== Browser history / downloads ===" -ForegroundColor Magenta
$bLines = [System.Collections.Generic.List[string]]::new(); $bPartial = $false
$profiles = @(
    @{N='Chrome';R=(Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data');T='c'},
    @{N='Edge';R=(Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data');T='c'},
    @{N='Brave';R=(Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data');T='c'},
    @{N='Vivaldi';R=(Join-Path $env:LOCALAPPDATA 'Vivaldi\User Data');T='c'},
    @{N='Opera';R=(Join-Path $env:APPDATA 'Opera Software\Opera Stable');T='c'},
    @{N='OperaGX';R=(Join-Path $env:APPDATA 'Opera Software\Opera GX Stable');T='c'},
    @{N='Firefox';R=(Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles');T='f'},
    @{N='LibreWolf';R=(Join-Path $env:APPDATA 'librewolf\Profiles');T='f'},
    @{N='Waterfox';R=(Join-Path $env:APPDATA 'Waterfox\Profiles');T='f'},
    @{N='Floorp';R=(Join-Path $env:APPDATA 'Floorp\Profiles');T='f'}
)
foreach ($pr in $profiles) {
    if (-not (Test-Path $pr.R)) { continue }
    $dbs = @()
    if ($pr.T -eq 'f') { $dbs = @(Get-ChildItem $pr.R -Recurse -Depth 2 -Filter 'places.sqlite' -EA SilentlyContinue) }
    else {
        $dirs = @(Get-ChildItem $pr.R -Directory -EA SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })
        if ($pr.N -in 'Opera','OperaGX') { $dirs = @(Get-Item $pr.R) }
        foreach ($d in $dirs) { $dbs += @(Get-ChildItem $d.FullName -Filter 'History' -EA SilentlyContinue) }
    }
    if ($dbs.Count -eq 0) { $bLines.Add("[$($pr.N)] no database"); continue }
    foreach ($db in $dbs) {
        $tmp = Join-Path $env:TEMP ("bh_$(Get-Random)_$($db.Name)")
        try {
            $src = [IO.File]::Open($db.FullName,'Open','Read','ReadWrite')
            try { $dst = [IO.File]::Create($tmp); try { $src.CopyTo($dst) } finally { $dst.Dispose() } } finally { $src.Dispose() }
            $txt = [Text.Encoding]::GetEncoding(28591).GetString([IO.File]::ReadAllBytes($tmp))
            foreach ($m in [regex]::Matches($txt,'https?://[^\x00-\x1F\x7F"''<> ]{6,400}')) { $u = $m.Value; $hit = Get-KeywordMatch $u; if ($hit) { $Stats.BrowserUrls++; $bLines.Add("[$($pr.N)] URL | $u | $hit") } }
            foreach ($m in [regex]::Matches($txt,'[A-Za-z]:\\\\?[^\x00-\x1F"<>|]{4,240}\.(exe|dll|zip|rar|7z|lua|msi|bat|ps1)')) { $p = $m.Value; $hit = Get-KeywordMatch $p; if ($hit) { $Stats.BrowserUrls++; $bLines.Add("[$($pr.N)] DOWNLOAD | $p | $hit") } }
        } catch { $bLines.Add("[$($pr.N)] $($db.Name) unreadable"); $bPartial = $true }
        finally { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue }
    }
}
$uniqB = @($bLines | Select-Object -Unique)
try { $uniqB | Set-Content -LiteralPath (Join-Path $OutDir 'browser_keyword_hits.txt') -Encoding UTF8 -EA Stop } catch {}
$bHits = @($uniqB | Where-Object { $_ -match '\| (URL|DOWNLOAD) \|' })
foreach ($g in ($bHits | Group-Object { ($_ -split '\|')[0].Trim() })) {
    Add-Finding Review 'Browser history' "$($g.Count) keyword hit(s)" 'browser_keyword_hits.txt' "Cheat URLs/downloads in $($g.Name)" '' 'Cross-check the timestamps' -Score ([Math]::Min(40,6*$g.Count)) -Confidence Medium -Evidence @($g.Group | Select-Object -First 8)
}
if (-not $bHits.Count) { Write-Host '  No cheat-related browser entries' -ForegroundColor Green }
Set-Phase 'Browser history' $(if ($bPartial) { 'Partial' } else { 'Completed' }) "$($bHits.Count) hit(s)"

# ============================================================================
# 11. Amcache + SRUM
# ============================================================================
Set-AuditProgress 76 'Self-audit' 'Parsing Amcache and SRUM...'
$hive = Join-Path $WinRoot 'AppCompat\Programs\Amcache.hve'
$amState = 'Failed'; $amHits = [System.Collections.Generic.List[string]]::new()
if (Test-Path $hive) {
    $cp = Join-Path $env:TEMP ("am_$(Get-Random).hve")
    try {
        $src = [IO.File]::Open($hive,'Open','Read','ReadWrite'); try { $dst=[IO.File]::Create($cp); try { $src.CopyTo($dst) } finally { $dst.Dispose() } } finally { $src.Dispose() }
        & reg.exe load 'HKLM\SATmp' $cp 2>$null | Out-Null
        if (Test-Path 'HKLM:\SATmp\Root\File') {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            foreach ($vol in (Get-ChildItem 'HKLM:\SATmp\Root\File' -EA SilentlyContinue)) {
                if ($sw.Elapsed.TotalSeconds -gt 25) { break }
                foreach ($e in (Get-ChildItem $vol.PSPath -EA SilentlyContinue)) {
                    if ($sw.Elapsed.TotalSeconds -gt 25) { break }
                    $Stats.Amcache++
                    $raw = try { (Get-Item $e.PSPath -EA Stop).GetValue('15') } catch { $null }; if (-not $raw) { continue }
                    $p = [Text.Encoding]::Unicode.GetString($raw).TrimEnd([char]0)
                    $hit = Get-KeywordMatch ([IO.Path]::GetFileName($p))
                    if ($hit) { $amHits.Add("$p | $hit"); $timeline.Add(" | AMCACHE | $p"); Add-Finding Review 'Amcache' ([IO.Path]::GetFileName($p)) $p "Amcache records this executable ($hit)" '' 'Survives deletion' -Score 22 -Confidence High }
                }
            }
            $amState = 'Completed'
        } else { $amState = 'Partial' }
    } catch { $amState = 'Failed' } finally { & reg.exe unload 'HKLM\SATmp' 2>$null | Out-Null; [gc]::Collect(); Start-Sleep -Milliseconds 150; Remove-Item -LiteralPath $cp -Force -EA SilentlyContinue }
    try { $amHits | Set-Content -LiteralPath (Join-Path $OutDir 'amcache_hits.txt') -Encoding UTF8 -EA Stop } catch {}
}
Set-Phase 'Amcache' $amState

function Get-SrumUsage {
    param([int]$Budget = 20)
    $out = @{}
    $dll = Join-Path $ToolRoot 'Esent\Microsoft.Isam.Esent.Interop.dll'
    if (-not (Test-Path $dll)) {
        try {
            New-Item -ItemType Directory -Path (Join-Path $ToolRoot 'Esent') -Force | Out-Null
            $nupkg = Join-Path $env:TEMP "esent_$(Get-Random).zip"
            Invoke-WebRequest -Uri 'https://www.nuget.org/api/v2/package/Microsoft.Isam.Esent.Interop/2.6.0' -OutFile $nupkg -UseBasicParsing -TimeoutSec 30 -EA Stop
            $ex = Join-Path $env:TEMP "esent_$(Get-Random)"
            [IO.Compression.ZipFile]::ExtractToDirectory($nupkg, $ex)
            $found = Get-ChildItem $ex -Recurse -Filter 'Microsoft.Isam.Esent.Interop.dll' -EA SilentlyContinue | Where-Object { $_.FullName -match 'net45' } | Select-Object -First 1
            if (-not $found) { $found = Get-ChildItem $ex -Recurse -Filter 'Microsoft.Isam.Esent.Interop.dll' -EA SilentlyContinue | Select-Object -First 1 }
            if (-not $found) { return $null }
            Copy-Item $found.FullName $dll -Force
            Remove-Item $ex,$nupkg -Recurse -Force -EA SilentlyContinue
        } catch { return $null }
    }
    try { Add-Type -Path $dll -EA Stop } catch { return $null }
    $sru = Join-Path $WinRoot 'System32\sru\SRUDB.dat'
    if (-not (Test-Path $sru)) { return $null }
    $work = Join-Path $env:TEMP "sru_$(Get-Random)"; New-Item -ItemType Directory $work -Force | Out-Null
    $copy = Join-Path $work 'SRUDB.dat'
    try {
        $src = [IO.File]::Open($sru,'Open','Read','ReadWrite'); try { $dst=[IO.File]::Create($copy); try { $src.CopyTo($dst) } finally { $dst.Dispose() } } finally { $src.Dispose() }
        $inst = [Microsoft.Isam.Esent.Interop.JET_INSTANCE]::new()
        $ses = [Microsoft.Isam.Esent.Interop.JET_SESID]::new()
        $dbid = [Microsoft.Isam.Esent.Interop.JET_DBID]::new()
        $nullSes = [Microsoft.Isam.Esent.Interop.JET_SESID]::Nil
        [Microsoft.Isam.Esent.Interop.Api]::JetCreateInstance([ref]$inst, 'SRU')
        [Microsoft.Isam.Esent.Interop.Api]::JetSetSystemParameter([ref]$inst, $nullSes, [Microsoft.Isam.Esent.Interop.JET_param]::TempPath, 0, $work)
        [Microsoft.Isam.Esent.Interop.Api]::JetSetSystemParameter([ref]$inst, $nullSes, [Microsoft.Isam.Esent.Interop.JET_param]::LogFileSize, 1, $null)
        [Microsoft.Isam.Esent.Interop.Api]::JetInit([ref]$inst)
        [Microsoft.Isam.Esent.Interop.Api]::JetBeginSession($inst, [ref]$ses, $null, $null)
        [Microsoft.Isam.Esent.Interop.Api]::JetAttachDatabase($ses, $copy, [Microsoft.Isam.Esent.Interop.AttachDatabaseGrbit]::ReadOnly)
        [Microsoft.Isam.Esent.Interop.Api]::JetOpenDatabase($ses, $copy, $null, [ref]$dbid, [Microsoft.Isam.Esent.Interop.OpenDatabaseGrbit]::ReadOnly)
        try {
            $idMap = @{}
            $tbl = [Microsoft.Isam.Esent.Interop.JET_TABLEID]::new()
            [Microsoft.Isam.Esent.Interop.Api]::JetOpenTable($ses, $dbid, 'SruDbIdMapTable', $null, 0, [Microsoft.Isam.Esent.Interop.OpenTableGrbit]::None, [ref]$tbl)
            [Microsoft.Isam.Esent.Interop.Api]::JetSetCurrentIndex($ses, $tbl, [string]$null)
            if ([Microsoft.Isam.Esent.Interop.Api]::TryMoveFirst($ses, $tbl)) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                do {
                    if ($sw.Elapsed.TotalSeconds -gt $Budget) { break }
                    $idx = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt32($ses, $tbl, [Microsoft.Isam.Esent.Interop.Api]::GetTableColumnid($ses, $tbl, 'IdIndex'))
                    $blob = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumn($ses, $tbl, [Microsoft.Isam.Esent.Interop.Api]::GetTableColumnid($ses, $tbl, 'IdBlob'))
                    if ($null -ne $idx -and $blob) { try { $idMap[$idx] = [Text.Encoding]::Unicode.GetString($blob).TrimEnd([char]0) } catch {} }
                } while ([Microsoft.Isam.Esent.Interop.Api]::TryMoveNext($ses, $tbl))
            }
            [Microsoft.Isam.Esent.Interop.Api]::JetCloseTable($ses, $tbl)

            $tbl2 = [Microsoft.Isam.Esent.Interop.JET_TABLEID]::new()
            [Microsoft.Isam.Esent.Interop.Api]::JetOpenTable($ses, $dbid, 'NetworkUsagetable', $null, 0, [Microsoft.Isam.Esent.Interop.OpenTableGrbit]::None, [ref]$tbl2)
            $cApp = [Microsoft.Isam.Esent.Interop.Api]::GetTableColumnid($ses, $tbl2, 'AppId')
            $cSent = [Microsoft.Isam.Esent.Interop.Api]::GetTableColumnid($ses, $tbl2, 'BytesSent')
            $cRecv = [Microsoft.Isam.Esent.Interop.Api]::GetTableColumnid($ses, $tbl2, 'BytesRecvd')
            if ([Microsoft.Isam.Esent.Interop.Api]::TryMoveFirst($ses, $tbl2)) {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                do {
                    if ($sw.Elapsed.TotalSeconds -gt $Budget) { break }
                    $aid = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt32($ses, $tbl2, $cApp)
                    if ($null -eq $aid -or -not $idMap.ContainsKey($aid)) { continue }
                    $s2 = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt64($ses, $tbl2, $cSent)
                    $r2 = [Microsoft.Isam.Esent.Interop.Api]::RetrieveColumnAsInt64($ses, $tbl2, $cRecv)
                    $key = $idMap[$aid]
                    if (-not $out.ContainsKey($key)) { $out[$key] = @{ S = 0; R = 0 } }
                    $out[$key].S += [long]$s2; $out[$key].R += [long]$r2
                } while ([Microsoft.Isam.Esent.Interop.Api]::TryMoveNext($ses, $tbl2))
            }
            [Microsoft.Isam.Esent.Interop.Api]::JetCloseTable($ses, $tbl2)
        } finally {
            [Microsoft.Isam.Esent.Interop.Api]::JetEndSession($ses, [Microsoft.Isam.Esent.Interop.EndSessionGrbit]::None)
            [Microsoft.Isam.Esent.Interop.Api]::JetTerm($inst)
        }
        return $out
    } catch { return $null }
    finally { Remove-Item $work -Recurse -Force -EA SilentlyContinue }
}

if (-not $NoReputation) {
    $srum = $null
    try { $srum = Get-SrumUsage -Budget 18 } catch { $srum = $null }
    if ($srum -and $srum.Count -gt 0) {
        $sLines = [System.Collections.Generic.List[string]]::new()
        foreach ($k in ($srum.Keys | Sort-Object { -($srum[$_].S + $srum[$_].R) } | Select-Object -First 300)) {
            $v = $srum[$k]; $mb = [math]::Round((($v.S + $v.R) / 1MB), 2)
            $sLines.Add("$mb MB | $k")
            $hit = Get-KeywordMatch $k
            if ($hit -and $mb -ge 0.05) { Add-Finding Review 'SRUM (30d network)' (Split-Path $k -Leaf) $k "SRUM shows $mb MB of network use ($hit)" '' 'SRUM survives deletion' -Score 25 -Confidence High }
        }
        try { $sLines | Set-Content -LiteralPath (Join-Path $OutDir 'srum_network.txt') -Encoding UTF8 -EA Stop } catch {}
        Set-Phase 'SRUM' 'Completed' "$($srum.Count) apps"
    } else { Set-Phase 'SRUM' 'Partial' 'Esent unavailable' }
} else { Set-Phase 'SRUM' 'Skipped' }

# ============================================================================
# 12. Misc
# ============================================================================
$hist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
if (Test-Path $hist) {
    $pats2 = @(@('Add-MpPreference.*-Exclusion','DefenderExclusionByCommand'),@('bcdedit.*(testsigning|nointegritychecks|debug)\s+on','BootSigningWeakened'),@('sc(\.exe)?\s+create.*type\s*=\s*kernel','KernelServiceCreated'),@('fsutil.*usn.*deletejournal','JournalDeleted'),@('wevtutil.*\bcl\b','EventLogCleared'),@('kdmapper','Kdmapper'))
    foreach ($l in (Get-Content $hist -Tail 2000)) { foreach ($p in $pats2) { if ($l -match $p[0]) { Add-Finding Review 'Command history' $p[1] $hist $l '' '' -Score 10 -Confidence Medium } } }
}
$hostsFile = Join-Path $WinRoot 'System32\drivers\etc\hosts'
if (Test-Path $hostsFile) { foreach ($l in (Get-Content $hostsFile)) { if ($l -match '^\s*[^#]' -and $l -match 'roblox|rbxcdn|byfron|anticheat\.life') { Add-Finding Review 'Network' 'hosts entry' $hostsFile $l '' '' -Score 15 -Confidence High } } }
foreach ($ln in @('Bloxstrap','Fishstrap','Voidstrap')) {
    $f = Join-Path $env:LOCALAPPDATA "$ln\Modifications\ClientSettings\ClientAppSettings.json"
    if (Test-Path $f) { $fl = @('DFIntS2PhysicsSenderRate','DFIntAssemblyExtentsExpansionStudHundredth','DFIntPhysicsSenderMaxBandwidthBps','DFIntDataSenderRate','DFIntMaxMissedWorldStepsRemembered','DFIntNetworkLatencyTolerance'); $t = Get-Content $f -Raw; $h = @($fl | Where-Object { $t -match [regex]::Escape($_) }); if ($h.Count) { Add-Finding Review 'FastFlags' "$ln flags" $f ("Abused flags: " + ($h -join ', ')) '' 'Expected if tuned' -Score 8 -Confidence Low } }
}
$timeline | Sort-Object -Descending | Set-Content -LiteralPath (Join-Path $OutDir 'unified_timeline.txt') -Encoding UTF8 -EA SilentlyContinue

if ($Shots -and -not $NoShots) {
    $i = 0; foreach ($s in [Windows.Forms.Screen]::AllScreens) { $i++; $b = $s.Bounds; try { [SA.Shot]::Save((Join-Path $OutDir "monitor$i.png"),$b.X,$b.Y,$b.Width,$b.Height) } catch {} }
    Set-Phase 'Screenshots' 'Completed'
} else { Set-Phase 'Screenshots' 'Skipped' }

# ============================================================================
# 13. Live watch
# ============================================================================
$LiveStart = Get-Date
$MonStats = @{ Proc=0; File=0; Drv=0; Svc=0; Pipe=0; List=0; Conn=0; Autorun=0; Deep=0 }
$MonLog = Join-Path $OutDir 'live_monitor.log'
function Write-Mon { param([string]$M,[ConsoleColor]$C='DarkGray'); $l = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$M; Add-Content -LiteralPath $MonLog -Value $l -Encoding UTF8 -EA SilentlyContinue; Write-Host $l -ForegroundColor $C }

$kPids=[Collections.Generic.HashSet[int]]::new(); $kDrv=[Collections.Generic.HashSet[string]]::new(); $kSvc=[Collections.Generic.HashSet[string]]::new()
$kList=[Collections.Generic.HashSet[string]]::new(); $kConn=[Collections.Generic.HashSet[string]]::new(); $kAuto=[Collections.Generic.HashSet[string]]::new(); $kFiles=[Collections.Generic.HashSet[string]]::new()
$deepDone=[Collections.Generic.HashSet[int]]::new()
$watchDirs = @((Join-Path $env:USERPROFILE 'Downloads'),([Environment]::GetFolderPath('Desktop')),$env:TEMP,(Join-Path $env:LOCALAPPDATA 'Temp'),(Join-Path $env:PUBLIC 'Downloads')) | Select-Object -Unique
$watchExt = @('.exe','.dll','.sys','.zip','.rar','.7z','.lua','.msi','.ps1','.bat','.vbs','.js','.scr')
$deadline = if ($LiveSeconds -gt 0) { (Get-Date).AddSeconds($LiveSeconds) } else { [datetime]::MaxValue }

function Live-Baseline {
    foreach ($p in (Get-Process -EA SilentlyContinue)) { [void]$kPids.Add($p.Id) }
    foreach ($d in (Get-CimInstance Win32_SystemDriver -EA SilentlyContinue)) { [void]$kDrv.Add($d.Name) }
    foreach ($s in (Get-Service -EA SilentlyContinue)) { [void]$kSvc.Add($s.Name) }
    foreach ($c in (Get-NetTCPConnection -State Listen -EA SilentlyContinue)) { [void]$kList.Add("$($c.LocalAddress):$($c.LocalPort)") }
    foreach ($c in (Get-NetTCPConnection -State Established -EA SilentlyContinue)) { [void]$kConn.Add("$($c.RemoteAddress):$($c.RemotePort)") }
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) { if (Test-Path $k) { $it = Get-Item $k; foreach ($v in $it.GetValueNames()) { [void]$kAuto.Add("$k|$v") } } }
    foreach ($d in $watchDirs) { if (Test-Path $d) { foreach ($f in (Get-ChildItem $d -File -EA SilentlyContinue)) { [void]$kFiles.Add($f.FullName) } } }
}
function Live-Proc {
    foreach ($p in (Get-Process -EA SilentlyContinue)) {
        if (-not $kPids.Add($p.Id)) { continue }
        if ($p.Id -le 4 -or $p.Id -eq $PID) { continue }
        $MonStats.Proc++
        $path = try { $p.Path } catch { '' }
        $ci = try { Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $p.Id) -EA SilentlyContinue } catch { $null }
        Write-Mon "New process: $($p.ProcessName) (PID $($p.Id)) parent=$(try{(Get-Process -Id $ci.ParentProcessId -EA SilentlyContinue).ProcessName}catch{'?'}) path=$path"
        if ($ci -and $ci.CommandLine) { Write-Mon "  cmd: $($ci.CommandLine)" }
        if ($path) { Invoke-BinaryEvaluation -Name $p.ProcessName -Path $path -Pid $p.Id -Source 'Live process' }
        if ($ci -and ($h2 = Get-KeywordMatch $ci.CommandLine)) { Add-Finding Review 'Live process' "$($p.ProcessName) PID $($p.Id)" $ci.CommandLine "Command line matches '$h2'" '' '' -Score 18 -Confidence Medium }
        if ($p.ProcessName -eq 'RobloxPlayerBeta' -and $deepDone.Add($p.Id)) {
            $MonStats.Deep++; Write-Mon 'Roblox started - deep memory pass.' Cyan; Start-Sleep -Seconds 8
            try { Test-RobloxThreads; Test-RobloxRegions; Test-RobloxHooks; Test-RobloxIat } catch {}
            Test-PESieve -P $p.Id -T 'RobloxPlayerBeta (live)'
        }
    }
}
function Live-File {
    foreach ($d in $watchDirs) { if (-not (Test-Path $d)) { continue }
        foreach ($f in (Get-ChildItem $d -File -EA SilentlyContinue)) {
            if (-not $kFiles.Add($f.FullName)) { continue }
            if ($watchExt -notcontains $f.Extension.ToLower()) { continue }
            $MonStats.File++; $hit = Get-KeywordMatch $f.Name
            Write-Mon "New file: $($f.FullName)$(if($hit){" [keyword: $hit]"})"
            if ($hit) { Add-Finding Detected 'Live file' $f.Name $f.FullName "Appeared during session, name matches '$hit'" $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm') '' -Score 30 -Confidence Medium }
            if ($f.Extension -in '.exe','.dll','.sys') { Invoke-BinaryEvaluation -Name $f.Name -Path $f.FullName -Source 'Live file' }
        }
    }
}
function Live-Drv {
    foreach ($d in (Get-CimInstance Win32_SystemDriver -EA SilentlyContinue | Where-Object { $_.State -eq 'Running' })) {
        if (-not $kDrv.Add($d.Name)) { continue }
        $MonStats.Drv++; Write-Mon "New driver: $($d.Name) [$($d.PathName)]" Yellow
        $fn = [IO.Path]::GetFileName([string]$d.PathName).ToLower()
        if ($VulnerableDriverNames -contains $fn) { Add-Finding Detected 'Live driver' $d.Name $d.PathName 'Known vulnerable driver started mid-session' '' '' -Score 45 -Confidence High }
        elseif ($d.PathName -match '\\(Temp|Downloads)\\') { Add-Finding Detected 'Live driver' $d.Name $d.PathName 'Driver started from a user-writable path' '' '' -Score 40 -Confidence High }
    }
}
function Live-Svc {
    foreach ($s in (Get-Service -EA SilentlyContinue)) {
        if (-not $kSvc.Add($s.Name)) { continue }
        $MonStats.Svc++; $sv = try { Get-CimInstance Win32_Service -Filter ("Name = '{0}'" -f $s.Name) -EA SilentlyContinue } catch { $null }
        $p = if ($sv) { $sv.PathName } else { '' }
        Write-Mon "New service: $($s.Name) [$p]"
        if ($p -match '\\(Temp|Downloads|AppData)\\') { Add-Finding Detected 'Live service' $s.Name $p 'Service registered from a user-writable path' '' '' -Score 30 -Confidence High }
    }
}
function Live-Pipe { try { foreach ($pp in [IO.Directory]::GetFiles('\\.\pipe\')) { $n = Split-Path $pp -Leaf; if (-not $SeenPipes.Add($n)) { continue }; $MonStats.Pipe++; $hit = Get-KeywordMatch $n; if ($hit) { Add-Finding Detected 'Live pipe' $n $pp "New pipe matches '$hit'" '' '' -Score 25 -Confidence Medium; Write-Mon "Suspicious pipe: $pp" Red } } } catch {} }
function Live-Net {
    try { foreach ($c in (Get-NetTCPConnection -State Listen -EA SilentlyContinue)) { $k = "$($c.LocalAddress):$($c.LocalPort)"; if (-not $kList.Add($k)) { continue }; $MonStats.List++; $pp = try { Get-Process -Id $c.OwningProcess -EA Stop } catch { $null }; if (-not $pp) { continue }; $pa = try { $pp.Path } catch { '' }; if ($pa -and ($pa.StartsWith($WinRoot,'OrdinalIgnoreCase') -or $pa -like '*\Program Files*')) { continue }; Add-Finding Detected 'Live listener' $pp.ProcessName $k 'New local listener on a non-system process' '' '' -Score 18 -Confidence Medium } } catch {}
    try { foreach ($c in (Get-NetTCPConnection -State Established -EA SilentlyContinue)) { if (Test-IsPrivateIp $c.RemoteAddress) { continue }; $k = "$($c.RemoteAddress):$($c.RemotePort)"; if (-not $kConn.Add($k)) { continue }; $MonStats.Conn++; $n = Get-CachedHostname $c.RemoteAddress; if (-not $n) { continue }; $low = $n.ToLower().TrimEnd('.'); foreach ($d in $NetworkIocDomains) { if ($low -eq $d -or $low.EndsWith(".$d")) { Add-Finding Detected 'Live network IOC' $low $c.RemoteAddress "New connection to '$d'" '' '' -Score 35 -Confidence High; Write-Mon "IOC connection: $low" Red; break } } } } catch {}
}
function Live-Auto {
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        if (-not (Test-Path $k)) { continue }
        $it = Get-Item $k
        foreach ($v in $it.GetValueNames()) { if (-not $kAuto.Add("$k|$v")) { continue }; $MonStats.Autorun++; $cmd = [string]$it.GetValue($v); Write-Mon "New autorun: $v = $cmd" Yellow; $hit = Get-KeywordMatch "$v $cmd"; if ($hit) { Add-Finding Detected 'Live autorun' $v $cmd "Autorun added mid-session ('$hit')" '' '' -Score 35 -Confidence High } }
    }
}
function Live-Mod {
    foreach ($rp in @(Get-Process -Name RobloxPlayerBeta -EA SilentlyContinue)) { try { foreach ($m in $rp.Modules) { if (-not (Test-SeenOnce "lm|$($m.FileName)")) { continue }; $s = Get-SigVerdict $m.FileName; $tr = $false; if ($s.Verdict -eq 'Valid') { foreach ($pu in $TrustedModulePublishers) { if ($s.Publisher -like "*$pu*") { $tr = $true; break } } }; Write-Mon "Roblox module: $($m.ModuleName) [$($m.FileName)] sig=$($s.Verdict)"; if (-not $tr) { Add-Finding Detected 'Live module' $m.ModuleName $m.FileName "Newly loaded into Roblox, signature $($s.Verdict)" '' 'Verify origin' -Score $(if ($m.FileName -match '\\(Temp|Downloads)\\') { 45 } else { 25 }) -Confidence Medium } } } catch {} }
}

if (-not $NoLive) {
    Set-AuditProgress 84 'Self-audit' 'Live watch starting...'
    Write-Host "`n=== Live monitoring ===" -ForegroundColor Magenta
    Write-Host 'Watching process starts, drivers, services, new files, pipes, listeners and autoruns. Roblox is not required.' -ForegroundColor Gray
    if ($LiveSeconds -gt 0) { Write-Host "Timed: ${LiveSeconds}s." -ForegroundColor Yellow } else { Write-Host 'Press ENTER to stop.' -ForegroundColor Yellow }
    Set-Content -LiteralPath $MonLog -Value "Live watch $($LiveStart.ToString('o'))" -Encoding UTF8 -EA SilentlyContinue
    Live-Baseline
    $t1=[datetime]::MinValue; $t2=$t1; $t3=$t1; $t4=$t1; $t5=$t1; $t6=$t1; $lastStat=$t1
    while ($true) {
        if ([Console]::KeyAvailable) { if ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Enter) { break } }
        if ((Get-Date) -ge $deadline) { break }
        try { Live-Proc } catch { Write-AuditError -Record $_ -Stage 'Live proc' }
        try { Live-File } catch { Write-AuditError -Record $_ -Stage 'Live file' }
        if (((Get-Date)-$t1).TotalSeconds -ge 10) { try { Live-Drv } catch {}; $t1=Get-Date }
        if (((Get-Date)-$t2).TotalSeconds -ge 10) { try { Live-Svc } catch {}; $t2=Get-Date }
        if (((Get-Date)-$t3).TotalSeconds -ge 5)  { try { Live-Pipe } catch {}; $t3=Get-Date }
        if (((Get-Date)-$t4).TotalSeconds -ge 10) { try { Live-Net } catch {}; $t4=Get-Date }
        if (((Get-Date)-$t5).TotalSeconds -ge 15) { try { Live-Auto } catch {}; $t5=Get-Date }
        if (((Get-Date)-$t6).TotalSeconds -ge 5)  { try { Live-Mod } catch {}; $t6=Get-Date }
        try { Send-Partial 'watch' } catch {}
        if (((Get-Date)-$lastStat).TotalSeconds -ge 10) { $rp = @(Get-Process -Name RobloxPlayerBeta -EA SilentlyContinue); Write-Host ("[WATCH] {0}p {1}f {2}d {3}n | Roblox: {4}" -f $MonStats.Proc,$MonStats.File,$MonStats.Drv,($MonStats.List+$MonStats.Conn),$(if($rp.Count){'running'}else{'idle'})) -ForegroundColor DarkCyan; $lastStat=Get-Date }
        Start-Sleep -Seconds $Config.LivePollSeconds
    }
    Write-Mon 'Live watch stopped.' Cyan
    Set-Phase 'Live monitoring' 'Completed' ("{0}s, {1} proc, {2} file" -f [int]((Get-Date)-$LiveStart).TotalSeconds, $MonStats.Proc, $MonStats.File)
} else { Set-Phase 'Live monitoring' 'Skipped' }
$Meta['live'] = @{ durationSeconds = [int]((Get-Date)-$LiveStart).TotalSeconds; stats = $MonStats }

# ============================================================================
# 14. Correlation
# ============================================================================
Set-AuditProgress 90 'Self-audit' 'Correlating...'
foreach ($g in @($Findings | Where-Object { $_.Severity -ne 'Info' } | Group-Object Name | Where-Object { $_.Count -gt 1 })) {
    $bonus = [Math]::Min(45, ($g.Count - 1) * 12)
    Add-Finding Detected 'Correlation' $g.Name $g.Group[0].Path "$($g.Count) independent indicators on one subject" '' 'Multiple weak signals beat one strong signal' -Score $bonus -Confidence High -Evidence @($g.Group | ForEach-Object { "$($_.Category): $($_.Reason)" })
    $Stats.Correlated++
}

# ============================================================================
# 15. Report
# ============================================================================
Set-AuditProgress 93 'Self-audit' 'Building report...'
$det = @($Findings | Where-Object Severity -eq 'Detected'); $rev = @($Findings | Where-Object Severity -eq 'Review')
$crit = @($Findings | Where-Object Band -eq 'CRITICAL'); $newHits = @($Findings | Where-Object { $_.New -and $_.Severity -ne 'Info' })
$verdict = if ($crit.Count -gt 0 -or $script:EffScore -ge 110) { 'FAIL' } elseif ($script:EffScore -ge 40) { 'PASS WITH NOTES' } else { 'CLEAN' }
$vColor = switch ($verdict) { 'FAIL' { 'Red' } 'PASS WITH NOTES' { 'Yellow' } default { 'Green' } }
$duration = [int]((Get-Date) - $ScanStart).TotalSeconds
$enc = { param($s) [Security.SecurityElement]::Escape([string]$s) }
$rows = foreach ($f in ($Findings | Sort-Object @{E={-$_.Score}},Category,Name)) {
    $ev = if ($f.Evidence.Count) { '<br>' + (($f.Evidence | ForEach-Object { '&bull; ' + (& $enc $_) }) -join '<br>') } else { '' }
    $tl = if ($f.Timeline.Count) { '<br><i>' + (($f.Timeline | ForEach-Object { & $enc $_ }) -join ', ') + '</i>' } else { '' }
    "<tr class='$($f.Band.ToLower())'><td>$($f.Band)<br><span class='sc'>$($f.Score)</span></td><td>$(if($f.New){'<b class=n>NEW</b>'})</td><td>$(& $enc $f.Confidence)</td><td>$(& $enc $f.Category)</td><td>$(& $enc $f.Name)</td><td class='p'>$(& $enc $f.Path)</td><td>$(& $enc $f.Reason)$ev$tl</td><td>$(& $enc $f.Fix)</td></tr>"
}
$healthRows = foreach ($k in $ScanHealth.Keys) { $st = $ScanHealth[$k]; $cls = switch ($st.State) { 'Completed'{'ok'} 'Partial'{'part'} 'Failed'{'fail'} default{'skip'} }; "<tr><td>$(& $enc $k)</td><td class='$cls'>$($st.State)</td><td>$(& $enc $st.Note)</td></tr>" }
$statRows = ($Stats.Keys | ForEach-Object { "<li>$($_): $($Stats[$_])</li>" }) -join ''
$bBlock = if ($uniqB.Count) { ($uniqB | Select-Object -First 250 | ForEach-Object { '&bull; ' + (& $enc $_) }) -join '<br>' } else { 'No keyword hits.' }

$html = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Self-audit $Stamp</title><style>
body{background:#0d0d0f;color:#e8e8ea;font:14px/1.6 system-ui,sans-serif;margin:0;padding:32px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px;color:#a1a1aa;text-transform:uppercase;letter-spacing:.08em}
.v{font-size:30px;font-weight:700;margin:16px 0}.FAIL{color:#ff5c5c}.CLEAN{color:#4ade80}.PASS{color:#fbbf24}
table{border-collapse:collapse;width:100%;margin-top:12px;font-size:12.5px}th,td{border:1px solid #26262c;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#17171b}tr.critical td:first-child,tr.high td:first-child{color:#ff5c5c;font-weight:700}
tr.medium td:first-child{color:#fbbf24;font-weight:700}tr.low td:first-child,tr.info td:first-child{color:#a1a1aa}
td.p{max-width:300px;word-break:break-all;font-family:ui-monospace,monospace;font-size:11.5px;color:#a1a1aa}
.sc{font-size:11px;opacity:.7}.meta{color:#a1a1aa;font-size:12px}.n{color:#38bdf8}
.ok{color:#4ade80}.part{color:#fbbf24}.fail{color:#ff5c5c}.skip{color:#71717a}
ul,div.list{margin:6px 0 0 18px;padding:0;font-size:12.5px;color:#a1a1aa}
</style></head><body>
<h1>Self-audit report</h1>
<div class="meta">$Stamp &middot; $env:COMPUTERNAME &middot; $env:USERNAME &middot; window ${Days}d &middot; duration ${duration}s &middot; baseline: $(if($script:HasBaseline){'yes'}else{'no'}) &middot; not the official scanner</div>
<div class="v $(if($verdict -eq 'FAIL'){'FAIL'}elseif($verdict -eq 'PASS WITH NOTES'){'PASS'}else{'CLEAN'})">$verdict</div>
<div class="meta">raw score $($script:TotalScore) &middot; effective score $($script:EffScore) &middot; $($crit.Count) critical &middot; $($newHits.Count) new &middot; $($det.Count) detected &middot; $($rev.Count) review</div>
<h2>Scan health</h2><table><thead><tr><th>Phase</th><th>State</th><th>Note</th></tr></thead><tbody>$($healthRows -join "`n")</tbody></table>
<h2>Scan statistics</h2><ul>$statRows</ul>
<h2>Browser keyword hits</h2><div class="list">$bBlock</div>
<h2>Findings</h2><table><thead><tr><th>Band</th><th>New</th><th>Conf</th><th>Category</th><th>Name</th><th>Path</th><th>Reason / evidence / timeline</th><th>Fix</th></tr></thead><tbody>$($rows -join "`n")</tbody></table>
</body></html>
"@
$html | Set-Content (Join-Path $OutDir 'report.html') -Encoding UTF8
$hOut = [ordered]@{}; foreach ($k in $ScanHealth.Keys) { $hOut[$k] = $ScanHealth[$k].State }
@{ stamp=$Stamp; verdict=$verdict; totalScore=$script:TotalScore; effectiveScore=$script:EffScore; critical=$crit.Count; detected=$det.Count; review=$rev.Count; findings=$Findings; stats=$Stats; health=$hOut; meta=$Meta } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir 'findings.json') -Encoding UTF8

if ($SaveBaseline) {
    try {
        $bp = Join-Path $DataRoot "baseline-$env:COMPUTERNAME.json"
        @{ stamp=$Stamp; findings=@($Findings | Where-Object { $_.Severity -ne 'Info' } | Select-Object Category,Name) } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $bp -Encoding UTF8
        Write-Host "[INFO] Baseline saved: $bp" -ForegroundColor Cyan
    } catch {}
}
foreach ($e in @($Error)) { Write-AuditError -Record $e -Stage 'Collected error' }

Write-Host "`n================================================================" -ForegroundColor DarkMagenta
Write-Host " VERDICT: $verdict (raw $($script:TotalScore) / effective $($script:EffScore), $($det.Count) detected, $($newHits.Count) new)" -ForegroundColor $vColor
Write-Host "================================================================" -ForegroundColor DarkMagenta
Write-Progress -Activity 'Self-audit' -Completed
try { Stop-Transcript | Out-Null } catch {}

# ============================================================================
# 16. Final archive + upload
# ============================================================================
$sum = @(
    "**SelfAudit $verdict** - effective $($script:EffScore) (raw $($script:TotalScore))"
    "Host: ``$env:COMPUTERNAME`` | User: ``$env:USERNAME`` | Window: ${Days}d | Duration: ${duration}s"
    "Critical: $($crit.Count) | New: $($newHits.Count) | Detected: $($det.Count) | Review: $($rev.Count)"
    if ($crit.Count) { '**Top:** ' + (($crit | Select-Object -First 6 | ForEach-Object { "$($_.Category)/$($_.Name)" }) -join '; ') }
) -join "`n"

try {
    New-Zip -Dest $ZipPath
    if ((Get-Item $ZipPath).Length -gt $Config.UploadLimitBytes) { New-Zip -Dest $ZipPath -TextOnly }
    Write-Host "  [INFO] Archive: $ZipPath" -ForegroundColor Cyan
    if (-not (Send-Webhook -Path $ZipPath -Summary $sum)) { Write-Host "  [INFO] Zip kept at: $ZipPath" -ForegroundColor Gray }
} catch { Write-AuditError -Record $_ -Stage 'Packaging' }

if (-not $NoPause) { Write-Host "`nDone. Press Enter to exit." -ForegroundColor DarkGray; [void][Console]::ReadLine() }
exit 0
