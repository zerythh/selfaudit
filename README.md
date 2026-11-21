A PowerShell self-audit ("PC check") for Windows. Static and live cheat, executor, rootkit and forensics scanner, with Roblox-specific detection.

Reports are built in a unique `%TEMP%` directory, zipped, and uploaded to a Discord webhook. Nothing is written to the Desktop.

It is an independent check. A "CLEAN" verdict is not proof of a clean machine, and a FAIL verdict is not proof of cheating. Treat it as evidence to review, not a ruling.

---

## Requirements:

- Windows 10 or 11
- Windows PowerShell 5.1 (built in)
- Administrator. The script self-elevates with a UAC prompt if launched unelevated.
- Outbound HTTPS
- A Discord webhook you control. This repo ships no default, so uploads are skipped until you supply one.

Optional third-party tools are fetched on demand into `%LOCALAPPDATA%\SelfAudit\Tools` and only when the relevant phase runs.

---

## Quick start:

Fork the repo and add a webhook first ([Webhook setup](#webhook-setup)). Then run this in `cmd` — it downloads the script to a temp directory and relaunches it elevated.

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop';$u='https://raw.githubusercontent.com/YOURNAME/YOURFORK/refs/heads/main/SelfAudit.ps1';$d=Join-Path $env:TEMP ('SelfAudit-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $d -Force|Out-Null;$p=Join-Path $d 'SelfAudit.ps1';Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile $p;if(-not(Test-Path $p)){throw 'Download failed'};Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + $p + '"'),'-LiveSeconds','45','-Shots','-HideDetails')"
```

That runs a 7-day lookback, a 45-second live watch, captures screenshots, and hides technical console output.

---

## Webhook setup

A Discord webhook URL is the only delivery target. There is no fallback in this repo, so pick one of the two options below.

### Option A — fork, and use your own `WebhookUrl.txt`

Most convenient for repeat use: the webhook lives in your fork and the command stays clean.

1. Sign in to GitHub and open this repo.
2. **Fork** → **Create fork**. Public is fine and simplest — `raw.githubusercontent.com` serves public repos without auth. The tradeoff is that your webhook becomes publicly readable, exactly like this repo's *used* to be.
3. In **your fork**, **Add file** → **Create new file**. Filename `WebhookUrl.txt`. Content: your webhook URL on one line, bare, no `?wait=true`. Commit to `main`.
4. Still in your fork, open `SelfAudit.ps1` and edit this line near the top:

```powershell
$RepoBase = 'https://raw.githubusercontent.com/zerythh/selfaudit/refs/heads/main'
```

   to point at your fork:

```powershell
$RepoBase = 'https://raw.githubusercontent.com/YOURNAME/YOURFORK/refs/heads/main'
```

   Commit. This line only feeds the webhook lookup, so nothing else changes behavior.
   
5. Use your fork's raw script URL in the command — `$u='https://raw.githubusercontent.com/YOURNAME/YOURFORK/refs/heads/main/SelfAudit.ps1'`.
6. Run once and confirm the zip lands in your channel.

When you sync your fork with upstream later, re-check step 4. A sync can overwrite that line.

### Option B — fork only to host the file

If you'd rather not maintain a modified script, fork and add `WebhookUrl.txt` as in steps 1–3, then keep using the upstream script and pass your fork's raw URL:

```
...,'-HideDetails','-WebhookFile','https://raw.githubusercontent.com/YOURNAME/YOURFORK/refs/heads/main/WebhookUrl.txt')"
```

`-WebhookFile` takes a URL or a local path. The webhook stays out of the command line, and updating upstream is a plain sync with no conflicts.

If you download the repo as a folder and run the `.ps1` in place, a `WebhookUrl.txt` sitting next to it is picked up automatically with no flag at all.

Or skip hosting entirely and pass it directly with `-Webhook`. Highest priority, but the URL then sits in the paste and in the process command line.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Days` | int | `7` | Lookback window in days for the USN journal and file history. |
| `-Shots` | switch | off | Capture one PNG per monitor. |
| `-NoShots` | switch | off | Force screenshots off even if `-Shots` is set. |
| `-NoLive` | switch | off | Skip live monitoring entirely. |
| `-LiveSeconds` | int | `0` | Live watch duration. `0` waits for ENTER. |
| `-NoPESieve` | switch | off | Skip the PE-sieve deep scan. |
| `-NoReputation` | switch | off | Skip hash reputation lookups and SRUM parsing. |
| `-NoUpload` | switch | off | Skip all uploads, including partials. |
| `-MaxUploadMB` | int | `8` | Soft cap before the archive is rebuilt as text-only. |
| `-SelfExclude` | switch | off | Add a Defender exclusion for the script directory. |
| `-HideDetails` | switch | off | Suppress console findings and progress. |
| `-NoPause` | switch | off | Skip the final "press ENTER" prompt. |
| `-Webhook` | string | — | Webhook URL. Highest priority. |
| `-WebhookFile` | string | — | URL or local path to a file containing the webhook. |
| `-Baseline` | string | — | Prior `findings.json` to diff against. Repeats count at 35%. |
| `-SaveBaseline` | switch | off | Write a baseline to `%LOCALAPPDATA%\SelfAudit\baseline-<host>.json`. |
| `-VTApiKey` | string | — | VirusTotal key. Falls back to MalwareBazaar without one. |

---

## What it checks

Security posture and boot integrity, rootkit cross-view, process and module signatures, Roblox handle and memory injection analysis, API hooks and IAT, drivers and persistence, listeners and network IOCs, execution forensics (USN, Prefetch, BAM, UserAssist, Amcache, SRUM, browser history), and a live watch during the run. Full detail is in the script.

---

## Reading the report

Findings are scored. Bands: `>=60` CRITICAL, `>=30` HIGH, `>=12` MEDIUM, `>=4` LOW, otherwise INFO.

Verdict:

| Verdict | Condition |
|---|---|
| FAIL | Any CRITICAL finding, or effective score `>= 110` |
| PASS WITH NOTES | Effective score `>= 40` |
| CLEAN | Anything lower |

With `-Baseline`, findings already present in the baseline score at 35% and are marked as not new, so a re-run surfaces changes rather than the same list.

`report.html` is the readable artifact. `findings.json` is the machine-readable equivalent, for diffing.

---

## Files produced

In `%TEMP%\SelfAudit-<guid>\SelfAudit-<stamp>\`:

`report.html`, `findings.json`, `audit.log`, `identity.txt`, `process_inventory.csv`, `prefetch_recent.txt`, `bam_recent.txt`, `userassist_recent.txt`, `browser_keyword_hits.txt`, `amcache_hits.txt`, `srum_network.txt`, `unified_timeline.txt`, `live_monitor.log`, `monitorN.png`, `SelfAudit-errors-<stamp>.log`.

Partial archives upload roughly every 45 seconds during a run, so a killed session still leaves evidence. On a successful final upload the whole temp tree is deleted. On failure the archive and folder are kept and the path is printed.

---

## External endpoints

`raw.githubusercontent.com`, `api.ipify.org`, `cloudflare.com`, `www.loldrivers.io`, `github.com` (pe-sieve release), `api.nuget.org`, `mb-api.abuse.ch` or `virustotal.com`, plus Discord for upload. DNS resolves Roblox connection endpoints for the IOC phase.

---

## Limitations

- Signature verdicts rely on the local certificate store and `Get-AuthenticodeSignature`. Revocation is not checked.
- `C:\Windows` and `Program Files` paths are largely trusted by prefix, so a binary dropped there is under-scrutinized.
- Keyword lists produce name-match false positives. A single keyword hit is a LOW-severity review item, not a detection.
- Unreadable processes and locked browser databases degrade specific phases to Partial. Scan health is recorded in the report; a Partial or Failed phase means that area is inconclusive, not clean.
- Roblox-specific phases skip entirely when Roblox is not running.
- Cheats that unload before the scan, or that never touch disk, are not detectable.
- The USN journal, Prefetch and SRUM are rolling. Short windows miss old activity, and cleared journals are visible only as a phase failure.
- There is no default webhook. Without one, the scan still runs and still leaves the archive, but delivers nothing.

---

## FAQ

**Does it need Roblox open?**
No, but the Roblox phases need it to do anything. Launch Roblox during the live watch for the deep pass to fire.

**Can I run it more than once?**
Yes. Use `-SaveBaseline` once, then `-Baseline <path>` on later runs to see only what changed.

**Why is the report zipped and uploaded rather than saved locally?**
So a run that gets interrupted still leaves evidence somewhere durable.

**The upload failed.**
The archive is kept and the path printed. Check in order: no webhook configured at all, a revoked or wrong webhook, or an archive over the size limit — lower `-MaxUploadMB` so the text-only fallback kicks in.
