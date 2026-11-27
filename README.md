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

## How to use

A Discord webhook URL is the only delivery target. There is no fallback in this repo, there are many ways you can send the file to the webhook, but for my sake and yours here is the simplest one:

Inside the command line you would send to a suspected cheater, add a `-Webhook`

```
...,'-HideDetails','-Webhook','https://discord.com/api/webhooks/.../..."
```

`-Webhook` takes a URL.

Highest priority, but the URL then sits in the paste and in the process command line. The webhook should then be treated as fully compromised, (all info inside can be deleted, which is a real concern) so once the check has concluded, download/forward the final results.

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

**Does Command Prompt need to be ran as administrator?**
Running as administrator is required for most checks, however, if ran without it, it auto elevates and shows a UAC prompt to the user.
