# 07 · SOC defender guide

[⬅ Infrastructure](06-infrastructure.md) · **SOC defender guide** · [Threat hunting ➡](08-threat-hunting-playbook.md)

> **TLP:CLEAR** · as of **2026-10-15** · for SOC analysts, detection engineers and incident responders.
> Everything referenced here is in [`detections/`](../detections/) and was validated offline ([how](../detections/README.md#validation)).

---

## 🚨 First 60 minutes

| ✅ | Action | Where |
|---|---|---|
| ☐ | **Run the four sweeps** that answer "are we already hit?" — KQL **Q01** (ftp.exe -s), **Q03** (`Windowsupdate.exe` in `%LOCALAPPDATA%`), **Q05** (December installer), **Q09** (hashes). Defender XDR hunts **30 days** natively; for the full campaign window (Dec 2025 →) run them with `ago(330d)` on tables retained in Sentinel or your SIEM | [`defender-xdr-hunting.kql`](../detections/kql/defender-xdr-hunting.kql) · Splunk S01 / S03 / S05 / S09 |
| ☐ | **Run Q08** (network indicators with date windows) — read the `Window` column before you escalate | same files |
| ☐ | **Block** the actor-only domains, IP, URLs and `quicsilver-sha256.txt` | [`iocs/blocklists/`](../iocs/blocklists/) (**not** `quicsilver-sha256-hunt.txt` or the `timebound` file — those are hunt-only) |
| ☐ | **Deploy YARA** to EDR / mail / sandbox | [`quicsilver.yar`](../detections/yara/quicsilver.yar) |
| ☐ | **Enable the Sigma rules** (`sigma convert -t <backend> -p <pipeline> detections/sigma/`) | [`detections/sigma/`](../detections/sigma/) |
| ☐ | **Check UDP/443 egress** — if QUIC leaves your network unmonitored, decide now whether to block it (see Harden) | firewall |

---

## Detection catalogue

| Rule | Platform | Catches | Fidelity | Needs |
|---|---|---|---|---|
| `proc_creation_win_ftp_script_nested_underscore_folders` | Sigma · KQL Q01 · SPL S01 | The exact QUICSILVER / GriefLure LNK launch | **Very high** | Process creation + command line |
| `proc_creation_win_ftp_script_execution_from_lnk` | Sigma · KQL Q01 | Any `ftp.exe -s:` (incl. the `-s"":` trick) | High | Process creation |
| `proc_creation_win_ftp_spawns_cmd` | Sigma | `ftp.exe` running `!` shell lines | High | Parent process |
| `proc_creation_win_cmd_copy_concat_doc_to_exe` | Sigma · KQL Q02 · SPL S02 | `.doc + .doc → .exe` rebuild | **Very high** | Command line |
| `file_event_win_quicagent_windowsupdate_localappdata` | Sigma · KQL Q03 · SPL S03 | The June/August drop | **Very high** | File events |
| `file_event_win_quicagent_startup_systemin_lnk` / `…create_lnk_ps1` | Sigma · KQL Q04 · SPL S04 | Startup persistence | **Very high** | File events |
| `proc_creation_win_powershell_shell_application_shellexecute` | Sigma · KQL Q04 | `launchViaCOM` | Medium | Command line |
| `file_event_win_quicagent_systempubliccache_exe` · `proc_creation_win_attrib_hide_systempubliccache` | Sigma · KQL Q05 · SPL S05 | December installer | **Very high** | File + process |
| `proc_creation_win_tasklist_csv_from_user_writable_parent` | Sigma · KQL Q05 | EDR check (`bdagent.exe`, `sentinelagent.exe`) | Medium (baseline) | Parent path |
| `proc_creation_win_cmd_ping_delay_self_delete` | Sigma · KQL Q05 | Self-delete | Medium (generic) | Command line |
| `file_event_win_quicagent_original_path_txt` | Sigma · KQL Q06 · SPL S06 | April build (Q06 / S06 also catch its `Downloads\*.hta` clean-up) | High | File events (+ file-delete events) |
| `network_connection_win_quic_from_quicagent_paths` | Sigma · KQL Q07 · SPL S07 | QUIC from the install paths | High | Network + process (Sysmon 3 logs UDP) |
| `proc_creation_win_quicagent_lolbin_children` | Sigma · KQL Q12 · SPL S12 | Operator `shell` tasks | **Very high** | Parent path |
| `dns_query_win_quicsilver_infrastructure` | Sigma · SPL S08 · Suricata | Resolver / C2 lookups | High (time-bound) | DNS |
| Suricata `quic.sni` / `tls.sni` / `dns.query` (sid 1913001+) | Suricata 7 | C2 names in the QUIC Initial, Worker SNI | High | Network sensor |
| YARA `*_Pin`, `C2_Protocol`, `RC4_Key_Builder`, `Worker_Resolver`, `*_Installer`, `Builder_Paths` | EDR / retro-hunt / memory | All four builds, both lineages; `RC4_Key_Builder` also hits the current `header.doc` (`4a1a1b14…`) and process memory | **Very high** | File or memory scan |
| YARA `LNK_FTP_Script_Loader`, `FTP_Script_Split_Payload`, `VHD_Lure_Container` | Mail / proxy / EDR | The lure before anyone opens it | High | File scan |

---

## Triage playbooks

### A · `ftp.exe -s` from a mounted VHD (Q01 / S01)

| Step | Do |
|---|---|
| 1 | Get the full command line. `_/_/j/` or `_\_\j\` → treat as **confirmed** QUICSILVER / GriefLure. |
| 2 | Find the mounted volume and the container: `DeviceFileEvents` for `*.vhd` / `*.vhdx` / large `*.jpg` in Downloads, Outlook cache or Temp in the previous 30 minutes (Q10). |
| 3 | Look for children of `ftp.exe` (`cmd.exe`), then `%LOCALAPPDATA%\Windowsupdate.exe` (Q02, Q03). |
| 4 | **Isolate** if `Windowsupdate.exe` ran. Collect the VHD — its Recycle Bin is evidence ([06](06-infrastructure.md#the-lure-factory--one-container-eight-decoy-slots)). |

### B · `Windowsupdate.exe` in `%LOCALAPPDATA%` (Q03 / S03)

| Step | Do |
|---|---|
| 1 | Hash it. Known: `cd147efe…`, `c15aead1…` (the December `2655c016…` is a memory image — its hash will not match a disk copy). Unknown hash + RAT CA PEM in the file = new build (run YARA). |
| 2 | Check `Startup\SystemIn.lnk`, `%TEMP%\create_lnk_<digits>.ps1` and a `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File …create_lnk_…` launch (Q04). |
| 3 | Pull network events for the process: HTTPS to `*.workers.dev`, then UDP/443 (Q11). Record every UDP/443 destination — that is the live C2. |
| 4 | Child processes (Q12) = operator activity. Scope lateral movement and data access from that time on. |

### C · `C:\Users\Public\Downloads\SystemPublicCache\` (Q05 / S05)

| Step | Do |
|---|---|
| 1 | This is the **December 2025** build. Expect `tasklist /FO CSV /NH` ×2, `attrib +h +s`, a relaunch with the old path as argument, and deletion of the original. |
| 2 | If **Bitdefender or SentinelOne** was running, the implant **skips** this install step and keeps running from where it was launched — search for the launch path instead (QUIC from `%TEMP%` / Downloads, Q07). |
| 3 | C2: hard-coded `www.maui-cocktailbar.com` (actor-held only until 2026-06-06). |

### D · `C:\Users\Public\original_path.txt` (Q06 / S06)

April build (`rat/agent`). The original writes `original_path.txt`, copies itself to `C:\Users\Public\<name>.exe` and exits; the copy deletes the original **and** `original_path.txt` about a second later — so the `.txt` is usually **gone from disk**: rely on the file-create event. The copy is not hidden; the decoy PDF is written **next to the original executable** (`<name without .exe>.pdf`). It **deletes every `*.hta` in the user's Downloads** — check the browser and mail history for an HTA, likely the delivery stage. If **SentinelOne** (`SentinelAgent.exe`) or **Trend Micro** (`ptsessionagent.exe`) runs, it opens the decoy, **hides its own file (+H +S) and runs in place** — no copy, no `.txt`; search for the original launch path instead. **Bitdefender** (`bdagent.exe`) only switches the relaunch to `cmd /c`. C2 `www.maui-cocktailbar.com` → 38.60.244.141 (≥ 7 Feb → 6 Jun 2026 for the `www` name).

### E · QUIC from a non-browser process (Q07 / Q11 / S07 / S11)

| Step | Do |
|---|---|
| 1 | Is the binary in a user-writable path? Is it signed? Most legitimate QUIC is browsers, Teams, Zoom, Discord, Steam. |
| 2 | Did it reach `*.workers.dev`, `mediumser.com` or a LightNode (AS154177) address first? → escalate. |
| 3 | A PCAP with only 1,280-byte client packets to UDP/443 and nothing back is the "dead C2" pattern ([05 §10](05-reverse-engineering.md#10--network-behaviour-in-sandboxes)). |

### F · DNS / proxy hit on a campaign name (Q08 / S08 / Suricata)

Check the date. `www.maui-cocktailbar.com` after **2026-06-06** and `104.64.211.22` after **2026-08-11** belong to someone else ([`excluded.csv`](../iocs/excluded.csv)). A hit on the Workers or `register.mediumser.com` at any time is meaningful — find the process.

---

## Incident response checklist

| ☐ | Item |
|---|---|
| ☐ | Isolate the host (network containment keeps QUIC from reaching a re-armed C2) |
| ☐ | Acquire memory before killing the process — the resolved C2 name and any task data may only be recoverable there. The RC4 keys are static (`MySecretEncryptionKey2025!@#$%`, April `2024axcegbaxcegb`), so captured traffic bodies can be decrypted |
| ☐ | Collect: the VHD (or `.jpg`) and any `.lnk` from Downloads / Outlook cache; `%LOCALAPPDATA%\Windowsupdate.exe`; `Startup\SystemIn.lnk`; `C:\Users\Public\Downloads\SystemPublicCache\`; `C:\Users\Public\*.exe`; `original_path.txt` and the original EXE are usually already deleted by the April copy — use file-create telemetry; hidden (+H +S) EXEs where the April lure was opened; recently deleted `Downloads\*.hta` (April build) |
| ☐ | Timeline: VHD open → `ftp.exe` → `cmd.exe copy /b` → implant start → first UDP/443 |
| ☐ | Remove persistence (`SystemIn.lnk`), the implant and its copies; reset the user's credentials and sessions |
| ☐ | Search the fleet for the same hashes, paths and the C2 IPs it actually used (Q09, Q08) |
| ☐ | Submit new samples privately first (your CERT, trusted sharing groups); a public upload tells the operator |

---

## Harden

| Control | How | Stops |
|---|---|---|
| **Disable double-click mounting of VHD / VHDX / ISO** for standard users | Set `ProgrammaticAccessOnly` (empty string) under `HKCR\Windows.VhdFile\shell\mount` and `HKCR\Windows.IsoFile\shell\mount` (GPO registry preference) | The whole delivery chain |
| **Mail gateway**: block `.vhd`, `.vhdx`, `.iso`, `.img` — and inspect content, not names (`TrainingAnnouncement.jpg` is a VHD; footer `conectix`) | Gateway policy + YARA `QUICSILVER_VHD_Lure_Container` | Delivery |
| **Restrict `ftp.exe`** for users who never need it | WDAC / AppLocker deny for `%SystemRoot%\System32\ftp.exe` | The loader step (also GriefLure) |
| **Control QUIC egress**: block UDP/443 outbound except where you need it (browsers fall back to TCP/443); or set browser policy `QuicAllowed=false` and block UDP/443 for everything else | Firewall / proxy | C2 channel |
| **Block execution from user-writable roots**: `%LOCALAPPDATA%\*.exe` (root), `C:\Users\Public\**` | WDAC / AppLocker / ASR rule "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" | The implant |
| **Watch the Startup folder** | Sigma `file_event_win_quicagent_startup_systemin_lnk` + generic Startup `.lnk` creation alerts | Persistence |

---

## False positives and tuning

| Rule | Known noise | Tune |
|---|---|---|
| ftp.exe `-s` generic | Legacy scripted FTP jobs | Allow-list by parent (scheduled task / service) and script path; keep the `_/_/j/` rule untuned |
| QUIC from user-writable paths (Q07) | Portable browsers, Electron apps, game launchers | Allow-list by signer and hash, not by name |
| `tasklist /FO CSV /NH` from Temp | Installers, RMM agents | Baseline 30 days; alert on unsigned parents |
| Ping-delay self-delete | Uninstallers | Combine with a non-Program-Files original path |
| DNS rule | `www.maui-cocktailbar.com` (new owner since 2026-09-29) | Treat as informational after 2026-06-06 |
