# 03 · Tactical intelligence

[⬅ Operational](02-operational-intelligence.md) · **Tactical** · [Attribution ➡](04-attribution-assessment.md)

> **TLP:CLEAR** · as of **2026-10-15** · for detection engineers and hunters. Every artefact below was read from a sample or a sandbox record, not copied from a report, unless it is tagged PUBLISHED.

---

## The ten fingerprints that matter most

| # | Fingerprint | Generation | Fidelity | Tag | Rule |
|---|---|---|---|---|---|
| 1 | **`ftp.exe -s"":_/_/j/_/_/_/_/_/_`** started by `explorer.exe` from a mounted VHD | Jun–Aug (and GriefLure) | Very high | CORROBORATED | Sigma `proc_creation_win_ftp_script_nested_underscore_folders` · KQL Q01 |
| 2 | **`cmd.exe` → `copy /Y /b <x>.doc+<y>.doc "%LOCALAPPDATA%\Windowsupdate.exe"`** with parent `ftp.exe` | Jun–Aug | Very high | CORROBORATED | Sigma `…copy_concat_doc_to_exe` · KQL Q02 |
| 3 | **`%APPDATA%\…\Startup\SystemIn.lnk`** created by PowerShell running **`%TEMP%\create_lnk_*.ps1`** | Jun–Aug | Very high | CORROBORATED | Sigma `file_event_win_quicagent_*` · KQL Q04 |
| 4 | **QUIC (UDP/443) from `%LOCALAPPDATA%\Windowsupdate.exe`** right after HTTPS to `*.workers.dev` | Jun–Aug | Very high | NOVEL (pattern) | KQL Q11 · SPL S11 · Sigma `network_connection_win_quic_*` |
| 5 | **`C:\Users\Public\Downloads\SystemPublicCache\<name>.exe`** + `attrib +h +s` + two `tasklist /FO CSV /NH` | Dec 2025 | Very high | NOVEL | Sigma `…systempubliccache*`, `…tasklist*` · KQL Q05 |
| 6 | **`cmd.exe /c ping 127.0.0.1 -n 3 >nul & del /f /q "<original>"`** | Dec 2025 | Medium (generic) | NOVEL | Sigma `…ping_delay_self_delete` |
| 7 | **`C:\Users\Public\original_path.txt`** created (and deleted ~1 s later by the copy) | Apr 2026 | High | NOVEL | Sigma `…original_path_txt` · KQL Q06 |
| 8 | **Embedded PEM** of `CN=RAT CA, O=RAT System` (EC P-384) or `CN=RAT-TeamServer` (RSA-2048) | all | Very high | NOVEL (TeamServer, Dec) · CORROBORATED (RAT CA) | YARA `*_Pin` |
| 9 | **quic-go + `X-Idempotency-Key` + `/heartbeat` `/result`** plus the lineage's upload paths (`%s/upload/next?%s` or `/upload/chunk/pull`) — or the **RC4 key built on the stack** (`48 BA "MySecret" … 48 BA "Encrypti"`) | all | High · very high (key) | NOVEL | YARA `C2_Protocol` · `RC4_Key_Builder` |
| 10 | **C2 server certificate** `C=US, O=RAT System, CN=localhost`, issued by RAT CA, serial 2, SAN `localhost` + `127.0.0.1` | server | Very high | NOVEL | [hunting/queries](../hunting/queries/) |

---

## ATT&CK mapping

33 technique entries, each tagged by evidence: [`attack/mapping.csv`](../attack/mapping.csv) · Navigator layer [`attack/quicsilver-navigator-layer.json`](../attack/quicsilver-navigator-layer.json) ([how to open](../attack/README.md)).

| Tactic | Techniques (NOVEL in **bold**) |
|---|---|
| Resource development | **T1583.001** Domains · **T1583.003** VPS · T1583.006 Web Services · **T1587.001** Malware · **T1587.003** Digital Certificates |
| Initial access | T1566.001 Spearphishing Attachment (PUBLISHED, not observed) |
| Execution | T1204.002 · T1059.003 · T1059.001 · **T1559.001** COM |
| Persistence | T1547.001 Startup Folder |
| Defense evasion | T1553.005 MOTW Bypass · T1036.008 · T1036.007 · **T1036.005** · T1202 Indirect Command Execution · T1027 · T1140 · **T1564.001** · **T1070.004** · T1497.003 |
| Discovery | **T1518.001** Security Software Discovery · **T1057** · T1082 · T1033 · T1083 |
| Command and control | T1102.001 Dead Drop Resolver · **T1008** Fallback Channels · T1071.001 · **T1573.002** · T1573.001 · T1105 |
| Exfiltration | T1041 |

---

## Host artefacts

### Delivery (VHD → LNK → ftp script)

| Artefact | Value |
|---|---|
| Container | `ACMECS_Pillar_1.vhd` — dynamic VHD, 14,716,928 B, virtual size 13,631,488 B, FAT, label `NO NAME`, created **2026-01-13 06:13:38 UTC** by Windows (`win ` / `Wi2k`) |
| Sister container | `TrainingAnnouncement.jpg` — a VHD with a `.jpg` name (PUBLISHED) |
| LNK | `ACMECS_Pillar_1.pdf.lnk` → `%SystemRoot%\System32\ftp.exe` · args `-s"":_/_/j/_/_/_/_/_/_` · icon `.\1.pdf` · window `SW_SHOWMINNOACTIVE` · console font Consolas |
| LNK tracker | machine **`desktop-stv6gg`** (CORROBORATED — published by Seqrite) · DROID MAC **`80:45:dd:e5:91:6e`**, DROID time **2024-05-20 06:52:54 UTC** · volume serial **`C205DAF6`**, label **`我的磁盘`** (GBK `CE D2 B5 C4 B4 C5 C5 CC`) (NOVEL) |
| Folder nest | `_\` (decoy) · `_\_\j\_\_\_\_\_\_` (the script, no extension) · `_\_\j\_\_\_\_\_\_rels\` (payload halves) |
| Script `_` | `!start /max _\ACMECS_Pillar_1.pdf` · `!call copy /Y /b …header.doc+…body.doc "%LOCALAPPDATA%\Windowsupdate.exe" >nul` · `!start "%LOCALAPPDATA%\Windowsupdate.exe" >nul` · `quit`. `ftp.exe` strips the double quotes before handing each line to `cmd.exe /C`, so the command lines you will see have **no quotes** |
| Payload halves | `header.doc` 3,523,328 B (starts `MZ`) + `body.doc` 3,523,328 B = **`cd147efe…`** exactly |

### Implant on disk and in the registry

| Generation | Path | Persistence | Other files |
|---|---|---|---|
| Dec 2025 | `C:\Users\Public\Downloads\SystemPublicCache\<own name>.exe` (+H +S) | Relaunch only (no autorun found) | — |
| Apr 2026 | `C:\Users\Public\<own name>.exe` (not hidden; the copy deletes the original and `original_path.txt` after ~1 s). If SentinelOne or Trend Micro runs: **no install** — the original hides itself (+H +S) and runs in place | Relaunch via `WScript.Shell.Run` — or `cmd /c` if Bitdefender runs | `C:\Users\Public\original_path.txt` (102 B); embedded `sample.pdf` written as `<name without .exe>.pdf` in the EXE's own folder and opened with `cmd /c`; **every `*.hta` in `%USERPROFILE%\Downloads` deleted** |
| Jun–Aug 2026 | `%LOCALAPPDATA%\Windowsupdate.exe` | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SystemIn.lnk` | `%TEMP%\create_lnk_<digits>.ps1` (e.g. `create_lnk_4258168477.ps1`; deleted after use) |

### Process tree you should expect

```text
explorer.exe
└─ ftp.exe -s"":_/_/j/_/_/_/_/_/_                      (from the mounted VHD)
   ├─ cmd.exe /c start /max _\ACMECS_Pillar_1.pdf      → PDF reader (decoy)
   ├─ cmd.exe /C call copy /Y /b …header.doc+…body.doc %LOCALAPPDATA%\Windowsupdate.exe >nul
   └─ cmd.exe /C start %LOCALAPPDATA%\Windowsupdate.exe >nul
      └─ Windowsupdate.exe                               → HTTPS to both Workers
         ├─ powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File %TEMP%\create_lnk_<digits>.ps1
         │                                               → Startup\SystemIn.lnk
         ├─ powershell.exe "$shell = New-Object -ComObject Shell.Application; $shell.ShellExecute('…')"
         └─ cmd.exe / powershell.exe                     (operator 'shell' tasks)
```

The quoted lines down to the PowerShell call are confirmed by Triage 260818-sw2wjadk7v (behavioral31, 2026-08-18); the `ShellExecute` line and the task shells come from the code.

December build (sandbox-observed):

```text
<sample>.exe  (from %TEMP%)
├─ tasklist /FO CSV /NH        x2   (bdagent.exe? sentinelagent.exe?)
├─ attrib +h +s C:\Users\Public\Downloads\SystemPublicCache\<sample>.exe
└─ C:\Users\Public\Downloads\SystemPublicCache\<sample>.exe <original path>
   ├─ tasklist /FO CSV /NH     x2
   ├─ attrib +h …\SystemPublicCache\<sample>.exe
   └─ (deletes the original)
```

April build (sandbox-observed, Triage 260415-d3xg3ad14q):

```text
%TEMP%\c4b46477…87c02.exe                       (Triage named the sample by its SHA-256)
├─ cmd /c %TEMP%\c4b46477…87c02.pdf             → Acrobat Reader (embedded decoy, 287,438 B)
├─ writes C:\Users\Public\original_path.txt     (the original does this, before it copies itself)
└─ C:\Users\Public\c4b46477…87c02.exe           (copy; after ~1 s deletes the original and original_path.txt)
```

The decoy lands **next to the executable** under the executable's name with `.exe` replaced by `.pdf` — `%TEMP%` here only because that is where the sandbox ran it.

---

## Network artefacts

| Artefact | Value | Tag |
|---|---|---|
| Transport | QUIC v1 over **UDP/443**, HTTP/3 (quic-go v0.40.1, qpack v0.4.0, qtls-go1-20 v0.4.1) | CORROBORATED |
| Client Initial | **1,252-byte UDP payload → 1,280-byte IPv4 packets** (quic-go padding). With no server reply: 135 Initials per ~150 s run | NOVEL |
| SNI | The C2 host name (`www.maui-cocktailbar.com`, `register.mediumser.com`). The ClientHello in a QUIC Initial is encrypted, but with keys derived from the **public** Destination Connection ID — any sensor that decrypts Initials (Suricata 7, Zeek, Wireshark) reads it without secrets | NOVEL (detection note) |
| TLS | Server leaf `C=US, O=RAT System, CN=localhost` (EC P-384, serial 2, 2025-12-05 08:17:02 → 2035-12-03) pinned to RAT CA; or RAT-TeamServer (RSA, self-signed) | NOVEL |
| C2 paths | Both: `/heartbeat`, `/result`. `agent`: `%s/upload?%s`, `%s/upload/next?%s`, `%s/download?task_id=%s&file_name=…`. `rat/agent`: `/register`, `/upload/chunk/pull` | NOVEL |
| Headers | `agent` only: `X-Agent-Hostname`, `X-Agent-OS`, `X-Agent-Arch`, `X-Agent-User`, `X-Agent-ID`. Both: `X-Idempotency-Key` | NOVEL (X-Agent-ID PUBLISHED) |
| Body | JSON, RC4-encrypted. Key `MySecretEncryptionKey2025!@#$%` (`agent`) · **`2024axcegbaxcegb`** (`rat/agent`), each built on the stack with `movabs` | CORROBORATED (agent key) · NOVEL (April key) |
| Beacon | 5 s default; operator can set 1–3,600 s (`Interval must be between 1 and 3600 seconds`) | PUBLISHED · NOVEL (range) |
| Resolver | HTTPS GET `https://appupdate.0cmds20cj2cdf8.workers.dev/A3cmf0q9ASCion` and `https://regupdate.eamakfu49dc28wa.workers.dev/vere0zme82cad`; reply lines starting `all:` carry the C2 name | CORROBORATED · NOVEL (path, `all:` format) |
| Resolver state | Both return `error code: 1042` (2026-10-15) | NOVEL |

---

## Indicator sets

| File | Use |
|---|---|
| [`iocs/iocs.csv`](../iocs/iocs.csv) | Everything, with tag, confidence, date window and action |
| [`iocs/blocklists/`](../iocs/blocklists/) | Block now (domains, IPs, URLs, `quicsilver-sha256.txt`) · **hunt only**: `quicsilver-sha256-hunt.txt` (decoys, the old payload half, an unconfirmed lead) and `quicsilver-timebound.csv` (retro-hunts) |
| [`iocs/file-hashes.csv`](../iocs/file-hashes.csv) | SHA-256 / SHA-1 / MD5 / size of every file we analysed |
| [`iocs/excluded.csv`](../iocs/excluded.csv) | What looks related but is not — **read before you block** |
| [`iocs/related-grieflure.csv`](../iocs/related-grieflure.csv) | The sibling template |
| [`iocs/stix/quicsilver.stix2.json`](../iocs/stix/quicsilver.stix2.json) | STIX 2.1 bundle |
