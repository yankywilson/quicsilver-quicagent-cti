# 09 · Methodology and corrections

[⬅ Threat hunting](08-threat-hunting-playbook.md) · **Methodology** · [Sources ➡](10-sources.md)

> **TLP:CLEAR** · as of **2026-10-15** · how every finding in this repository was produced, tagged, checked and corrected.

---

## 🛡️ Collection posture

| Principle | In practice |
|---|---|
| **Passive only** | No connection to actor infrastructure — no browsing, scanning, banner grabs or sandbox submissions of actor URLs. Sources: passive DNS, WHOIS history and reverse WHOIS, certificate transparency, scan-engine archives, **existing** public sandbox reports. |
| **Static analysis only** | Samples were read, never executed: Go build info, pclntab symbols, string tables, capstone disassembly, PE and certificate parsing, VHD / FAT / LNK forensics. |
| **Offline analysis host** | Samples handled on an isolated analysis environment; Python run with `-I`; each sample in its own folder; scripts kept elsewhere. |
| **Read-only consoles** | Lookups only — nothing sent, released, deleted or submitted. |
| **Bystanders protected** | `104.64.211.22` now runs someone else's workload: not probed, current services not published. The domain's legitimate former owner and its new 2026 owner are not named. |
| **No social-media sources** | Posts and mirrors of posts were excluded, even when they repeated vendor findings. |

---

## 🔬 Methods

| Method | Used for | Tools |
|---|---|---|
| **Go static analysis** | Lineages, functions, source-line order, strings, certificates | `go version -m`, pclntab dump, [`quicagent_triage.py`](../tools/quicagent_triage.py), capstone |
| **Byte-level comparison** | August respin (1 byte); deleted `header.doc` vs each build — positional identity per 50 KB window, **aligned at each file's `.text` start** (raw offsets differ: `0x1000` in the December memory image, `0x600`/`0x400` in the others; see C14, C24) | Python |
| **Certificate reconstruction** | Rebuilding the Censys leaf and verifying its signature | [`rat_leaf_verify.py`](../tools/rat_leaf_verify.py) |
| **Container forensics** | VHD footer, FAT stamps, Recycle Bin `$I` records, implied clock offsets | `dissect.hypervisor` / `dissect.fat`, [`vhd_recycle_timeline.py`](../tools/vhd_recycle_timeline.py) |
| **LNK forensics** | Tracker block, DROID UUIDv1 → time + MAC, VolumeID label code page | LnkParse3, [`lnk_tracker.py`](../tools/lnk_tracker.py) |
| **Sandbox records** | DNS answers, QUIC flow sizes, dropped files, server `Date` headers to date a run | Triage public reports, Joe Sandbox report + memory strings, PCAPs |
| **Infrastructure** | Domains, IPs, certificates | Validin, SecurityTrails, VirusTotal (WHOIS, resolutions, graph), OTX, Censys, Shodan, FOFA, crt.sh, SANS ISC new-domain feed, reverse WHOIS, ipinfo |
| **Sample availability** (Rule 9) | Before any analysis promise | VirusTotal, Triage, MalwareBazaar, Hybrid Analysis |
| **Independent review** | Before release, a separate reviewer re-derived every claim from the samples, symbol dumps, tool output and the Seqrite report without seeing our reasoning. Round 1's 25 findings are logged as C14–C22; round 2 (a fresh reviewer checking the fixes) found 11 more, logged as C23–C27. Each was re-verified first-hand | Separate agents; same offline toolset |
| **Detection validation** | Every rule shipped | yara-python, pySigma (+ Kusto and Splunk backends), Kusto.Language parser, Suricata 7.0.3 `-T`, suricataparser, stix2 + stix2-patterns — see [detections/README](../detections/README.md#validation) |

### Connectors used during the investigation

| Connector | Used for | Result |
|---|---|---|
| **Firecrawl** | Reading the Seqrite report, Triage reports, OTX passive-DNS API, ipinfo; web search | Seqrite's exact claims and IOC list (basis of every PUBLISHED tag); Triage runs for all four builds; ASN for three C2 IPs; `ptsessionagent.exe` = Trend Micro |
| **ThreatCluster** | Clustered reporting, 7-day window | `QUICSILVER`, `QUICAgent`, `mediumser`: **no clusters** (2026-10-15 05:22 UTC) |
| **Malwarebytes** | Reputation of URLs and the registrant e-mail | Worker URLs, `register.mediumser.com`, registrant e-mail: **unknown**; `www.maui-cocktailbar.com`: **suspicious**, domain age 15 days (new owner) |
| **ScanMalware** | Existing scans and CT only — **never** `submit_scan` | No scans of `mediumser.com`; CT entries 2026-06-27 and 2026-08-25 |
| **Microsoft Learn** | Defender XDR `DeviceNetworkEvents` schema (`Protocol` = TCP/UDP) | Grounded KQL Q07 / Q11 and the Sigma network rule |
| **Past-conversation search** | Repository conventions from the DarkBlinders release | Same layout, author and packaging |

---

## Tags and the ICD-203 scale

### Evidence tags — on every finding

| Tag | Meaning |
|---|---|
| **NOVEL** | First-hand ANCHOR finding, not in any public report as of 2026-10-15 |
| **CORROBORATED** | Published by others **and** confirmed first-hand |
| **PUBLISHED** | A vendor claim we cite but did not confirm |
| **EXCLUDED** | Examined and ruled out — reasons in [`iocs/excluded.csv`](../iocs/excluded.csv) |

### Likelihood — ICD-203 estimative language

| Term | Probability |
|---|---|
| Almost no chance | 1–5 % |
| Very unlikely | 5–20 % |
| Unlikely | 20–45 % |
| Roughly even chance | 45–55 % |
| Likely | 55–80 % |
| Very likely | 80–95 % |
| Almost certain | 95–99 % |

Confidence (low / moderate / high) rates the **evidence**, not the claim.

### SOP rules cited in this repository

| Rule | Text |
|---|---|
| **Rule 4** | Vendor labels are claims. A family name in a filename, an AV verdict or a feed tag is not evidence. |
| **Rule 8** | No attribution on shared tooling or shared / commercial infrastructure. |
| **Rule 9** | Verify that a public sample exists before promising analysis of it. |

---

## Corrections log

| # | Was | Now | Why |
|---|---|---|---|
| **C1** | Shodan `ssl:"RAT System"` hit 3.22.233.21 treated as a lead | **EXCLUDED** | The query matched the hostname `rat-system.ddns.net`; use `ssl.cert.issuer.cn:"RAT CA"` |
| **C2** | `104.64.211.22` EXCLUDED | **Likely actor-held 2026-07-07 → 08-11** | Validin and SecurityTrails windows |
| **C3** | SSH-key pivot on `38.60.244.141` | **Dropped** | Key captured after the actor left the host |
| **C4** | July `register.mediumser.com` timeline tagged NOVEL | **PUBLISHED** | Seqrite had used the same Validin data |
| **C5** | `38.60.244.141` actor-held 1–6 Jul only | **≥ 2026-02-07 → 07-06** | VirusTotal resolutions for `www.maui-cocktailbar.com` and `register.mediumser.com` |
| **C6** | C2 upgrade for `104.64.211.22` to *very likely* | **Back to likely** | Seqrite's "continuous QUIC traffic" is consistent with one-sided client retries |
| **C7** | "Both C2 names died ~36 h after the report"; June 2026 certificates and 172.234.24.211 / 172.239.57.117 as actor | **Retracted / EXCLUDED** | `maui-cocktailbar.com` expired in June (normal lifecycle); the June certificates belong to registrar parking. Only the `register.mediumser.com` deletion may be a reaction (low–moderate) |
| **C8** | Seqrite's file hashes left out of a "known" list in a browser-agent prompt | **PUBLISHED** | Re-tagged those items |
| **C9** | First known C2 use **≥ 2026-02-07** | **≤ 2025-12-26** | December build `2655c016` resolved its C2 live in Triage |
| **C10** | `2655c016` "may be VirusTotal graph noise" | **Very likely, then almost certain, QUICAgent** | Hard-coded C2, QUIC pattern, then static RE (RAT CA pin, shared source) |
| **C11** | December build and deleted `header.doc` "share a toolchain" (same entry point); April "a different toolchain" | **Withdrawn** — itself **reversed by C14** | All builds report `go1.20`; the entry point moves with code layout. Byte identity puts the deleted payload with the **April** lineage *(this byte comparison was misaligned — see C14)* |
| **C12** | Predicted the December build would be module `rat/agent`, pin RAT-TeamServer and use a different Go point release | **All three falsified** | Module `agent`, pins RAT CA, `go1.20`. The `qwe` prediction held |
| **C13** | Release draft listed the RAT CA name, `SystemIn.lnk` / `create_lnk_*.ps1`, the five task names, the 5 s beacon, `X-Agent-ID`, the sandbox-evasion delay, `desktop-stv6gg` and the GriefLure link among the novel findings | **PUBLISHED / CORROBORATED** | All are in Seqrite's report (pre-release re-read, 2026-10-15) |

**C14–C27: found by two independent pre-release reviews (2026-10-15) — C14–C22 in round 1, C23–C27 in round 2, which re-checked the round-1 fixes. Each was re-verified first-hand.**

| # | Was | Now | Why |
|---|---|---|---|
| **C14** | Deleted `header.doc` put in the **`rat/agent`** lineage ("92–97 % identical to April"); "`rat/agent` existed by January 2026"; C11 withdrew the shared entry point | **Reversed: likely `agent` lineage, closest to the December build (low confidence)**. "By January" withdrawn. C11's entry-point observation **reinstated** | We compared raw file offsets; the December specimen is a memory image (C24), so its `.text` starts at `0x1000`, the others at `0x600`. Aligned at `.text`: December 98.0 %, April 95.1 % (first 390,000 B); December stays ≥ 95.6 % to 500 KB, April falls at 400 KB. Section sizes match December within 15 KB (April: ~300 KB off) — see C27 for how this evidence is now described |
| **C15** | `/poll` listed as a C2 endpoint (docs, ATT&CK T1071.001, YARA `$e2`, triage tool) | **Removed**. Real paths: `/heartbeat`, `/result`, `%s/upload?%s`, `%s/upload/next?%s`, `/download?task_id=` (`agent`); `/register`, `/upload/chunk/pull` (`rat/agent`) | Every `/poll` hit is inside Go's `internal/poll` package path, present in all Go binaries |
| **C16** | June persistence "reached through a vectored exception handler"; "call-graph tools miss it" | **A VEH is registered and an exception raised (likely anti-debug); persistence is then called directly** | `setupVEHStartup` (0x140334420) calls `addToStartupFolder` at 0x140334469 / 0x140334478 in both branches |
| **C17** | Seqrite's RC4 key "in none of the builds" — logged as a vendor correction, an EXCLUDED row and a dated null; "do not write YARA on it" | **CORROBORATED** for the `agent` lineage; April key **`2024axcegbaxcegb`** found (NOVEL); YARA `RC4_Key_Builder` added | The key is built on the stack by four `movabs` stores (length `0x1e`); our search only looked for contiguous strings |
| **C18** | "Continuous QUIC traffic" listed as a correction to Seqrite | **Dropped** | None of our runs contacted `104.64.211.22`, the server Seqrite observed — not a like-for-like test |
| **C19** | "Six decoys"; "payload swapped 14 May"; the `5-14-2026.pdf` slot "from 16 May"; VHD row "built after 26 Jun, in use since Feb" | **Eight decoy slots** (7 deleted + current), counting rule stated — real-document count fixed again in C26. 14 May = the old payload's **deletion** (refined in C27). Slot start "mid-May". VHD created 13 Jan, LNK/script modified 30 Jul | FAT and `$I` stamps re-read; the 16 May stamp is on the clock that runs ≥ 2 days off |
| **C20** | April: "Bitdefender skips the install"; decoy "in `%TEMP%`" / "`HolidayNotice.pdf.pdf`"; no HTA behaviour; ftp `start` line assumed to work | Only **SentinelOne / Trend Micro** skip the install (refined in C25), **Bitdefender** switches the relaunch to `cmd /c`. Decoy (`sample.pdf`) goes **next to the EXE**; Triage shows `%TEMP%\<sha256>.pdf`. **Deletes `Downloads\*.hta`** (added). Launch line **confirmed** — ftp.exe strips the quotes (Triage 260818-sw2wjadk7v) | April `main.main` 0x72db87–0x72dc00 and 0x72de57; `extractAndOpenPDF` 0x72d2de–0x72d426; Triage process trees |
| **C21** | Tags and wording: headers CORROBORATED; sandbox-evasion PUBLISHED; `desktop-stv6gg` PUBLISHED in 05; "same API / same EDR list"; "deliberate respin"; "VHD posing as JPEG or PDF"; "7,007,744-byte image"; TeamServer extensions "—"; December build named `Windowsupdate.exe` | Headers **NOVEL** (only `X-Agent-ID` PUBLISHED); evasion **CORROBORATED** (0x140333860); `desktop-stv6gg` **CORROBORATED** everywhere; "**overlapping**"; "**likely** deliberate"; only `TrainingAnnouncement.jpg` is disguised; 7,007,744 B is the **file** size (`SizeOfImage` 7,405,568); TeamServer KU/EKU/SAN `DNS:RAT-TeamServer` listed; December build's Triage name is `2025-12-22_ef50056b…` | Re-read against the binaries, certificates and Triage |
| **C22** | Detection notes: "YARA `C2_Protocol` still keys on the endpoints" without QUIC; KQL lookbacks 180 d / 330 d; SNI "readable without decryption"; decoys and `bf8afbd1` in the block-now SHA-256 list; NXDOMAIN lag "two days" vs "~36 h"; `www` → `.141` "Feb–Jul"; Seqrite's sandbox run "in August" | The rule **requires** quic-go; KQL ships `ago(30d)` (native Defender XDR limit — Microsoft Learn), 330 d only on Sentinel-retained tables; SNI needs **Initial decryption** (public keys); hunt-only hashes moved to `quicsilver-sha256-hunt.txt`; lag **1–2 days**; window ends **6 Jun**; Seqrite's run is **undated** (7 Jul–11 Aug by its IP) | Rule logic, Microsoft Learn (advanced-hunting quotas), RFC 9001, our own timelines |
| **C23** | (added after round 1) "Within ~28 h of the report the Workers stopped serving the C2 name"; "Workers first, then DNS"; rated moderate | **Between 15 Aug 20:10 and 18 Aug ~15:29 UTC (likely)** — a window from 40 h before to 28 h after the report; order vs the DNS deletion not proven; back to **low–moderate** | Triage 260815-yx3r4stvdy (15 Aug) still got `register.mediumser.com`; we had overlooked it. 15:29 is the submission time; the reply content is not visible |
| **C24** | December specimen `2655c016` treated as the shipped file; its offsets as file offsets | **A memory image** (raw pointer = virtual address for every section, `ImageBase` `0x920000`, relocated `.data`, untouched `.bss`). Its hash describes the dump; offsets are RVAs | PE headers; a disk copy on a victim will hash differently — hunt with YARA |
| **C25** | (round 1 fix) April: the install copy "hidden"; `original_path.txt` written by the copy; "collect `original_path.txt`" | `setFileSystemHidden` (+H +S, in place) runs **only** when SentinelOne / Trend Micro is found; the `C:\Users\Public` copy is not hidden. The **original** writes `original_path.txt` and exits; the copy deletes both after ~1 s — expect file-create telemetry, not files | April `main.main`: 0x72dbc4, 0x72dbf9, 0x72dc32, 0x72df47; 0x72da6e–0x72da92 |
| **C26** | (round 1 fix) "Five real documents"; ACMECS decoy "shown to the victim" | **Four real documents**; the current `ACMECS_Pillar_1.pdf` is a **corrupt** 4 KB file (no objects; `startxref` past its end; last 203 B = the tail of the 70,213-B `5-14-2026.pdf`) | Byte comparison of the two files |
| **C27** | (round 1 fix) Current payload "written 25 Jun, ~8 min after TrainingAnnouncement.pdf"; header.doc lineage evidence "entry point + `.data` size are the real signal"; MD5 list still held the hunt-only fragment; RC4 offsets 2 bytes into the instruction; "fires on header.doc" unqualified; SPL header missing Sysmon 23/26; "a working implant from day one" | Mtime **25 Jun 04:27:42 on an unknown clock**, placed on or after; `header.doc`'s inherited creation time points to a replacement **within seconds of the 14 May deletion** (file-system tunnelling, likely). Lineage evidence restated: section sizes are the signal; the entry point is not independent of the byte test, and December also falls after 500 KB. MD5 list now mirrors the block-now SHA-256 list; offsets corrected (`0x327e8d`…); "current `header.doc` (`4a1a1b14…`)"; SPL header fixed; "an implant (likely `agent`)" | FAT stamps (`copy` keeps source mtime), section headers, `build_exports.py` |

### Corrections to published reporting

| Claim (source) | Correction | Basis |
|---|---|---|
| Worker path `/vere0zme82cadre` (Seqrite; copied by SOCRadar, HivePro, cybersecuritynews) | `/vere0zme82cad` | 59-byte literal in the binary; the next literal starts `reflect` |
| "Earliest campaign observed in April 2026" (Seqrite) | December 2025 | `2655c016`, live C2 on 2025-12-26 |
| Deleted Recycle Bin documents "do not appear to be directly associated with the campaign" (Seqrite) | They were the container's **decoys in sequence**, Jan → Jun 2026 | FAT and `$I` stamps ([06](06-infrastructure.md#the-lure-factory--one-container-eight-decoy-slots)) |

Seqrite's RC4 key was briefly listed here as wrong; it is **right** (C17). The "continuous QUIC traffic" item was dropped (C18).

---

## Dated-nulls register

| Date | Null | Scope |
|---|---|---|
| 2026-10-14 | No public source code for RAT CA, RAT-TeamServer, `rat/agent` or QUICAgent | Code search, GitHub, web |
| 2026-10-14 | RAT-TeamServer certificate not seen by Censys | Censys |
| 2026-10-14 | `TrainingInstructions (1).vhd` not on Triage, MalwareBazaar or Hybrid Analysis | Those three |
| 2026-10-15 | `bf8afbd1…` not on Triage or MalwareBazaar; no web mentions | Those two + web |
| 2026-10-15 | `38.60.244.92`: no OTX passive DNS, no reporting | OTX, web |
| 2026-10-15 | No reporting on QUICSILVER beyond Seqrite and its re-publishers (ThreatCluster: no clusters) | ThreatCluster, web |
| 2026-10-15 | Full 7,007,744-byte early payload (the file behind the deleted `header.doc`) not public | Triage, MalwareBazaar, web |
| 2025-12 → 2026-08 | No server reply to any sandbox QUIC client | Four Triage runs |

---

## 🔒 Redaction decisions

| Item | Decision | Why |
|---|---|---|
| Legitimate prior owner of `maui-cocktailbar.com` | Not named | A victim of domain re-use, not part of the operation |
| 2026 re-registrant of the same domain | Not named | Unrelated third party |
| `104.64.211.22` current services | Not published | Bystander host |
| `jack.amy2015@atomicmail.io` | Published, flagged *pivot, do not contact* | Actor-controlled registrant identifier, single-use |
| Decoy documents | Hashes only | Real-looking government material; do not re-host |
| Samples | None in the repository | TLP:CLEAR, defensive use |
| Pinned certificates | Public certificates included in `tools/data/` (no private keys exist here) | Needed to verify the leaf and to hunt |

---

## ⚠️ Limits of this analysis

- **No live C2 session** was observed by anyone: the protocol is reconstructed from code and strings. Both RC4 keys are recovered statically but have not been seen working on the wire.
- **Victims are unknown**. Targeting is inferred from decoys.
- **Clock artefacts** come from operator machines whose clocks disagree; we use offsets and intervals, not absolute local times, and give no attribution weight to time zones.
- **The lineage of the deleted payload** (likely `agent`) rests on its layout (entry point, `.data` size) and on byte identity of its first ~500 KB of code, most of which is Go runtime; the rest of that file is missing. Low confidence.
- **The VEH handler** was not decompiled: what it does when the exception fires is unknown.
