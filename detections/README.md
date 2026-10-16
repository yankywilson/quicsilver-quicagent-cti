# 🛡️ Detections

TLP:CLEAR · 2026-10-15 · Operation QUICSILVER / QUICAgent. Triage guidance for every rule: [SOC defender guide](../docs/07-soc-defender-guide.md).

## 📦 The pack

| Folder | Content | Count |
|---|---|---|
| [`yara/`](yara/quicsilver.yar) | File / memory rules for all four builds, both lineages, the LNK, the ftp script and the VHD | 11 rules |
| [`sigma/`](sigma/) | Process, file, network and DNS rules (Windows) | 16 rules |
| [`kql/`](kql/defender-xdr-hunting.kql) | Microsoft Defender XDR advanced hunting | 12 queries (Q01–Q12) |
| [`spl/`](spl/splunk-hunting.spl) | Splunk (Sysmon) | 12 searches (S01–S12) |
| [`suricata/`](suricata/quicsilver.rules) | Suricata 7: `dns.query`, `tls.sni`, **`quic.sni`**, C2 IP rules | 26 rules (sid 1913001+) |
| [`zeek/`](zeek/quicsilver.intel) | Zeek Intel framework (domains, IPs, URLs, hashes, cert SHA-1, e-mail) | generated |

Suricata and Zeek files are **generated** from [`iocs/iocs.csv`](../iocs/iocs.csv) by [`tools/build_exports.py`](../tools/build_exports.py) — edit the CSV, not the outputs.

## 🧬 YARA rules

| Rule | Matches | Fidelity | Tag |
|---|---|---|---|
| `QUICSILVER_QUICAgent_RAT_CA_Pin` | Dec, Jun, Aug builds; `header.doc`; the VHD | Very high | CORROBORATED (Dec pin NOVEL) |
| `QUICSILVER_QUICAgent_RAT_TeamServer_Pin` | Apr build | Very high | NOVEL |
| `QUICSILVER_QUICAgent_C2_Protocol` | All four builds (survives a re-key or new C2; **requires quic-go**) | High | NOVEL |
| `QUICSILVER_QUICAgent_RC4_Key_Builder` | All four builds, the current `header.doc` (`4a1a1b14…`), the VHD, process memory — the `movabs` sequence that builds each lineage's RC4 key | Very high | CORROBORATED (agent key) · NOVEL (April key, stack build) |
| `QUICSILVER_QUICAgent_Worker_Resolver` | Jun, Aug builds; `body.doc`; the VHD | Very high | CORROBORATED |
| `QUICSILVER_QUICAgent_December_Installer` | Dec build | Very high | NOVEL |
| `QUICSILVER_QUICAgent_April_Installer` | Apr build (EDR names, `original_path.txt`, `*.hta` clean-up, `sample.pdf`) | High | NOVEL |
| `QUICSILVER_QUICAgent_Builder_Paths` | Dec, Apr builds (no `-trimpath`) | Very high | NOVEL |
| `QUICSILVER_LNK_FTP_Script_Loader` | The ACMECS LNK; GriefLure-style LNKs | High | CORROBORATED |
| `QUICSILVER_FTP_Script_Split_Payload` | The `_` script | Very high | CORROBORATED |
| `QUICSILVER_VHD_Lure_Container` | The ACMECS VHD | High | NOVEL |

Two traps we avoided: a **plain-string** rule on Seqrite's RC4 key misses (the key is never one string — use `RC4_Key_Builder`), and **`/poll`** is not a QUICAgent endpoint (it is Go's `internal/poll` package path, in every Go binary).

## 📐 Sigma rules

| Rule | Log source | Level | Tag |
|---|---|---|---|
| `proc_creation_win_ftp_script_nested_underscore_folders` | process_creation | critical | CORROBORATED |
| `proc_creation_win_ftp_script_execution_from_lnk` | process_creation | high | CORROBORATED |
| `proc_creation_win_ftp_spawns_cmd` | process_creation | high | CORROBORATED |
| `proc_creation_win_cmd_copy_concat_doc_to_exe` | process_creation | high | CORROBORATED |
| `file_event_win_quicagent_windowsupdate_localappdata` | file_event | high | CORROBORATED |
| `file_event_win_quicagent_startup_systemin_lnk` | file_event | high | CORROBORATED |
| `file_event_win_quicagent_create_lnk_ps1` | file_event | high | CORROBORATED |
| `proc_creation_win_powershell_shell_application_shellexecute` | process_creation | medium | NOVEL |
| `file_event_win_quicagent_systempubliccache_exe` | file_event | high | NOVEL |
| `proc_creation_win_attrib_hide_systempubliccache` | process_creation | high | NOVEL |
| `proc_creation_win_tasklist_csv_from_user_writable_parent` | process_creation | medium | NOVEL |
| `proc_creation_win_cmd_ping_delay_self_delete` | process_creation | medium | NOVEL |
| `file_event_win_quicagent_original_path_txt` | file_event | high | NOVEL |
| `network_connection_win_quic_from_quicagent_paths` | network_connection | high | NOVEL |
| `proc_creation_win_quicagent_lolbin_children` | process_creation | critical | NOVEL |
| `dns_query_win_quicsilver_infrastructure` | dns_query | high | CORROBORATED (time-bound) |

### Converting Sigma

```bash
pip install sigma-cli
sigma plugin install kusto splunk
sigma convert -t kusto  -p microsoft_xdr  detections/sigma/      # Defender XDR / Sentinel
sigma convert -t splunk -p splunk_windows detections/sigma/      # Splunk
```

The Defender XDR pipeline has no `dns_query` table — use KQL **Q08** for DNS.

## Validation

All results below are from **2026-10-15**, offline.

| Check | Tool | Result |
|---|---|---|
| YARA compiles | yara-python 4.5.4 | 11 rules |
| YARA expected matches | [`tests/run_yara_tests.py`](../tests/run_yara_tests.py) + [`yara_expected.json`](../tests/yara_expected.json) | **11 / 11** specimens match exactly as expected (incl. 2 expected non-matches) |
| YARA false positives | 2,837 benign files (`/usr/bin`, system `.so`, the Go toolchain, a benign Go `windowsgui` PE built for the test) | **0** — [`tests/yara_results.txt`](../tests/yara_results.txt) |
| Sigma | pySigma validators + conversion to Kusto (`microsoft_xdr`) and Splunk (`splunk_windows`) | **16 / 16** OK |
| KQL | Microsoft Kusto.Language parser (`@kusto/language-service-next` 12.4.1) with Defender XDR table schemas | **12 / 12** queries, 0 errors. All ship with `ago(30d)` — the native Defender XDR limit |
| Suricata | Suricata **7.0.3** `-T` (full rule load) + suricataparser | Loads; 26 rules, unique sids |
| Zeek intel | Field-count check | OK |
| STIX 2.1 | `stix2` strict parse + `stix2-patterns` + reference check | 72 objects, 0 pattern errors |
| Exports | `build_exports.py` twice → byte-identical | Deterministic |

### Run it yourself

```bash
pip install -r tools/requirements.txt
npm install @kusto/language-service-next@12.4.1           # optional, for KQL
bash tests/run_all.sh node_modules
QUICSILVER_SAMPLES=/path/to/your/samples bash tests/run_all.sh   # full YARA expectation run (files are only read)
```

## 🎛️ Tuning

See [07 · False positives and tuning](../docs/07-soc-defender-guide.md#false-positives-and-tuning). Never block `workers.dev` or all QUIC blindly in production without a fallback plan — block the exact hosts, and move QUIC to an allow-list.
