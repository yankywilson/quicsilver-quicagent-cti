# 🧰 Tools

TLP:CLEAR · 2026-10-15 · Every tool **reads files only** — none executes a sample or contacts the network. Run Python with `-I` when the input is untrusted.

## Install

```bash
pip install -r tools/requirements.txt
```

## At a glance

| Tool | What it does | Self-test |
|---|---|---|
| [`quicagent_triage.py`](quicagent_triage.py) | Static triage of a suspected QUICAgent PE: Go build info, pinned certificates vs the known pins, lineage markers (C2 paths, headers, the stack-built RC4 key), C2 / resolver strings, developer paths, `main.*` functions | `--self-test` (synthetic build info) |
| [`vhd_recycle_timeline.py`](vhd_recycle_timeline.py) | Opens a lure VHD without mounting it, lists every file with SHA-256, and rebuilds the Recycle Bin timeline with each deleting machine's UTC offset | `--self-test` (synthetic `$I` record) |
| [`lnk_tracker.py`](lnk_tracker.py) | Builder artefacts from a `.lnk`: machine name, DROID → time + MAC, volume serial and label (decoded in a chosen code page), target and arguments | `--self-test` (the ACMECS DROID and GBK label) |
| [`rat_leaf_verify.py`](rat_leaf_verify.py) | Rebuilds the C2 leaf Censys saw from its parsed fields and verifies its signature with the RAT CA key | `--self-test` (full verification with the bundled CA) |
| [`build_exports.py`](build_exports.py) | Generates block lists, Suricata, Zeek, STIX and the Navigator layer from `iocs.csv` / `mapping.csv` | `tests/run_all.sh` (determinism) |

`data/` holds the **public** certificates pinned by the implants (`rat_ca.pem`, `rat_teamserver.pem`) and the rebuilt C2 leaf (`rat_leaf_localhost_rebuilt.pem`). There are no private keys anywhere in this repository.

## `quicagent_triage.py`

```text
$ python3 -I tools/quicagent_triage.py Windowsupdate.exe
assessment: QUICAgent - agent lineage
go go1.20  module agent  build {'-trimpath': 'true', 'CGO_ENABLED': '1', ...}
cert 0x344600 dad3fa94...  RAT CA (pinned by the `agent` lineage: Dec 2025, Jun/Aug 2026)
markers:
   [x] quic-go client
   [x] common C2 API (/heartbeat /result + idempotency)
   [x] agent uploads (/upload?, /upload/next?)
   [x] agent X-Agent-* headers
   [x] RC4 key built on the stack (agent)
   [x] Worker dead-drop resolver
   [x] Startup SystemIn.lnk
   [x] cgo VEH register + raise (June)
urls (Go string table: a path can run into the next literal):
   https://appupdate.0cmds20cj2cdf8.workers.dev/A3cmf0q9ASCion
   https://regupdate.eamakfu49dc28wa.workers.dev/vere0zme82cadreflect   <- the real path ends at /vere0zme82cad
```

## `vhd_recycle_timeline.py`

```text
$ python3 -I tools/vhd_recycle_timeline.py ACMECS_Pillar_1.vhd
  2026-05-14 01:27:12  $IETCMOD.PDF   v2       265 B  local 2026-05-13 22:27:12  UTC-3.0h  E:\_\5-14-2026.pdf
  2026-05-14 01:37:35  $ISZLWN9.DOC   v2   652,141 B  local 2026-05-13 18:37:35  UTC-7.0h  E:\_\_\j\_\_\_\_\_\_rels\header.doc
  2026-05-14 01:48:50  $IW9D1Q6.PDF   v2    54,759 B  local 2026-05-13 22:48:50  UTC-3.0h  E:\_\5-14-2026.pdf
```

## `lnk_tracker.py`

```text
$ python3 -I tools/lnk_tracker.py ACMECS_Pillar_1.pdf.lnk
volume   {'drive_type': 3, 'serial': 'C205DAF6', 'label_raw': 'ce d2 b5 c4 b4 c5 c5 cc', 'label': '我的磁盘'}
arguments  -s"":_/_/j/_/_/_/_/_/_
tracker  {'machine': 'desktop-stv6gg', ..., 'droid_time_utc': '2024-05-20T06:52:54.203669+00:00', 'droid_mac': '80:45:dd:e5:91:6e'}
```

## `rat_leaf_verify.py`

```text
$ python3 -I tools/rat_leaf_verify.py
TBS match          : True
Signature by embedded RAT CA: VALID
Rebuilt cert sha256: 6b348f7ad068f0324fcf0fff6e91437adb5edd8d2301e44cc0888ef2a8fd43ca
```
