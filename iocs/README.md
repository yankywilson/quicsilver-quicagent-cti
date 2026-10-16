# 🎯 Indicators

TLP:CLEAR · 2026-10-15 · One source of truth: [`iocs.csv`](iocs.csv). Everything in [`blocklists/`](blocklists/), [`stix/`](stix/), [`../detections/suricata/`](../detections/suricata/) and [`../detections/zeek/`](../detections/zeek/) is generated from it by [`tools/build_exports.py`](../tools/build_exports.py).

## 📁 Files

| File | What |
|---|---|
| [`iocs.csv`](iocs.csv) | Every indicator with role, evidence tag, confidence, date window, status today and recommended action |
| [`file-hashes.csv`](file-hashes.csv) | SHA-256 / SHA-1 / MD5 / size of every file analysed (implants, LNK, script, payload halves, decoys) |
| [`excluded.csv`](excluded.csv) | Look-alikes and traps: parking, aftermarket, prior owner, bystander, a hostname collision, a mis-transcribed URL, feed labels |
| [`related-grieflure.csv`](related-grieflure.csv) | The sibling template (Seqrite's GriefLure) and an 18 Aug 2026 sample using it |
| [`stix/quicsilver.stix2.json`](stix/quicsilver.stix2.json) | STIX 2.1 bundle: campaign, malware, indicators with `valid_from` / `valid_until`, relationships |

### Block lists

| File | Safe to block now? |
|---|---|
| `quicsilver-domains.txt` | **Yes** — actor-only names (Workers, `mediumser.com`) |
| `quicsilver-ipv4.txt` | **Yes** — currently only 130.94.100.181 |
| `quicsilver-urls.txt` | **Yes** — resolver URLs (correct path) |
| `quicsilver-sha256.txt` / `quicsilver-md5.txt` | **Yes** — implants, lure containers, LNKs, the ftp script, payload halves |
| `quicsilver-sha256-hunt.txt` | **No** — hunt only: decoy documents (real-looking government files), the deleted early payload half, the unconfirmed `bf8afbd1…` lead |
| `quicsilver-timebound.csv` | **No** — retro-hunt only. These now belong to other people |

## 🧾 Columns — `iocs.csv`

| Column | Meaning |
|---|---|
| `indicator`, `type` | Value and kind (`sha256`, `domain`, `ipv4`, `url`, `email`, `x509_sha256`) |
| `role` | What it is in the operation |
| `tag` | NOVEL / CORROBORATED / PUBLISHED ([legend](../docs/09-methodology-and-corrections.md#tags-and-the-icd-203-scale)) |
| `confidence` | ICD-203 likelihood that the role is right |
| `first_seen`, `last_seen` | Actor-held window (UTC dates; month-level where noted) |
| `status_2026_10_15` | State on the release date |
| `action` | `block` · `hunt` · `hunt-historic` (time-bound) · `pivot` |
| `source`, `notes` | Where it came from; caveats |

## 🧾 Columns — `excluded.csv`

`indicator, type, tag, why_excluded, date_checked, source, what_to_do_instead`

## 🧾 Columns — `file-hashes.csv`

`file, role, verdict, sha256, sha1, md5, size`

## ⚠️ Handling

- **Respect the date windows.** `www.maui-cocktailbar.com` belongs to an unrelated party since 2026-09-29; `104.64.211.22` hosts someone else's workload.
- **Do not contact** the registrant e-mail; use it only as a WHOIS pivot.
- **Do not upload** the decoys to public services — they are realistic government documents.
