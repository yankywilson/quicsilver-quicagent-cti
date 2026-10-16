# 04 · Attribution assessment

[⬅ Tactical](03-tactical-intelligence.md) · **Attribution** · [Reverse engineering ➡](05-reverse-engineering.md)

> **TLP:CLEAR** · as of **2026-10-15** · ICD-203 · SOP Rule 4 (vendor labels are claims) and Rule 8 (no attribution on shared tooling or infrastructure) apply throughout.

---

## Holding

| Question | Holding | Likelihood | Confidence |
|---|---|---|---|
| Is QUICSILVER the work of a **China-nexus** actor? | **Yes, held** | **Likely** (55–80%) | Low–moderate |
| Is it a **named, tracked** group (APT x / Typhoon y)? | **Not adopted** | — | — |
| Are **QUICSILVER and GriefLure** the same operator? | **Yes, held** | **Very likely** (80–95%) | Moderate |
| Is QUICAgent **shared or commercial** tooling? | **No public trace** | Unlikely (20–45%) | Moderate |

We corroborate Seqrite's China-nexus call with one independent artefact and add no group name. The evidence is thin enough that a single strong counter-indicator would move it.

---

## 1 · Why China-nexus (KJ4)

| # | Evidence | Weight | Tag | Plantable? |
|---|---|---|---|---|
| E1 | **Targeting**: Myanmar ministries, MFA material, BIMSTEC / ASEAN / ACMECS themes, foreign missions in Myanmar | Moderate | PUBLISHED (Seqrite) · CORROBORATED (decoys in hand) | n/a |
| E2 | **Builder locale**: the LNK records the builder's system volume label `我的磁盘` encoded in **GBK (code page 936)** — only possible if that machine's ANSI code page is Simplified Chinese | Moderate (for a Chinese-language environment) · Low (for state attribution) | **NOVEL** | Yes — a VM locale is a setting |
| E3 | **Sibling operation** GriefLure (same builder host `desktop-stv6gg`): Vietnamese military telecom, Philippine healthcare — South China Sea neighbours | Low–moderate | PUBLISHED (Seqrite) | n/a |
| E4 | **Infrastructure**: LightNode (commercial VPS provider) servers in Yangon; Cloudflare Workers; Namecheap / NameSilo | **None** (Rule 8: commercial, shared) | NOVEL (pattern) | — |
| E5 | **Clocks**: UTC−8/−7 (DST-aware) and UTC−3 — **neither is UTC+8**. UTC−8 Pacific is the default time zone of a fresh en-US Windows install, so it most likely marks an unconfigured VM | **None** | NOVEL | Yes |
| E6 | **Tool names** "RAT CA", "RAT System", "RAT-TeamServer", module `rat/agent`, user `qwe` | None for nationality; points to an in-house or freelance developer | NOVEL | Yes |
| E7 | **No public source code** for QUICAgent, RAT CA, RAT-TeamServer or `rat/agent` (code search, GitHub, web) | Supports "private toolset", not nationality | NOVEL (dated null 2026-10-14) | — |

**Read-out**: E1 and E2 point the same way and are independent of each other. E3 adds a little. Everything else is neutral. That supports **likely**, not **very likely**.

---

## 2 · QUICSILVER ↔ GriefLure — same operator

| Link | Detail | Tag |
|---|---|---|
| Builder host | `desktop-stv6gg` in LNK tracker blocks of both | PUBLISHED (Seqrite) · CORROBORATED (our ACMECS LNK) |
| Template | LNK → `ftp.exe -s:` → `_` script → `_/_/j/_rels/header.doc` + `body.doc` → `copy /b` | PUBLISHED · CORROBORATED |
| Template still alive | Vietnamese, Viettel-themed RAR on Triage **18 Aug 2026** with `_/_/j/_rels/`, a 48-byte `header.doc`, chunk files `0.doc`–`9.doc` and `_/_/j/doc/1.pdf` | **NOVEL** |
| Different payload and C2 | GriefLure's in-memory loader and `whatsappcenter.com` vs QUICAgent and `mediumser.com` | PUBLISHED |

A shared builder machine plus a shared, unusual template makes one operator **very likely**. Open test: compare the 18 Aug LNK's tracker block (MAC, DROID, volume label) with ours ([08](08-threat-hunting-playbook.md#-open-leads)).

---

## 3 · Analysis of competing hypotheses

| Evidence | H1 China-nexus state espionage | H2 Another regional state service | H3 Contractor / RAT developer for hire | H4 False flag |
|---|---|---|---|---|
| E1 Myanmar policy targeting | ✔ consistent | ✔ consistent | ~ (depends on client) | ~ |
| E2 GBK builder locale | ✔ | ✘ unless planted | ✔ (if Chinese-speaking contractor) | ✔ (planted) |
| E3 Vietnam / Philippines sibling | ✔ | ~ | ✔ | ~ |
| E6 Generic "RAT" naming, single dev user | ~ | ~ | ✔ strongly | ~ |
| E7 Private code, two parallel lineages | ✔ | ✔ | ✔ | ~ |
| Weak OPSEC (Recycle Bin, paths, cert names) | ~ | ~ | ✔ | ✘ (a false flag would be tidier) |
| **Inconsistent items** | 0 | 1 | 0 | 1 |

H1 and H3 both survive, and they are **not exclusive**: a Chinese-speaking contractor building tools for a China-nexus tasking fits everything. We therefore hold the **nexus**, not an organisation.

---

## Excluded hypotheses and claims

| Claim | Why excluded | Tag |
|---|---|---|
| Family labels in sample names (Cobalt Strike, Sliver, Quasar RAT, FrostyGoop, GlassWorm, Luca Stealer, PoetRAT, Snatch, Dosia, coinminer) | Bulk-feed tags on `2655c016` and `cd147efe`; mutually incompatible. Both samples are QUICAgent. Rule 4 | EXCLUDED |
| `rat-system.ddns.net` / 3.22.233.21 as QUICAgent infrastructure | Shodan `ssl:"RAT System"` matched the hostname, not the certificate | EXCLUDED |
| Post-June 2026 `maui-cocktailbar.com` owners | Parking, aftermarket lander, and an unrelated 2026-09-29 registrant | EXCLUDED |

---

## What would change our mind

| Observation | Effect |
|---|---|
| QUICAgent code, the RAT CA key, or a QUICAgent C2 shared with a **tracked** China-nexus set | KJ4 → very likely; a group name becomes possible |
| A second, independent locale artefact (e.g., Chinese-language strings or PDB paths) | KJ4 → likely, higher confidence |
| The same builder artefacts in a **non-Asian** operation | KJ4 down to roughly even chance; H3 up |
| Evidence the GBK label was planted (e.g., label changes between LNKs made on one machine) | E2 drops out → roughly even chance |
