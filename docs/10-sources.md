# 10 · Sources

[⬅ Methodology](09-methodology-and-corrections.md) · **Sources** · [README ➡](../README.md)

> **TLP:CLEAR** · as of **2026-10-15** · every external source used, grouped by kind. Social-media sources are excluded by policy.

---

## 📰 Primary reporting on the operation

| Source | Date | Used for |
|---|---|---|
| Seqrite Labs — [Operation QUICSILVER: China-Nexus Actor Targets Myanmar Diplomats via VHD-Delivered Go Backdoor](https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/) | 2026-08-17 (updated 2026-09-29) | Every PUBLISHED tag; IOC baseline |
| Seqrite Labs — [Operation GriefLure: Dissecting an APT Campaign Targeting Vietnam's Military Telecom & Philippine Healthcare](https://www.seqrite.com/blog/operation-grieflure-dissecting-an-apt-campaign-targeting-vietnams-military-telecom-philippine-healthcare/) | 2026-05 | Sibling template and builder host |

## 🧾 Secondary summaries (cited only for the typo's spread)

| Source | Note |
|---|---|
| [SOCRadar IOC Radar — Operation QUICSILVER](https://socradar.io/free-tools/ioc-radar/reports/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor-5dc9b4b1f27b) | Repeats `/vere0zme82cadre` |
| [HivePro — Operation QUICSILVER Drops a Go Backdoor on Myanmar Government](https://www.hivepro.com/threat-advisory/operation-quicsilver-drops-a-go-backdoor-on-myanmar-government) | Repeats `/vere0zme82cadre` |
| [Cyber Security News — China-Nexus Hackers Disguise Malicious VHD as JPEG](https://cybersecuritynews.com/china-nexus-hackers/) | Repeats `/vere0zme82cadre` |

## 🧪 Sandbox records

| Record | Specimen |
|---|---|
| [Triage 251222-kah8asynej](https://tria.ge/251222-kah8asynej) ([Win10](https://tria.ge/251222-kah8asynej/behavioral1), [Win11](https://tria.ge/251222-kah8asynej/behavioral2), [static](https://tria.ge/251222-kah8asynej/static1)) | December build `2655c016` |
| [Triage 260415-d3xg3ad14q](https://tria.ge/260415-d3xg3ad14q) ([behavioural](https://tria.ge/260415-d3xg3ad14q/behavioral1)) | April build `c4b46477` |
| [Triage 260814-zaebnshl2y](https://tria.ge/260814-zaebnshl2y) ([behavioural](https://tria.ge/260814-zaebnshl2y/behavioral1), [static](https://tria.ge/260814-zaebnshl2y/static1)) · resubmission [260815-yx3r4stvdy](https://tria.ge/260815-yx3r4stvdy) | August respin `c15aead1` |
| [Triage 260818-sw2wjadk7v](https://tria.ge/260818-sw2wjadk7v) ([LNK run, behavioral31](https://tria.ge/260818-sw2wjadk7v/behavioral31)) | ACMECS_Pillar_1.vhd — full ftp.exe → copy → start → PowerShell chain; Workers fetched, no C2 lookup (18 Aug 15:29 UTC) |
| [Triage 260918-gy8w3sbl7v](https://tria.ge/260918-gy8w3sbl7v) | June build, Workers only |
| [Triage 260818-m7n6xsssdx](https://tria.ge/260818-m7n6xsssdx) | GriefLure-template RAR (Viettel theme) |
| [Joe Sandbox analysis 1987362](https://www.joesandbox.com/analysis/1987362) | June build, Workers → `error code: 1042`, memory strings |

## 🌐 Infrastructure data

| Source | Used for |
|---|---|
| [ipinfo — 38.60.244.92](https://ipinfo.io/38.60.244.92) · [38.60.244.141](https://ipinfo.io/38.60.244.141) · [130.94.100.181](https://ipinfo.io/130.94.100.181) | ASN AS154177 LIGHT NODE LIMITED, Yangon |
| [OTX passive DNS API — 38.60.244.92](https://otx.alienvault.com/api/v1/indicators/IPv4/38.60.244.92/passive_dns) | Dated null |
| [ThreatFox — whatsappcenter.com](https://threatfox.abuse.ch/ioc/1808238/) | GriefLure C2 |
| [Censys Platform — host 38.60.244.92](https://platform.censys.io/hosts/38.60.244.92) | Pivot target |
| [SANS Internet Storm Center](https://isc.sans.edu/) — new-domain feed | 2025-06-08 listing of `maui-cocktailbar.com` |
| Validin, SecurityTrails, VirusTotal (WHOIS history, resolutions, graph), Censys certificate search, Shodan, FOFA, crt.sh, reverse WHOIS | Analyst console exports and lookups (not linkable) |

## 🪟 Vendor and platform documentation

| Source | Used for |
|---|---|
| [Microsoft Learn — DeviceNetworkEvents](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table) | `Protocol` column for QUIC hunts |
| [Microsoft Learn — Advanced hunting schema](https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables) | KQL validator schema |
| [Microsoft Learn — Advanced hunting quotas and usage parameters](https://learn.microsoft.com/defender-xdr/advanced-hunting-overview#quotas-and-usage-parameters) · [Data retention](https://learn.microsoft.com/defender-xdr/data-privacy#data-retention) | 30-day native look-back; longer only via Sentinel retention |
| [quic-go](https://github.com/quic-go/quic-go) | Library version and Initial packet size |
| [file.net — PtSessionAgent.exe](https://www.file.net/process/ptsessionagent.exe.html) · [Netskope — Trend Micro Maximum Security processes](https://docs.netskope.com/fr/en/trend-micro-maximum-security) | `ptsessionagent.exe` = Trend Micro |

## 🗄️ Standards

| Source | Used for |
|---|---|
| [MITRE ATT&CK](https://attack.mitre.org/) | Technique mapping (v19) |
| ICD 203 — Analytic Standards (ODNI) | Estimative language and confidence |
| [STIX 2.1 (OASIS)](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) | IOC bundle |
| [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001) | Initial keys derive from the public Destination Connection ID (why sensors can read the SNI) |

## 🚫 Excluded sources

| Source | Why |
|---|---|
| Social-media posts (including a researcher thread on GriefLure-like LNKs found in search) | Policy: no social-media sources |
| Bulk sample-feed family tags | SOP Rule 4 ([`excluded.csv`](../iocs/excluded.csv)) |
