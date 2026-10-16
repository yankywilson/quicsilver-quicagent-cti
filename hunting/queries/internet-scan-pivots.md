# Internet-scan pivots (passive)

[⬅ Hunting](../README.md) · TLP:CLEAR · 2026-10-15

These run against **scan-engine archives**. They never touch the hosts. The result column says whether a query was run during the investigation and what it returned; rows marked *open* were prepared but not yet run.

## Certificates

| Engine | Query | Result (2026-10-14/15) | Notes |
|---|---|---|---|
| Censys Platform — certificate search | `cert.parsed.issuer.common_name: "RAT CA"` | **1** certificate: `C=US, O=RAT System, CN=localhost`, serial 2, first seen 2026-07-15 09:16 UTC (SHA-256 `6b348f7ad068f0324fcf0fff6e91437adb5edd8d2301e44cc0888ef2a8fd43ca` after rebuild) | Rebuild and verify with `tools/rat_leaf_verify.py` |
| Shodan | `ssl.cert.issuer.cn:"RAT CA"` | *open* | Use this, **not** `ssl:"RAT System"` |
| Shodan | `ssl.cert.subject.cn:"RAT-TeamServer"` | *open* | April lineage |
| FOFA | `cert="RAT-TeamServer"` | *open* | April lineage |
| Censys | RAT-TeamServer SHA-256 `2290c2a6576eb32eb0810e9d67f83ceae2e372f32b44c7438828a25de8679988` | **null** (2026-10-14) | Not seen by Censys |

## Hosts

| Engine | Query | Why |
|---|---|---|
| FOFA | `ip="38.60.244.92"` | December C2 history |
| FOFA | `ip="130.94.100.181"` | August C2 history |
| Censys host history | `https://platform.censys.io/hosts/38.60.244.92` | Look for UDP/443 or a RAT CA leaf between 2025-12 and 2026-02 |
| Validin | `38.60.244.92` · `130.94.100.181` · `mediumser.com` | Other names on the same servers; new `mediumser.com` subdomains |

## Excluded pivot

| Query | Why not |
|---|---|
| Shodan `ssl:"RAT System"` | Matches `rat-system.ddns.net` (3.22.233.21) by hostname — unrelated (see `iocs/excluded.csv`) |
