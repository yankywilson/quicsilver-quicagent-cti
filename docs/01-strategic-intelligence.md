# 01 · Strategic intelligence

[⬅ README](../README.md) · **Strategic** · [Operational ➡](02-operational-intelligence.md)

> **TLP:CLEAR** · as of **2026-10-15** · ICD-203 estimative language · tags: **NOVEL / CORROBORATED / PUBLISHED / EXCLUDED** ([legend](09-methodology-and-corrections.md#tags-and-the-icd-203-scale))
> Audience: CISOs, intelligence leads and risk owners for Myanmar-facing government, diplomatic, NGO and regional-policy work (ASEAN, BIMSTEC, Mekong cooperation).

---

## Bottom line up front

| | |
|---|---|
| **Who** | The operator behind **Operation QUICSILVER** (Seqrite, 17 Aug 2026) and its Go backdoor **QUICAgent**. Seqrite assesses **China-nexus** (moderate). We hold **China-nexus — likely**, without naming a group. |
| **What** | Espionage against **Myanmar government and diplomatic targets**. The lures impersonate Myanmar's ITCSD/MOTC, the Ministry of Foreign Affairs and regional cooperation programmes (ACMECS, BIMSTEC). |
| **How** | A **VHD** (one copy disguised as `TrainingAnnouncement.jpg`) → a **LNK posing as a PDF that runs `ftp.exe -s:`** → a script that **glues two `.doc` halves into `Windowsupdate.exe`** → **QUICAgent**, which talks **HTTP/3 over QUIC (UDP/443)** to a server whose TLS certificate is **pinned to a private "RAT CA"**. |
| **When** | **December 2025 to at least 18 August 2026.** The earliest published date was April 2026. We push the start back **four months** with a December 2025 build and its live C2. |
| **Now** | Quiet. Around the Seqrite report (between 15 and 18 Aug) the Workers stopped handing out the C2 name (likely), and the name went **NXDOMAIN 1–2 days after** the report. Both Cloudflare Worker resolvers now return an error page. The operator has rebuilt after exposure before, and keeps going back to the same hosting provider. |
| **So what** | Most enterprise proxies **do not see QUIC**. Block or inspect **UDP/443 egress**, stop **VHD auto-mount** for users who don't need it, and hunt the **ftp.exe -s** launch. Everything you need is in [`detections/`](../detections/). |

---

## Key judgments

| # | Judgment | Likelihood | Confidence | Why — and what would change it |
|---|---|---|---|---|
| **KJ1** | Operation QUICSILVER was **running by December 2025**, four months before the earliest published date. | **Almost certain** (95–99%) | High | A QUICAgent build pinning the RAT CA was collected on **22 Dec 2025** — as a **memory image**, so it had already been loaded on some Windows host — and resolved its C2 `www.maui-cocktailbar.com` → **38.60.244.92** on **26 Dec 2025**. The ACMECS lure container was built on **13 Jan 2026** with a payload already inside. **Down**: proof the December sample was a later re-submission with a forged date (sandbox server headers make this very unlikely). |
| **KJ2** | QUICAgent is a **private toolset with two code lineages** (`agent` and `rat/agent`) built in **one developer environment**. | **Very likely** (80–95%) | High | Both lineages carry `C:/Users/qwe/go/pkg/mod` paths, speak an **overlapping** server API (`/heartbeat`, `/result`, `X-Idempotency-Key`; uploads and headers differ), check **overlapping** EDR agents (2 of 3 names), and pin certificates **minted about two hours apart on 5 Dec 2025**. No public source code exists for either (dated null). **Down**: the same code turning up in an unrelated actor's toolkit. |
| **KJ3** | The operator runs **one reusable VHD as a lure factory**, swapping the decoy roughly monthly. | **Likely** (55–80%) | Moderate | The ACMECS VHD's Recycle Bin shows **eight decoy slots** Jan → Jun 2026 (seven deleted PDFs + the current one; four held a real document, and the current ACMECS decoy is a corrupt file) and a payload replaced on 14 May (likely) and again on or after 25 Jun. Seqrite treated the deleted documents as unrelated; their dates say they were the container's earlier decoys. We cannot see which were sent. **Up**: any of them found as a delivered lure. |
| **KJ4** | The operator is **China-nexus**. | **Likely** (55–80%) | Low–moderate | Seqrite's assessment (victimology, lure themes). We add one independent artefact: the builder's system volume is labelled **我的磁盘** ("My disk") in the **GBK** code page — a Simplified-Chinese Windows locale. Locale and labels are trivial to plant. Infrastructure is commercial and shared (no attribution weight, SOP Rule 8). **Not adopted**: any named group. **Up**: code, key or infrastructure overlap with a tracked China-nexus set. |
| **KJ5** | The operator will **reconstitute C2** — new resolvers, new C2 name — with **LightNode (AS154177, Yangon)** VPS. | **Likely** | Moderate–low | 3 of 4 actor-held C2 addresses sit on LightNode Yangon, including the one it **moved to after** using Linode. It rebuilt the implant within weeks of the **GriefLure** exposure (May 2026; hypothesis, see [02](02-operational-intelligence.md#how-the-actor-reacts-to-exposure)). **Down**: no new LightNode QUIC/RAT CA hosts by Jan 2027. |
| **KJ6** | Defences that inspect only TCP/HTTPS will **miss QUICAgent's C2**. | **Very likely** | Moderate | C2 is HTTP/3 over QUIC to a private CA. TLS-inspecting proxies usually pass or ignore UDP/443. Endpoint and DNS telemetry still see it ([07](07-soc-defender-guide.md)). |

---

## Who they are

| Source | Name | Published | Scope |
|---|---|---|---|
| Seqrite Labs | **Operation QUICSILVER**, backdoor **QUICAgent** | 2026-08-17 | TrainingAnnouncement.jpg (VHD), ACMECS_Pillar_1.vhd, HolidayNotice.pdf.exe; Myanmar government; China-nexus (moderate) |
| Seqrite Labs | **Operation GriefLure** | 2026-05 | Same LNK → `ftp.exe -s:` → `header.doc`/`body.doc` chain and the same builder hostname `desktop-stv6gg`; Vietnam military telecom, Philippine healthcare; different payload and C2 |
| ANCHOR (this repo) | — | 2026-10-15 | December 2025 build, two code lineages, C2 certificate on the internet, LightNode pattern, lure-factory timeline, corrected IOCs |

No other vendor has published original research on QUICAgent as of 2026-10-15 (ThreatCluster, 7-day window: **no clusters**; secondary outlets only repeat Seqrite — see [10](10-sources.md)).

---

## What they want

| Target set | Evidence | Tag |
|---|---|---|
| **Myanmar government ICT staff** | Burmese-language ITCSD / MOTC graduation-ceremony invitation (TrainingAnnouncement) | PUBLISHED |
| **Foreign diplomats and NGOs in Myanmar** | "Belgian–Myanmar public holiday calendar" in HolidayNotice.pdf.exe (April) | PUBLISHED · decoy embedded in the binary CORROBORATED |
| **Myanmar MFA / regional diplomacy** | "Inside Story of Trump's Visit to China" (5-14-2026.pdf), BIMSTEC / MISIS concept note, the ACMECS lure (by name — its decoy file is corrupt) | PUBLISHED (content) · NOVEL (they were the container's decoys in sequence, see [06](06-infrastructure.md#the-lure-factory--one-container-eight-decoy-slots)) |
| **South China Sea neighbours** (via the GriefLure sibling) | Vietnam military telecom, Philippine healthcare; a Vietnamese Viettel-themed archive with the same template on **18 Aug 2026** | PUBLISHED · NOVEL (Aug sample) |

This is a Myanmar-policy collection set: the regime's ministries, the diplomats who deal with them, and the regional forums (ASEAN, BIMSTEC, ACMECS) where Myanmar's neighbours coordinate.

---

## How they operate — the strategic picture

| Trait | What it means for defenders |
|---|---|
| **Low-cost, high-trust delivery** | VHD containers dodge Mark-of-the-Web; `ftp.exe` is signed and rarely watched. No exploit is needed. |
| **QUIC for C2** | Moves C2 out of the protocol most security stacks inspect. Pinning to a private CA defeats TLS interception even where QUIC is decrypted. |
| **Dead-drop resolvers on Cloudflare Workers** | The C2 name can change without rebuilding the implant. Blocking one C2 IP buys little. |
| **Aged domains and regional VPS** | A re-registered small-business domain (aged reputation) and Yangon-geolocated servers — C2 traffic that would **look local** to a Myanmar victim (our reading; low confidence on intent). |
| **Fast rebuilds** | Two lineages, a June rebuild with new persistence and resolvers, and a 1-byte "respin" in August to change the hash. Expect new hashes; hunt behaviour. |
| **Sloppy operational security** | Build paths, a Windows user name, cert names that literally say "RAT", a Recycle Bin full of history. These are the handles we hunt with. |

### Threat assessment

| Factor | Rating | Basis |
|---|---|---|
| **Capability** | Moderate | Custom Go implant, QUIC, private PKI, dead-drop resolvers; no exploits, weak OPSEC |
| **Intent** | High | Sustained (≥8 months) collection against one country's government and diplomacy |
| **Opportunity** | High for unmanaged / NGO endpoints; moderate for managed fleets | VHD auto-mount and UDP/443 egress are open by default on Windows |
| **Overall** | **Significant** for Myanmar-facing government, diplomatic and NGO networks; **low** elsewhere | |

---

## Outlook (1–3 months)

| Expect | Likelihood | Watch for |
|---|---|---|
| New C2 name behind **new Workers or another dead-drop service** | Likely | Non-browser process → `*.workers.dev` → UDP/443 ([KQL Q11](../detections/kql/defender-xdr-hunting.kql)) |
| New C2 servers on **LightNode AS154177** with a RAT CA–signed `localhost` certificate | Likely | Certificate hunts in [`hunting/queries`](../hunting/queries/) |
| More **VHD lures** using regional-cooperation themes (ASEAN, BIMSTEC, ACMECS, Mekong) | Likely | [YARA VHD rule](../detections/yara/quicsilver.yar), `ftp.exe -s` |
| A **third code lineage** or a switch away from QUIC | Roughly even chance | Builds with the same C2 paths but no quic-go. The shipped [YARA C2_Protocol](../detections/yara/quicsilver.yar) rule **requires** quic-go — hunt with a copy that drops `$quic`; `RC4_Key_Builder` still fires if the key is kept |

---

## Intelligence gaps

| Gap | Why it matters | How to close it |
|---|---|---|
| **The full early payload** behind the deleted `header.doc` (7,007,744-byte file, Go build ID `_sw2KbxsC…`) | Settles its lineage (likely `agent`, closest to the December build) and what the lure carried from January | VirusTotal retro-hunt; open lead `bf8afbd1…` ([08](08-threat-hunting-playbook.md#-open-leads)) |
| **Which host served the C2 leaf on 15 Jul 2026** | Would tie the certificate to a server and date | Censys history of the leaf hash |
| **Victims** | Scale and success rate are unknown | Regional CERTs; sandbox submitters' metadata |
| **Delivery** | Seqrite infers spear-phishing; nobody has published the e-mail | Mail-gateway hunts for `.vhd` / `.jpg` > 1 MB attachments |
| **A live C2 exchange** | Both RC4 keys are recovered statically, but no one has captured a session to confirm the protocol on the wire | Sinkhole or partner telemetry — out of our passive scope |
