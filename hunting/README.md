# 🔭 Hunting data and queries

TLP:CLEAR · 2026-10-15 · Endpoint and network queries live in [`detections/`](../detections/) (KQL Q01–Q12, SPL S01–S12). This folder holds the **passive internet pivots** and the **data tables** behind the timelines.

## 🗃️ `queries/`

| File | What |
|---|---|
| [`internet-scan-pivots.md`](queries/internet-scan-pivots.md) | Censys / Shodan / FOFA / Validin queries that worked, with their results and the one that misleads |

## 🗂️ `data/`

| File | What |
|---|---|
| [`c2_resolution_timeline.csv`](data/c2_resolution_timeline.csv) | Every C2 name → address window with its source |
| [`lure_factory_timeline.csv`](data/lure_factory_timeline.csv) | The VHD container's decoy and payload swaps (Recycle Bin + FAT stamps) |
| [`sandbox_runs.csv`](data/sandbox_runs.csv) | Public sandbox runs used, with QUIC packet counts and resolver state |
