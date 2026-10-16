# 🗺 MITRE ATT&CK mapping

TLP:CLEAR · 2026-10-15 · 33 technique entries in [`mapping.csv`](mapping.csv), each with the procedure, the evidence tag, the source and the detections that cover it.

## Open the layer

1. Go to the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).
2. **Open Existing Layer → Upload from local** → [`quicsilver-navigator-layer.json`](quicsilver-navigator-layer.json).
3. Colours: **red** NOVEL · **blue** CORROBORATED · **amber** PUBLISHED. Hover a cell for the procedure and the rule names.

The layer is generated from `mapping.csv` by [`tools/build_exports.py`](../tools/build_exports.py); `tests/run_all.sh` checks they agree.

## Notes on the mapping

| Choice | Why |
|---|---|
| `ftp.exe -s:` mapped to **T1202 Indirect Command Execution** | `ftp.exe` runs the script's `!` lines through the shell — indirect execution, not a proxy-execution technique under T1218 |
| VHD delivery mapped to **T1553.005 Mark-of-the-Web Bypass** | Files inside a mounted VHD do not carry the container's MOTW |
| EDR checks mapped to **T1518.001** and **T1057** | December uses `tasklist`, April uses `go-ps`. December skips its install for Bitdefender or SentinelOne; April skips it for SentinelOne or Trend Micro, and only changes the relaunch for Bitdefender |
| VEH register-and-raise folded into **T1497.003** | Its purpose is inferred (likely anti-debug), not proven, so it gets no technique of its own |
| RC4 mapped to **T1573.001** as CORROBORATED | Seqrite's `agent` key confirmed in the code; the April key is new |
| T1566.001 kept as **PUBLISHED** | Nobody has published the delivery e-mail |
