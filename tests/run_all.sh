#!/usr/bin/env bash
# ======================================================================================
# Offline validation of everything in this repository (no network, no malware needed).
#   bash tests/run_all.sh [path/to/node_modules]
# Optional: QUICSILVER_SAMPLES=<dir> (and QUICSILVER_NEGATIVES=<dir>) re-runs the full YARA
# expectation test against your own copies of the samples - files are only read, never run.
# ======================================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
NODE_MODULES="${1:-node_modules}"
pass=0; fail=0
step() { printf '\n\033[1;36m== %s\033[0m\n' "$1"; }
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '\033[1;31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

step "Tool self-tests (synthetic vectors / bundled public certificates)"
for t in quicagent_triage lnk_tracker vhd_recycle_timeline rat_leaf_verify; do
  if python3 -I "tools/$t.py" --self-test >/dev/null; then ok "$t"; else bad "$t"; fi
done

step "YARA"
if python3 tests/run_yara_tests.py ${QUICSILVER_SAMPLES:+--samples "$QUICSILVER_SAMPLES"} ${QUICSILVER_NEGATIVES:+--negatives "$QUICSILVER_NEGATIVES"}; then ok "yara"; else bad "yara"; fi

step "Sigma (pySigma validators + conversion to KQL and SPL)"
if python3 tests/validate_sigma.py >/dev/null; then ok "sigma"; else bad "sigma"; fi

step "KQL (Kusto.Language parser + Defender XDR schema)"
if [[ -d "$NODE_MODULES/@kusto/language-service-next" ]]; then
  if node tests/validate_kql.js detections/kql/defender-xdr-hunting.kql "$NODE_MODULES"; then ok "kql"; else bad "kql"; fi
else
  echo "skip: npm install @kusto/language-service-next@12.4.1"
fi

step "Exports are reproducible (build twice, compare)"
python3 tools/build_exports.py >/dev/null
sums1=$(sha256sum iocs/stix/*.json iocs/blocklists/* detections/suricata/*.rules detections/zeek/*.intel attack/*.json | sha256sum)
python3 tools/build_exports.py >/dev/null
sums2=$(sha256sum iocs/stix/*.json iocs/blocklists/* detections/suricata/*.rules detections/zeek/*.intel attack/*.json | sha256sum)
if [[ "$sums1" == "$sums2" ]]; then ok "deterministic exports"; else bad "exports differ between runs"; fi

step "Suricata"
if command -v suricata >/dev/null; then
  tmp=$(mktemp -d)
  if suricata -T -S detections/suricata/quicsilver.rules -l "$tmp" >/dev/null 2>&1; then ok "suricata -T loads all rules"; else bad "suricata -T"; fi
  rm -rf "$tmp"
fi
if python3 -c "
from suricataparser import parse_file
r = parse_file('detections/suricata/quicsilver.rules'); s = [x.sid for x in r]
assert r and len(set(s)) == len(s), 'duplicate sid'
print(len(r), 'rules parsed, sids unique')"; then ok "suricata parse"; else bad "suricata parse"; fi

step "Zeek intel (tab-separated, 6 fields per row)"
if awk -F'\t' 'NR>1 && NF!=6 {print "bad line " NR; bad=1} END {exit bad}' detections/zeek/quicsilver.intel; then ok "zeek intel"; else bad "zeek intel"; fi

step "STIX 2.1 (strict parse, patterns, referential integrity)"
if python3 - <<'PY'
import stix2
from stix2patterns.validator import run_validator
b = stix2.parse(open("iocs/stix/quicsilver.stix2.json").read(), allow_custom=False)
ids = {o.id for o in b.objects}
for o in b.objects:
    if o.type == "indicator": assert not run_validator(o.pattern), o.pattern
    if o.type == "relationship": assert o.source_ref in ids and o.target_ref in ids
print(len(b.objects), "objects ok")
PY
then ok "stix"; else bad "stix"; fi

step "ATT&CK layer and mapping agree"
if python3 - <<'PY'
import csv, json
m = {(r["technique_id"], r["tactic"]) for r in csv.DictReader(open("attack/mapping.csv"))}
l = {(t["techniqueID"], t["tactic"]) for t in json.load(open("attack/quicsilver-navigator-layer.json"))["techniques"]}
assert m == l, m ^ l
print(len(m), "technique/tactic pairs")
PY
then ok "attack"; else bad "attack"; fi

step "Markdown links resolve"
if python3 tests/check_links.py; then ok "links"; else bad "links"; fi

step "Handling sweep (no payload files, no private keys)"
if ! git ls-files 2>/dev/null | grep -Ei '\.(exe|dll|vhdx?|lnk|zip|rar|7z|bin|doc)$' && ! grep -rIl "PRIVATE KEY" --exclude-dir=.git --exclude=run_all.sh . ; then ok "no payloads or keys"; else bad "payload or key material found"; fi

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
