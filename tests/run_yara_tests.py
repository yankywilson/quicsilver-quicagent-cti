#!/usr/bin/env python3
"""Compile detections/yara/quicsilver.yar and, if given sample folders, check every expected match and
that a negative corpus stays silent. Files are only read - nothing is executed.

  python3 tests/run_yara_tests.py                                  # compile only
  python3 tests/run_yara_tests.py --samples DIR [--negatives DIR]  # full run (expectations: tests/yara_expected.json)
"""
import hashlib, json, os, sys, pathlib
import yara

ROOT = pathlib.Path(__file__).resolve().parents[1]
rules = yara.compile(filepath=str(ROOT / "detections" / "yara" / "quicsilver.yar"))
print("compiled:", len(list(rules)), "rules")
args = sys.argv[1:]
def opt(n): return args[args.index(n) + 1] if n in args else None
samples, negatives = opt("--samples"), opt("--negatives")
if not samples:
    sys.exit(0)
exp = json.load(open(ROOT / "tests" / "yara_expected.json"))
seen, bad = {}, 0
for dp, _, fs in os.walk(samples):
    for f in fs:
        p = os.path.join(dp, f)
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        if h in exp and h not in seen:
            got = sorted(m.rule for m in rules.match(p))
            seen[h] = got
            ok = got == sorted(exp[h])
            bad += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {h[:12]}  {', '.join(got) or '(no match - expected)' if ok else got}")
missing = [h for h in exp if h not in seen]
for h in missing: print(f"skip {h[:12]}  (sample not in {samples})")
if negatives:
    n = fp = 0
    for dp, _, fs in os.walk(negatives):
        for f in fs:
            p = os.path.join(dp, f)
            if os.path.islink(p) or not os.path.isfile(p): continue
            n += 1
            try:
                m = rules.match(p, timeout=30)
            except yara.Error:
                continue
            if m: fp += 1; print(f"FP   {p} {[x.rule for x in m]}")
    print(f"negatives: {n} files, {fp} matches"); bad += fp
sys.exit(1 if bad else 0)
