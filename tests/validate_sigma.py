#!/usr/bin/env python3
"""Validate every Sigma rule offline: parse, run pySigma's structural validators, convert to KQL and SPL.

Network-dependent validators (MITRE ATT&CK / D3FEND tag lists) are skipped so this runs air-gapped;
tags are checked against a local technique-ID regex instead.
Usage: python3 tests/validate_sigma.py [--show]
"""
import re, sys, pathlib
from sigma.collection import SigmaCollection
from sigma.validators.core import validators as core_validators

ROOT = pathlib.Path(__file__).resolve().parents[1] / "detections" / "sigma"
SKIP = {"attacktag", "d3fendtag", "invalidattacktags", "invalidd3fendtags", "attacktagvalidator", "d3fendtagvalidator"}
TAG_RE = re.compile(r"^attack\.(t\d{4}(\.\d{3})?|[a-z]+(-[a-z]+)*)$")

def backends():
    out = []
    try:
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
        out.append(("KQL (Defender XDR)", KustoBackend(processing_pipeline=microsoft_xdr_pipeline())))
    except Exception as e:  # backend not installed
        print(f"  [skip] kusto backend: {e}")
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.splunk import splunk_windows_pipeline
        out.append(("SPL (Splunk)", SplunkBackend(processing_pipeline=splunk_windows_pipeline())))
    except Exception as e:
        print(f"  [skip] splunk backend: {e}")
    return out

def main():
    show = "--show" in sys.argv
    vals = [v() for k, v in core_validators.items() if k.lower() not in SKIP and "tag" not in k.lower()]
    bks = backends()
    failed = 0
    files = sorted(ROOT.glob("*.yml"))
    for f in files:
        try:
            col = SigmaCollection.from_yaml(f.read_text())
            rule = col.rules[0]
            issues = [i for v in vals for i in v.validate(rule)]
            bad_tags = [str(t) for t in rule.tags if not TAG_RE.match(f"{t.namespace}.{t.name}")]
            conv = {}
            for name, b in bks:
                # fresh parse per backend: processing pipelines mutate the rule objects in place
                try:
                    conv[name] = b.convert(SigmaCollection.from_yaml(f.read_text()))
                except Exception as e:
                    if "KQL" in name and rule.logsource.category == "dns_query":
                        conv[name] = ["n/a - Defender XDR pipeline has no dns_query table; see KQL Q08 in detections/kql"]
                    else:
                        raise
            status = "OK" if not issues and not bad_tags else "WARN"
            print(f"{status:4} {f.name}")
            for i in issues: print(f"      issue: {i}")
            for t in bad_tags: print(f"      bad tag: {t}")
            if show:
                for n, q in conv.items(): print(f"      {n}: {q[0]}")
        except Exception as e:
            failed += 1
            print(f"FAIL {f.name}: {type(e).__name__}: {e}")
    print(f"\n{len(files)} rules, {failed} failed to parse/convert, backends: {', '.join(n for n, _ in bks) or 'none'}")
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())
