#!/usr/bin/env python3
"""Check that every relative Markdown link (and #anchor in a local .md target) resolves."""
import pathlib, re, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
LINK = re.compile(r"\]\(([^)\s]+)\)")
def anchors(md):
    out = set()
    for line in md.splitlines():
        m = re.match(r"^#{1,6}\s+(.*)", line)
        if m:
            t = re.sub(r"[`*_~]", "", m.group(1)).strip().lower()
            t = re.sub(r"[^\w\- ]", "", t, flags=re.UNICODE).replace(" ", "-")
            out.add(t)
    return out
bad = 0
for md in ROOT.rglob("*.md"):
    if ".git" in md.parts or "node_modules" in md.parts: continue
    for target in LINK.findall(md.read_text(encoding="utf-8")):
        if re.match(r"^[a-z]+://|^mailto:", target): continue
        path, _, frag = target.partition("#")
        dest = (md.parent / path).resolve() if path else md
        if not dest.exists():
            print(f"{md.relative_to(ROOT)}: missing {target}"); bad += 1; continue
        if frag and dest.suffix == ".md" and frag.lower() not in anchors(dest.read_text(encoding="utf-8")):
            print(f"{md.relative_to(ROOT)}: missing anchor #{frag} in {path or md.name}"); bad += 1
print(f"{'all links ok' if not bad else str(bad) + ' broken links'}")
sys.exit(1 if bad else 0)
