#!/usr/bin/env python3
"""quicagent_triage.py - static triage of a suspected QUICAgent PE (reads bytes only; never executes anything).

Reports:
  * Go build info (version, module path, dependencies, build flags) from the '\\xff Go buildinf:' blob
  * embedded PEM certificates, their SHA-256, and whether they are the known RAT CA / RAT-TeamServer pins
  * lineage markers (agent vs rat/agent), C2 / dead-drop strings, developer paths, main.* function names

Usage:
  python3 -I tools/quicagent_triage.py sample.bin [--json]
  python3 -I tools/quicagent_triage.py --self-test
"""
import base64, hashlib, json, re, sys

KNOWN_CERTS = {
    "dad3fa948af98c55a2029c93999661264c37eb432ef42fdef402326393cfbd0a": "RAT CA (pinned by the `agent` lineage: Dec 2025, Jun/Aug 2026)",
    "2290c2a6576eb32eb0810e9d67f83ceae2e372f32b44c7438828a25de8679988": "RAT-TeamServer (pinned by the `rat/agent` lineage: Apr 2026)",
    "6b348f7ad068f0324fcf0fff6e91437adb5edd8d2301e44cc0888ef2a8fd43ca": "RAT CA-signed C2 leaf CN=localhost (seen by Censys 2026-07-15)",
}
MARKERS = {
    "quic-go client":             [b"github.com/quic-go/quic-go"],
    "common C2 API (/heartbeat /result + idempotency)": [b"/heartbeat", b"/result", b"X-Idempotency-Key"],
    "agent uploads (/upload?, /upload/next?)": [b"%s/upload?%s", b"%s/upload/next?%s"],
    "agent X-Agent-* headers":    [b"X-Agent-Hostname", b"X-Agent-OS", b"X-Agent-Arch", b"X-Agent-User"],
    "rat/agent /register + /upload/chunk/pull + typed results": [b"/register", b"/upload/chunk/pull", b"file_list_result", b"shell_result"],
    "RC4 key built on the stack (agent)":     [b"\x48\xbaMySecret", b"\x48\xbaEncrypti"],
    "RC4 key built on the stack (rat/agent)": [b"\x48\xba2024axce", b"\x48\xbagbaxcegb"],
    "April HTA cleanup (Downloads\\*.hta)":  [b"*.hta", b"Downloads"],
    "Worker dead-drop resolver":  [b".workers.dev/"],
    "Startup SystemIn.lnk":       [b"SystemIn.lnk", b"create_lnk_*.ps1"],
    "launchViaCOM (Shell.Application)": [b"Shell.Application; $shell.ShellExecute"],
    "Dec installer (SystemPublicCache)": [b"SystemPublicCache", b"C:\\Users\\Public\\Downloads"],
    "EDR check: SentinelOne":     [b"entinelagent.exe", b"entinelAgent.exe"],
    "EDR check: Bitdefender":     [b"bdagent.exe"],
    "EDR check: Trend Micro":     [b"ptsessionagent.exe"],
    "tasklist enumeration":       [b"tasklist"],
    "go-ps process list":         [b"github.com/mitchellh/go-ps"],
    "April original_path.txt":    [b"original_path.txt"],
    "self-delete (ping & del)":   [b"ping 127.0.0.1 -n 3 >nul & del /f /q"],
    "cgo VEH register + raise (June)": [b"_Cfunc_register_veh", b"_Cfunc_trigger_veh"],
}
ANY_OF = {"EDR check: SentinelOne"}
PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")
URL_RE = re.compile(rb"https://[a-z0-9][a-z0-9.-]{3,80}\.(?:com|net|org|dev|io|info|xyz|top|site)(?::\d{2,5})?(?:/[A-Za-z0-9_-]{1,40})?")
FUNC_RE = re.compile(rb"main\.(?:\(\*[A-Za-z]+\)\.)?[A-Za-z_][A-Za-z0-9_]{2,40}")
SRC_RE = re.compile(rb"[A-Z]:/[ -~]{1,80}?/main\.go")
MOD_RE = re.compile(rb"[A-Z]:/Users/[^/\x00]{1,40}/go/pkg/mod/")

def uvarint(b, i):
    x = s = 0
    while True:
        c = b[i]; i += 1
        x |= (c & 0x7F) << s
        if c < 0x80: return x, i
        s += 7

def go_buildinfo(data):
    i = data.find(b"\xff Go buildinf:")
    if i < 0: return None
    flags = data[i + 15]
    if not flags & 0x2:
        return {"note": "pre-1.18 pointer-format build info (not parsed)"}
    p = i + 32
    n, p = uvarint(data, p); version = data[p:p + n].decode("utf-8", "replace"); p += n
    n, p = uvarint(data, p); mod = data[p:p + n]
    if len(mod) >= 33 and mod[-17:-16] == b"\n": mod = mod[16:-16]
    info = {"go_version": version, "module": None, "deps": [], "build": {}}
    for line in mod.decode("utf-8", "replace").splitlines():
        f = line.split("\t")
        if f[0] == "path" and len(f) > 1: info["module"] = f[1]
        elif f[0] == "dep" and len(f) > 2: info["deps"].append(f"{f[1]}@{f[2]}")
        elif f[0] == "build" and len(f) > 1 and "=" in f[1]:
            k, v = f[1].split("=", 1); info["build"][k] = v
    return info

def certs(data):
    out = []
    for m in PEM_RE.finditer(data):
        body = b"".join(m.group().split(b"\n")[1:-1])
        try: der = base64.b64decode(body, validate=False)
        except Exception: continue
        h = hashlib.sha256(der).hexdigest()
        subj = None
        try:
            from cryptography import x509
            c = x509.load_der_x509_certificate(der)
            subj = f"{c.subject.rfc4514_string()} | issuer {c.issuer.rfc4514_string()} | {c.not_valid_before_utc:%Y-%m-%d %H:%M:%S} -> {c.not_valid_after_utc:%Y-%m-%d %H:%M:%S}"
        except Exception:
            pass
        out.append({"offset": hex(m.start()), "sha256": h, "subject": subj, "known": KNOWN_CERTS.get(h)})
    return out

def triage(data):
    r = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "is_pe": data[:2] == b"MZ",
         "buildinfo": go_buildinfo(data), "certs": certs(data), "markers": {}}
    for name, needles in MARKERS.items():
        hit = [n.decode("latin1") for n in needles if n in data]
        r["markers"][name] = bool(hit) if name in ANY_OF else (len(hit) == len(needles))
    urls = set()
    for st in re.finditer(rb"https://", data):          # every start, so adjacent strings are not swallowed
        m = URL_RE.match(data, st.start())
        if m and b"golang.org" not in m.group() and b"github.com" not in m.group():
            u = m.group().decode()
            urls.add(u[:-5] if u.endswith("https") else u)
    # Go packs string literals back to back: a path may run into the next string (e.g. '/heartbeatmath')
    r["urls"] = sorted(urls)[:40]
    r["source_paths"] = sorted({s.decode("latin1") for s in SRC_RE.findall(data)})[:20]
    r["module_cache_owner"] = sorted({s.decode("latin1") for s in MOD_RE.findall(data)})
    r["main_functions"] = sorted({f.decode() for f in FUNC_RE.findall(data)})
    mod = (r["buildinfo"] or {}).get("module")
    known = {c["known"] for c in r["certs"] if c["known"]}
    if mod == "rat/agent" or any("TeamServer" in k for k in known):
        r["assessment"] = "QUICAgent - rat/agent lineage"
    elif mod == "agent" and (any("RAT CA" in k for k in known) or r["markers"]["agent X-Agent-* headers"]):
        r["assessment"] = "QUICAgent - agent lineage"
    elif r["markers"]["quic-go client"] and r["markers"]["common C2 API (/heartbeat /result + idempotency)"]:
        r["assessment"] = "QUICAgent-like (protocol markers only)"
    else:
        r["assessment"] = "no QUICAgent markers"
    return r

def show(r):
    print(f"sha256 {r['sha256']}  size {r['size']:,}  PE={r['is_pe']}")
    print(f"assessment: {r['assessment']}")
    b = r["buildinfo"] or {}
    if b:
        print(f"go {b.get('go_version')}  module {b.get('module')}  build {b.get('build')}")
        for d in b.get("deps", []): print(f"   dep {d}")
    for c in r["certs"]: print(f"cert {c['offset']} {c['sha256']}  {c['known'] or ''}\n     {c['subject']}")
    print("markers:"); [print(f"   [{'x' if v else ' '}] {k}") for k, v in r["markers"].items()]
    if r["urls"]:
        print("urls (Go string table: a path can run into the next literal):"); [print(f"   {u}") for u in r["urls"]]
    for k in ("source_paths", "module_cache_owner"):
        if r[k]: print(f"{k}:"); [print(f"   {v}") for v in r[k]]
    print(f"main functions ({len(r['main_functions'])}):"); [print(f"   {f}") for f in r["main_functions"]]

def self_test():
    mod = b"0" * 16 + b"path\tagent\nmod\tagent\t(devel)\t\ndep\tgithub.com/quic-go/quic-go\tv0.40.1\th1:x=\nbuild\tCGO_ENABLED=0\n" + b"1" * 15 + b"\n"
    ver = b"go1.20"
    blob = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16 + bytes([len(ver)]) + ver
    n = len(mod); enc = bytearray()
    while True:
        if n < 0x80: enc.append(n); break
        enc.append((n & 0x7F) | 0x80); n >>= 7
    blob += bytes(enc) + mod
    data = b"MZ" + b"\x00" * 64 + blob + b"github.com/quic-go/quic-go/heartbeat/resultX-Idempotency-Key%s/upload?%s%s/upload/next?%s" \
           + b"X-Agent-HostnameX-Agent-OSX-Agent-ArchX-Agent-User main.(*Agent).sendHeartbeat main.rc4Decrypt" \
           + b"\x48\xbaMySecret\x48\x89\x54\x24\x3a\x48\xbaEncrypti"
    r = triage(data)
    assert r["buildinfo"]["go_version"] == "go1.20", r["buildinfo"]
    assert r["buildinfo"]["module"] == "agent" and r["buildinfo"]["build"]["CGO_ENABLED"] == "0"
    assert r["markers"]["agent X-Agent-* headers"] and r["markers"]["common C2 API (/heartbeat /result + idempotency)"]
    assert r["markers"]["agent uploads (/upload?, /upload/next?)"] and r["markers"]["RC4 key built on the stack (agent)"]
    assert not r["markers"]["rat/agent /register + /upload/chunk/pull + typed results"]
    assert r["assessment"] == "QUICAgent - agent lineage", r["assessment"]
    assert "main.(*Agent).sendHeartbeat" in r["main_functions"]
    print("self-test OK")

if __name__ == "__main__":
    if len(sys.argv) < 2: print(__doc__); sys.exit(2)
    if sys.argv[1] == "--self-test": self_test(); sys.exit(0)
    res = triage(open(sys.argv[1], "rb").read())
    print(json.dumps(res, indent=2)) if "--json" in sys.argv else show(res)
