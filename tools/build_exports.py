#!/usr/bin/env python3
"""Build every derived file from the two sources of truth: iocs/iocs.csv and attack/mapping.csv.

Outputs (deterministic - running twice gives byte-identical files):
  iocs/blocklists/*            plain lists for firewalls, proxies, EDR
  iocs/stix/quicsilver.stix2.json
  detections/suricata/quicsilver.rules   (Suricata 7: dns.query, tls.sni, quic.sni, IP rules)
  detections/zeek/quicsilver.intel       (Zeek Intel framework)
  attack/quicsilver-navigator-layer.json (ATT&CK Navigator, coloured by evidence tag)

Usage: python3 tools/build_exports.py
"""
import csv, json, pathlib, uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = "https://github.com/yankywilson/quicsilver-quicagent-cti"
ASOF = "2026-10-15"
NS = uuid.UUID("6d2b9c51-6a39-4d8e-9e5f-6c1f0a7b4d10")  # fixed namespace -> stable STIX ids
TS = f"{ASOF}T00:00:00.000Z"
STATUS = "status_2026_10_15"

def rows():
    return list(csv.DictReader(open(ROOT / "iocs" / "iocs.csv", newline="", encoding="utf-8")))

def write(path, text):
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")
    return p

def blocklists(R):
    out = {}
    def lst(name, items, header):
        body = "".join(f"{i}\n" for i in sorted(set(items)))
        out[name] = write(f"iocs/blocklists/{name}", f"# {header}\n# Operation QUICSILVER / QUICAgent - TLP:CLEAR - {ASOF} - {REPO}\n{body}")
    lst("quicsilver-domains.txt", [r["indicator"] for r in R if r["type"] == "domain" and r["action"] == "block"],
        "Domains safe to block now (actor-only). Time-bound domains are in quicsilver-timebound.csv")
    lst("quicsilver-ipv4.txt", [r["indicator"] for r in R if r["type"] == "ipv4" and r["action"] == "block"],
        "IPv4 safe to block now. Historic C2 IPs are in quicsilver-timebound.csv (several now belong to others)")
    lst("quicsilver-sha256.txt", [r["indicator"] for r in R if r["type"] == "sha256" and r["action"] == "block"],
        "SHA-256 safe to block now: implants, lure containers, LNKs, the ftp script and payload halves")
    lst("quicsilver-sha256-hunt.txt", [r["indicator"] for r in R if r["type"] == "sha256" and r["action"] == "hunt"],
        "SHA-256 to HUNT, not block: decoy documents (real-looking government files), the deleted early payload half, an unconfirmed lead")
    lst("quicsilver-urls.txt", [r["indicator"] for r in R if r["type"] == "url" and r["action"] == "block"],
        "Dead-drop resolver URLs (note the correct /vere0zme82cad path)")
    block256 = {r["indicator"] for r in R if r["type"] == "sha256" and r["action"] == "block"}
    md5 = [r["md5"] for r in csv.DictReader(open(ROOT / "iocs" / "file-hashes.csv", encoding="utf-8")) if r["sha256"] in block256]
    lst("quicsilver-md5.txt", md5, "MD5 of the block-now files in quicsilver-sha256.txt (for tools that only take MD5)")
    tb = [r for r in R if r["action"] == "hunt-historic"]
    lines = ["indicator,type,first_seen,last_seen,why_time_bound"]
    for r in sorted(tb, key=lambda x: x["indicator"]):
        lines.append(f'{r["indicator"]},{r["type"]},{r["first_seen"]},{r["last_seen"]},"{r[STATUS]}"')
    out["quicsilver-timebound.csv"] = write("iocs/blocklists/quicsilver-timebound.csv", "\n".join(lines) + "\n")
    return out

def suricata(R):
    hdr = [
        "# =====================================================================================================",
        f"#  Operation QUICSILVER / QUICAgent - Suricata 7 rules - ANCHOR - TLP:CLEAR - {ASOF}",
        f"#  {REPO}",
        "#  sid range 1913001-1913999 (local). Generated from iocs/iocs.csv by tools/build_exports.py - do not edit.",
        "#  QUICAgent speaks HTTP/3 over QUIC: quic.sni reads the C2 name from the client Initial (Suricata decrypts Initials with keys from the public DCID).",
        "#  Rules tagged 'historic' match infrastructure the actor has since abandoned - use for retro-hunts only.",
        "# =====================================================================================================",
    ]
    sid = 1913000
    meta = f"metadata:created_at {ASOF.replace('-', '_')}, updated_at {ASOF.replace('-', '_')}, tag QUICSILVER, tag QUICAgent, tag TLP_CLEAR;"
    ref = "reference:url,github.com/yankywilson/quicsilver-quicagent-cti; classtype:trojan-activity;"
    out = hdr + ["# --- Section A: DNS, TLS SNI and QUIC SNI ---"]
    for r in [x for x in R if x["type"] == "domain" and x["action"] in ("block", "hunt-historic")]:
        d = r["indicator"]; label = d.replace(".", " .")
        hist = " (historic)" if r["action"] == "hunt-historic" else ""
        for proto, kw, flow in (("dns", "dns.query", ""), ("tls", "tls.sni", "flow:established,to_server; "),
                                ("quic", "quic.sni", "")):
            sid += 1
            src = "$HOME_NET any -> any any" if proto == "dns" else "$HOME_NET any -> $EXTERNAL_NET any"
            out.append(f'alert {proto} {src} (msg:"ANCHOR QUICSILVER {proto.upper()} {label}{hist}"; {flow}{kw}; '
                       f'dotprefix; content:".{d}"; nocase; endswith; {ref} sid:{sid}; rev:1; {meta})')
    out.append("# --- Section B: C2 addresses (QUIC on UDP/443, any TCP) ---")
    for r in [x for x in R if x["type"] == "ipv4" and x["action"] in ("block", "hunt-historic")]:
        ip = r["indicator"]; win = f'{r["first_seen"]}..{r["last_seen"]}'
        hist = f" (historic {win})" if r["action"] == "hunt-historic" else ""
        sid += 1
        out.append(f'alert udp $HOME_NET any -> {ip} 443 (msg:"ANCHOR QUICSILVER QUIC to C2 {ip}{hist}"; '
                   f'threshold:type limit, track by_src, count 1, seconds 3600; {ref} sid:{sid}; rev:1; {meta})')
        sid += 1
        out.append(f'alert tcp $HOME_NET any -> {ip} any (msg:"ANCHOR QUICSILVER TCP to C2 {ip}{hist}"; flow:to_server; '
                   f'threshold:type limit, track by_src, count 1, seconds 3600; {ref} sid:{sid}; rev:1; {meta})')
    return write("detections/suricata/quicsilver.rules", "\n".join(out) + "\n")

def zeek(R):
    out = ["#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice"]
    def add(ind, typ, desc):
        out.append(f"{ind}\t{typ}\tANCHOR-QUICSILVER\t{desc.replace(chr(9), ' ')}\t{REPO}\tT")
    for r in R:
        t, i, role = r["type"], r["indicator"], r["role"]
        if t == "domain": add(i, "Intel::DOMAIN", role)
        elif t == "ipv4": add(i, "Intel::ADDR", f'{role} [{r["first_seen"]}..{r["last_seen"]}]')
        elif t == "sha256": add(i, "Intel::FILE_HASH", role)
        elif t == "url": add(i.split("://", 1)[1], "Intel::URL", role)
        elif t == "email": add(i, "Intel::EMAIL", role)
        elif t == "x509_sha256":
            sha1 = r["notes"].split("SHA-1 ", 1)[1].split(";")[0].split(".")[0].strip() if "SHA-1 " in r["notes"] else ""
            if sha1: add(sha1, "Intel::CERT_HASH", role)
    return write("detections/zeek/quicsilver.intel", "\n".join(out) + "\n")

def sid_(kind, key):
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + key)}"

def stix(R):
    ident = sid_("identity", "ANCHOR")
    camp = sid_("campaign", "Operation QUICSILVER")
    mal = sid_("malware", "QUICAgent")
    objs = [
        {"type": "identity", "spec_version": "2.1", "id": ident, "created": TS, "modified": TS,
         "name": "ANCHOR - Colonel Yanky Wilson", "identity_class": "individual"},
        {"type": "campaign", "spec_version": "2.1", "id": camp, "created": TS, "modified": TS, "created_by_ref": ident,
         "name": "Operation QUICSILVER", "first_seen": "2025-12-22T00:00:00Z", "last_seen": "2026-08-18T00:00:00Z",
         "description": "VHD/LNK/ftp.exe-delivered QUICAgent campaign against Myanmar government and diplomatic targets "
                        "(Seqrite, 2026-08-17). ANCHOR extends the start to December 2025.",
         "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]},
        {"type": "malware", "spec_version": "2.1", "id": mal, "created": TS, "modified": TS, "created_by_ref": ident,
         "name": "QUICAgent", "is_family": True, "malware_types": ["backdoor", "remote-access-trojan"],
         "implementation_languages": ["go"], "architecture_execution_envs": ["x86-64"],
         "description": "Go 1.20 backdoor speaking HTTP/3 over QUIC (quic-go v0.40.1) with a pinned private CA. "
                        "Two code lineages: module 'agent' (Dec 2025, Jun/Aug 2026) and module 'rat/agent' (Apr 2026).",
         "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]},
        {"type": "relationship", "spec_version": "2.1", "id": sid_("relationship", "camp-uses-mal"), "created": TS,
         "modified": TS, "created_by_ref": ident, "relationship_type": "uses", "source_ref": camp, "target_ref": mal},
    ]
    pat = {"sha256": "[file:hashes.'SHA-256' = '{}']", "domain": "[domain-name:value = '{}']",
           "ipv4": "[ipv4-addr:value = '{}']", "url": "[url:value = '{}']", "email": "[email-addr:value = '{}']",
           "x509_sha256": "[x509-certificate:hashes.'SHA-256' = '{}']"}
    for r in R:
        p = pat[r["type"]].format(r["indicator"].replace("\\", "\\\\").replace("'", "\\'"))
        ind = sid_("indicator", r["type"] + "|" + r["indicator"])
        vf = (r["first_seen"] or ASOF) + "T00:00:00Z"
        o = {"type": "indicator", "spec_version": "2.1", "id": ind, "created": TS, "modified": TS,
             "created_by_ref": ident, "name": f'{r["type"]}: {r["indicator"]}', "description": r["role"],
             "indicator_types": ["malicious-activity"] if r["action"] in ("block", "hunt-historic") else ["anomalous-activity"],
             "pattern": p, "pattern_type": "stix", "valid_from": vf,
             "labels": [f'tag:{r["tag"]}', f'confidence:{r["confidence"]}', f'action:{r["action"]}'],
             "object_marking_refs": ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"]}
        if r["action"] == "hunt-historic" and r["last_seen"]:
            o["valid_until"] = r["last_seen"] + "T23:59:59Z"
        objs.append(o)
        objs.append({"type": "relationship", "spec_version": "2.1", "id": sid_("relationship", ind + "->mal"),
                     "created": TS, "modified": TS, "created_by_ref": ident, "relationship_type": "indicates",
                     "source_ref": ind, "target_ref": mal})
    bundle = {"type": "bundle", "id": sid_("bundle", "quicsilver-" + ASOF), "objects": objs}
    return write("iocs/stix/quicsilver.stix2.json", json.dumps(bundle, indent=2, ensure_ascii=False) + "\n")

def navigator():
    colours = {"NOVEL": "#ff4d6d", "CORROBORATED": "#4cc9f0", "PUBLISHED": "#ffb703"}
    techs = []
    for r in csv.DictReader(open(ROOT / "attack" / "mapping.csv", encoding="utf-8")):
        techs.append({"techniqueID": r["technique_id"], "tactic": r["tactic"], "color": colours.get(r["tag"], "#999999"),
                      "comment": f'[{r["tag"]}] {r["procedure"]} | source: {r["source"]}', "enabled": True,
                      "metadata": [{"name": "tag", "value": r["tag"]}, {"name": "detections", "value": r["detections"] or "-"}]})
    layer = {"name": "Operation QUICSILVER / QUICAgent", "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
             "domain": "enterprise-attack",
             "description": f"ANCHOR {ASOF} - coloured by evidence tag. {REPO}",
             "filters": {"platforms": ["Windows"]}, "sorting": 0,
             "layout": {"layout": "side", "showID": True, "showName": True}, "hideDisabled": False,
             "techniques": techs, "gradient": {"colors": ["#ffffff", "#ff4d6d"], "minValue": 0, "maxValue": 1},
             "legendItems": [{"label": "NOVEL - first-hand ANCHOR", "color": colours["NOVEL"]},
                             {"label": "CORROBORATED - published and confirmed", "color": colours["CORROBORATED"]},
                             {"label": "PUBLISHED - vendor claim cited", "color": colours["PUBLISHED"]}],
             "showTacticRowBackground": True, "tacticRowBackground": "#1f2630", "selectTechniquesAcrossTactics": True}
    return write("attack/quicsilver-navigator-layer.json", json.dumps(layer, indent=2) + "\n")

if __name__ == "__main__":
    R = rows()
    made = list(blocklists(R).values()) + [suricata(R), zeek(R), stix(R), navigator()]
    for p in made:
        print("wrote", p.relative_to(ROOT))
