#!/usr/bin/env python3
"""vhd_recycle_timeline.py - rebuild the operator timeline from a lure VHD without mounting it.

Reads a dynamic/fixed VHD, opens its FAT volume, lists every file, and for each Recycle Bin $I record
prints the UTC deletion time (from the $I FILETIME) next to the FAT creation stamp of the $I file
(written in the LOCAL time of whichever machine deleted the file). The difference is that machine's
UTC offset at that moment - clock skew cancels out because both stamps come from the same clock.

Usage:
  python3 -I tools/vhd_recycle_timeline.py lure.vhd [--extract OUTDIR]
  python3 -I tools/vhd_recycle_timeline.py --self-test
Requires: dissect.hypervisor, dissect.volume, dissect.fat (pip install -r tools/requirements.txt)
"""
import datetime as dt, hashlib, os, struct, sys

EPOCH_1601 = dt.datetime(1601, 1, 1)

def parse_i(b):
    """Windows $Recycle.Bin $I record (v1 Vista-8, v2 Windows 10+). Returns (version, size, utc, path)."""
    ver, size, ft = struct.unpack_from("<qqq", b, 0)
    if ver == 2:
        n = struct.unpack_from("<i", b, 24)[0]
        path = b[28:28 + 2 * n].decode("utf-16le").rstrip("\0")
    else:
        path = b[24:24 + 520].decode("utf-16le").split("\0")[0]
    return ver, size, EPOCH_1601 + dt.timedelta(microseconds=ft // 10), path

class Slice:
    def __init__(s, f, off, size): s.f, s.o, s.n, s.p = f, off, size, 0
    def seek(s, p, w=0): s.p = p if w == 0 else (s.p + p if w == 1 else s.n + p); return s.p
    def tell(s): return s.p
    def read(s, n=-1):
        if n < 0: n = s.n - s.p
        s.f.seek(s.o + s.p); b = s.f.read(n); s.p += len(b); return b

def vhd_footer(fh):
    fh.seek(-512, 2); f = fh.read(512)
    if f[:8] != b"conectix": return None
    ts = dt.datetime(2000, 1, 1) + dt.timedelta(seconds=struct.unpack(">I", f[24:28])[0])
    return {"created_utc": ts, "creator_app": f[28:32].decode("latin1"), "creator_host": f[36:40].decode("latin1"),
            "disk_type": {2: "fixed", 3: "dynamic", 4: "differencing"}.get(struct.unpack(">I", f[60:64])[0], "?")}

def walk(path, extract=None):
    from dissect.hypervisor.disk import vhd
    from dissect.volume import disk as vdisk
    from dissect.fat import FATFS
    fh = open(path, "rb")
    foot = vhd_footer(fh)
    v = vhd.VHD(fh); part = vdisk.Disk(v).partitions[0]
    fs = FATFS(Slice(v, part.offset, part.size))
    files, records = [], []
    def rec(d, p):
        for e in d.iterdir():
            if e.name in (".", ".."): continue
            q = p + "/" + e.name
            if e.is_directory():
                rec(e, q); continue
            data = e.open().read()
            files.append((q, len(data), hashlib.sha256(data).hexdigest(), e.ctime, e.mtime))
            if extract:
                os.makedirs(extract, exist_ok=True)
                open(os.path.join(extract, q.strip("/").replace("/", "__")), "wb").write(data)
            if "/$RECYCLE.BIN/" in q.upper() and os.path.basename(q).upper().startswith("$I"):
                ver, size, utc, orig = parse_i(data)
                loc = e.ctime.replace(tzinfo=None) if e.ctime else None
                off = round((loc - utc).total_seconds() / 3600, 2) if loc else None
                records.append((utc, os.path.basename(q), ver, size, orig, loc, off))
    rec(fs.root, "")
    return foot, files, sorted(records)

def main():
    if "--self-test" in sys.argv: return self_test()
    if len(sys.argv) < 2: print(__doc__); return 2
    ext = sys.argv[sys.argv.index("--extract") + 1] if "--extract" in sys.argv else None
    foot, files, recs = walk(sys.argv[1], ext)
    if foot: print(f"VHD footer: created {foot['created_utc']} UTC  creator '{foot['creator_app']}' on '{foot['creator_host']}'  {foot['disk_type']}")
    print(f"\n{len(files)} files")
    for q, n, h, c, m in files: print(f"  {n:>10,}  {h}  {q}")
    print("\nRecycle Bin timeline (UTC deletion time | FAT local stamp | implied UTC offset of the deleting machine)")
    for utc, name, ver, size, orig, loc, off in recs:
        print(f"  {utc:%Y-%m-%d %H:%M:%S}  {name:14} v{ver} {size:>9,} B  local {loc:%Y-%m-%d %H:%M:%S}  UTC{off:+.1f}h  {orig}")
    return 0

def self_test():
    path = "E:\\_\\5-14-2026.pdf"
    ft = int((dt.datetime(2026, 5, 14, 1, 27, 12) - EPOCH_1601).total_seconds() * 10_000_000)
    b = struct.pack("<qqq", 2, 265, ft) + struct.pack("<i", len(path) + 1) + (path + "\0").encode("utf-16le")
    ver, size, utc, p = parse_i(b)
    assert (ver, size, p) == (2, 265, path) and utc == dt.datetime(2026, 5, 14, 1, 27, 12), (ver, size, utc, p)
    print("self-test OK"); return 0

if __name__ == "__main__":
    sys.exit(main())
