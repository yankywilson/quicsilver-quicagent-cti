#!/usr/bin/env python3
"""lnk_tracker.py - pull builder-machine artefacts out of a Windows shortcut (.lnk). Reads bytes only.

  * TrackerDataBlock (0xA0000003): NetBIOS machine name and DROID GUIDs. A version-1 GUID carries the
    creation time and the MAC address of the machine that created the tracked file.
  * LinkInfo VolumeID: drive serial number and volume label. The label is stored in the system ANSI
    code page - decode it as GBK (cp936), Big5, Shift-JIS, etc. to learn the builder's locale.
  * Target, arguments and icon location (StringData + EnvironmentVariableDataBlock).

Usage:
  python3 -I tools/lnk_tracker.py file.lnk [--codepage cp936]
  python3 -I tools/lnk_tracker.py --self-test
"""
import datetime as dt, struct, sys, uuid

def droid(u: uuid.UUID):
    if u.version != 1: return None
    t = dt.datetime(1582, 10, 15, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=u.time // 10)
    mac = ":".join(f"{(u.node >> s) & 0xff:02x}" for s in range(40, -1, -8))
    return t, mac, bool(u.node & 0x010000000000)  # multicast bit set = random node, not a real MAC

def parse(b, codepage="cp936"):
    out = {}
    assert struct.unpack_from("<I", b, 0)[0] == 0x4C, "not a shell link"
    flags = struct.unpack_from("<I", b, 0x14)[0]
    off = 0x4C
    if flags & 0x1: off += 2 + struct.unpack_from("<H", b, off)[0]          # IDList
    if flags & 0x2:                                                           # LinkInfo
        li = off; li_size = struct.unpack_from("<I", b, li)[0]
        vid_off = struct.unpack_from("<I", b, li + 0x0C)[0]
        if struct.unpack_from("<I", b, li + 0x08)[0] & 1 and vid_off:
            v = li + vid_off
            dtype, serial, lab_off = struct.unpack_from("<III", b, v + 4)
            raw = b[v + lab_off: b.index(b"\0", v + lab_off)]
            out["volume"] = {"drive_type": dtype, "serial": f"{serial:08X}", "label_raw": raw.hex(" "),
                             "label": raw.decode(codepage, "replace")}
        off = li + li_size
    unicode = bool(flags & 0x80)
    for bit, name in ((0x4, "name"), (0x8, "relative_path"), (0x10, "working_dir"), (0x20, "arguments"), (0x40, "icon")):
        if flags & bit:
            n = struct.unpack_from("<H", b, off)[0]; off += 2
            s = b[off: off + (2 * n if unicode else n)]; off += 2 * n if unicode else n
            out[name] = s.decode("utf-16le" if unicode else "latin1")
    while off + 8 <= len(b):                                                  # ExtraData blocks
        size, sig = struct.unpack_from("<II", b, off)
        if size < 8: break
        if sig == 0xA0000003:
            machine = b[off + 16: off + 32].split(b"\0")[0].decode("latin1")
            g = [uuid.UUID(bytes_le=b[off + 32 + 16 * i: off + 48 + 16 * i]) for i in range(4)]
            d = droid(g[1])
            out["tracker"] = {"machine": machine, "droid_volume": str(g[0]).upper(), "droid_file": str(g[1]).upper(),
                              "birth_droid_file": str(g[3]).upper()}
            if d: out["tracker"].update(droid_time_utc=d[0].isoformat(), droid_mac=d[1], random_node=d[2])
        elif sig == 0xA0000001:
            out["env_target"] = b[off + 8: off + 268].split(b"\0")[0].decode("latin1")
        off += size
    return out

def main():
    if "--self-test" in sys.argv: return self_test()
    if len(sys.argv) < 2: print(__doc__); return 2
    cp = sys.argv[sys.argv.index("--codepage") + 1] if "--codepage" in sys.argv else "cp936"
    for k, v in parse(open(sys.argv[1], "rb").read(), cp).items(): print(f"{k:14} {v}")
    return 0

def self_test():
    t, mac, rnd = droid(uuid.UUID("9534FAD6-1675-11EF-8391-8045DDE5916E"))
    assert mac == "80:45:dd:e5:91:6e" and not rnd and t.strftime("%Y-%m-%d %H:%M:%S") == "2024-05-20 06:52:54", (t, mac)
    assert bytes.fromhex("CED2B5C4B4C5C5CC").decode("cp936") == "我的磁盘"
    print("self-test OK"); return 0

if __name__ == "__main__":
    sys.exit(main())
