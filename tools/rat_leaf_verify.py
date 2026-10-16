#!/usr/bin/env python3
"""rat_leaf_verify.py - prove that the TLS leaf Censys saw on 2026-07-15 was issued by QUICAgent's RAT CA.

Censys published only parsed fields of the leaf (subject, key, extensions, validity, signature and the
SHA-256 of its TBSCertificate). This script rebuilds the DER TBSCertificate from those fields exactly the
way Go's crypto/x509 encodes it, checks the hash against Censys' tbs_fingerprint, then verifies the ECDSA
P-384 / SHA-384 signature with the public key of the RAT CA embedded in the implant (tools/data/rat_ca.pem).

Usage:
  python3 -I tools/rat_leaf_verify.py [--ca tools/data/rat_ca.pem] [--out leaf.der]
  python3 -I tools/rat_leaf_verify.py --self-test      (same run; exits non-zero unless TBS and signature verify)
"""
import hashlib, os, sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization


def L(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length()+7)//8, 'big'); return bytes([0x80|len(b)]) + b
def tlv(t, c): return bytes([t]) + L(len(c)) + c
def seq(*a): return tlv(0x30, b''.join(a))
def oid(s):
    p=[int(x) for x in s.split('.')]; out=bytes([40*p[0]+p[1]])
    for v in p[2:]:
        enc=[v&0x7f]; v>>=7
        while v: enc.append(0x80|(v&0x7f)); v>>=7
        out+=bytes(reversed(enc))
    return tlv(0x06,out)
def integer(i): b=i.to_bytes((i.bit_length()+8)//8 or 1,'big'); return tlv(0x02,b)
def pstr(s): return tlv(0x13, s.encode())
def rdn(o,v): return tlv(0x31, seq(oid(o), pstr(v)))


def run(ca_path, out=None):
    ca = x509.load_pem_x509_certificate(open(ca_path, 'rb').read())
    issuer = ca.subject.public_bytes()   # Go copies parent RawSubject into the issuer field
    subject = seq(rdn('2.5.4.6','US'), rdn('2.5.4.10','RAT System'), rdn('2.5.4.3','localhost'))
    x = bytes.fromhex('5dac38b725e9f953e9a14dd0d36af851bf4af5dcb7e8df28014f91e8ca59fe29160bdab49abb278dffbe38a64f0846ce')
    y = bytes.fromhex('e01dccfde2cf19d3754fd5158f5a27bb0b8b4aab501e9c315d1661751f84655b8326d4b116eaa91065eec670a2407e78')
    spki = seq(seq(oid('1.2.840.10045.2.1'), oid('1.3.132.0.34')), tlv(0x03, b'\x00\x04'+x+y))
    ku  = seq(oid('2.5.29.15'), tlv(0x01,b'\xff'), tlv(0x04, tlv(0x03, b'\x05\xa0')))
    eku = seq(oid('2.5.29.37'), tlv(0x04, seq(oid('1.3.6.1.5.5.7.3.1'))))
    aki = seq(oid('2.5.29.35'), tlv(0x04, seq(tlv(0x80, bytes.fromhex('f2f17b88d28bb8eb18147dd5d39eff47fcdc49f6')))))
    san = seq(oid('2.5.29.17'), tlv(0x04, seq(tlv(0x82,b'localhost'), tlv(0x87, bytes([127,0,0,1])))))
    exts = tlv(0xa3, seq(ku, eku, aki, san))
    tbs = seq(tlv(0xa0, integer(2)), integer(2), seq(oid('1.2.840.10045.4.3.3')), issuer,
              seq(tlv(0x17,b'251205081702Z'), tlv(0x17,b'351203081702Z')), subject, spki, exts)
    want = 'f417bd3062e60677af7adac65cde0597d190760a8daa97522a26dd0a6e807042'
    got = hashlib.sha256(tbs).hexdigest()
    print('TBS sha256 rebuilt :', got); print('TBS sha256 Censys  :', want); print('TBS match          :', got==want)
    sig = bytes.fromhex('30660231008da1d5112fa3b7f84b3e8c5aeb5faa879fbbf0f26f5aa2b1da3bb35f83b5279af28faf23f00ece73fb5acfeb0d61a8a1023100f7095f40a8105c77bf75a8101c29b284a8545dc77b0af5453a913cbfa79c0cc953056a08e617878780e31fac5b642aff')
    try:
        ca.public_key().verify(sig, tbs, ec.ECDSA(hashes.SHA384())); print('Signature by embedded RAT CA: VALID'); valid = True
    except Exception as e: print('Signature check failed:', type(e).__name__)
    # full cert for the record
    cert_der = seq(tbs, seq(oid('1.2.840.10045.4.3.3')), tlv(0x03, b'\x00'+sig))
    print('Rebuilt cert sha256:', hashlib.sha256(cert_der).hexdigest())
    if out: open(out, 'wb').write(cert_der)
    return got == want and valid

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    ca = sys.argv[sys.argv.index("--ca") + 1] if "--ca" in sys.argv else os.path.join(here, "data", "rat_ca.pem")
    out = sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv else None
    ok = run(ca, out)
    if "--self-test" in sys.argv: print("self-test OK" if ok else "self-test FAILED")
    sys.exit(0 if ok else 1)
