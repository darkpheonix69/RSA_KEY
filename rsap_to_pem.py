#!/usr/bin/env python3
"""Convert an 'RSAP' public-key blob to PEM.
Layout: "RSAP" | bits u32 LE | n_len u32 LE | e_len u32 LE | n (BE) | e (BE)
Usage: rsap_to_pem.py in.bin [out_prefix] [--pkcs1-trunc N]"""
import sys, struct
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization as s

def parse(d):
    assert d[:4] == b"RSAP", "bad magic"
    bits, nl, el = struct.unpack("<III", d[4:16])
    assert len(d) == 16 + nl + el, "length mismatch"
    return bits, int.from_bytes(d[16:16+nl], "big"), int.from_bytes(d[16+nl:16+nl+el], "big"), d[16:16+nl]

if __name__ == "__main__":
    d = open(sys.argv[1], "rb").read()
    pre = sys.argv[2] if len(sys.argv) > 2 else "rsa_pubkey"
    bits, n, e, raw = parse(d)
    k = RSAPublicNumbers(e, n).public_key()
    open(pre + "_pkcs1.pem", "wb").write(k.public_bytes(s.Encoding.PEM, s.PublicFormat.PKCS1))
    open(pre + "_spki.pem", "wb").write(k.public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo))
    print("header bits:", bits, "| actual n bits:", n.bit_length(), "| e:", e, "| n even:", n % 2 == 0)
