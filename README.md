# RSA Public Key Analysis Report

Prepared October 7, 2026. Subject: `rsa_pubkey.bin` and three PEM files derived from it.

## 1. Summary

The binary file `rsa_pubkey.bin` is a custom "RSAP" container holding one RSA public key. The three PEM files (`extracted_rsa_pubkey.pem`, `rsa_pubkey_pkcs1.pem`, `rsa_pubkey_spki.pem`) are the same key written in two standard formats. All three were verified against the binary and all three match.

The key is **not a usable, secure RSA key**. Its modulus is the byte sequence 01, 02, 03 ... ff, 00, which is a placeholder pattern and not the product of two large random primes. No hidden second key was found in the file.

## 2. Files Examined

- `rsa_pubkey.bin`: 275-byte source file in the custom RSAP format.
- `extracted_rsa_pubkey.pem`: PKCS#1 PEM (`BEGIN RSA PUBLIC KEY`).
- `rsa_pubkey_pkcs1.pem`: PKCS#1 PEM, generated from the binary by script.
- `rsa_pubkey_spki.pem`: SubjectPublicKeyInfo PEM (`BEGIN PUBLIC KEY`), generated from the binary by script.
- `rsa_modulus.bin` (256 bytes) and `rsa_exponent.bin` (3 bytes): raw parts, also checked against the binary.

## 3. Method: How the Key Was Found

**Step 1: Hex dump.** The first bytes spell `RSAP` in ASCII, followed by small integers, then a long run of incrementing bytes. This suggested a header plus raw key material.

**Step 2: Decode the header.** Reading the fields as little-endian 32-bit integers gave the layout below.

- Offset 0x00, 4 bytes: magic `RSAP`.
- Offset 0x04, 4 bytes: 2048 (declared key size in bits).
- Offset 0x08, 4 bytes: 256 (modulus length in bytes).
- Offset 0x0C, 4 bytes: 3 (exponent length in bytes).
- Offset 0x10, 256 bytes: modulus n, big-endian.
- Offset 0x110, 3 bytes: exponent e, bytes `01 00 01`, which is 65537.

The length check works out exactly: 16 + 256 + 3 = 275 bytes, so nothing is truncated and nothing is appended.

**Step 3: Build standard keys.** A Python script (`rsap_to_pem.py`) read n and e and wrote PKCS#1 and SPKI PEM files using the `cryptography` library.

**Step 4: Verify with OpenSSL.** The PEM files were compared with the binary using independent tools (commands in section 6).

**Step 5: Check strength.** The modulus was tested for small factors by trial division, and ECM factoring was attempted on the remaining cofactor.

## 4. Findings

**Key parameters (identical in all three PEM files)**

- Exponent: 65537 (0x10001).
- Modulus: 256 bytes, `01 02 03 ... fd fe ff 00`.
- True bit length: 2041 bits. The header claims 2048, a mismatch.
- The modulus is even (it ends in `00`, with 8 trailing zero bits). A real RSA modulus is always odd.

**The three PEM files**

- `extracted_rsa_pubkey.pem`: PKCS#1 format, 2041 bits, modulus matches the binary. An earlier version of this file had only 253 modulus bytes (2017 bits, ending in `fd`) because the last three bytes `fe ff 00` were lost during extraction. The version checked in the final comparison is complete and correct.
- `rsa_pubkey_pkcs1.pem`: PKCS#1 format, 2041 bits, matches the binary.
- `rsa_pubkey_spki.pem`: SPKI format, 2041 bits, matches the binary.

The only difference between the files is the wrapper. PKCS#1 stores just n and e. SPKI wraps the same two numbers together with an algorithm identifier (rsaEncryption).

**Strength analysis**

- Trial division gives n = 2^8 x 3^2 x 5 x 17 x C, where C is a 2023-bit composite number.
- C was not factored. An ECM attempt did not finish in the time allowed, so no private exponent could be computed.
- No private key is present in any file.

## 5. Conclusion on Which File Is "The Key"

All three files are the same key. None is more correct than the others. Choose by format, as described in section 7. No second or hidden key exists in `rsa_pubkey.bin`.

## 6. Verification Commands

Show the parsed key and confirm exponent and size:

```bash
openssl rsa -RSAPublicKey_in -in rsa_pubkey_pkcs1.pem -text -noout
openssl pkey -pubin -in rsa_pubkey_spki.pem -text -noout
```

Compare the modulus in the binary with the PEM:

```bash
a=$(dd if=rsa_pubkey.bin bs=1 skip=16 count=256 2>/dev/null | od -An -v -tx1 | tr -d ' \n' | tr a-f A-F | sed 's/^0*//')
b=$(openssl rsa -RSAPublicKey_in -in rsa_pubkey_pkcs1.pem -modulus -noout | sed 's/Modulus=//')
[ "$a" = "$b" ] && echo SAME || echo DIFF
```

The `sed` removes the leading zero because OpenSSL prints the modulus without it (511 characters instead of 512). The expected result is `SAME`.

Check the exponent bytes in the binary (expect `01 00 01`):

```bash
dd if=rsa_pubkey.bin bs=1 skip=272 count=3 2>/dev/null | od -An -tx1
```

Inspect the ASN.1 structure (expect a SEQUENCE of two INTEGERs, 256 bytes and 3 bytes):

```bash
openssl asn1parse -in rsa_pubkey_pkcs1.pem
```

In this study, all of these checks matched.

## 7. How Each File Can Be Used

**`rsa_pubkey_spki.pem` (BEGIN PUBLIC KEY).** The most widely accepted format. Use it with `openssl pkey -pubin`, most programming libraries, and most online tools.

**`rsa_pubkey_pkcs1.pem` and `extracted_rsa_pubkey.pem` (BEGIN RSA PUBLIC KEY).** Use these with tools that specifically expect the PKCS#1 form, such as `openssl rsa -RSAPublicKey_in`. Conversion between the two formats is possible:

```bash
openssl rsa -RSAPublicKey_in -in rsa_pubkey_pkcs1.pem -pubout -out converted_spki.pem
```

**Realistic uses for this key**

- Testing a parser or converter for the RSAP format.
- Demonstrating or teaching key formats (PKCS#1 versus SPKI) and PEM/DER structure.
- A fixture or mock key in unit tests, or a starting point for a reverse-engineering exercise.

**What it must not be used for**

- Real encryption, signing, authentication or any security purpose. The modulus is a known pattern with small factors, no private key exists, and any party could treat it as broken.
- Treating it as proof of identity. A verifier configured with this key would not provide protection.

## 8. Limitations and Next Steps

- This report covers only the files provided. The real key for a challenge or system, if one exists, is not in this data.
- If a program loads RSAP files, analyzing that program may show where the actual key is supplied, for example by patching the modulus at runtime.
- Useful follow-ups: search the program for the `RSAP` magic bytes, scan for 128- or 256-byte high-entropy blocks, and look for PEM or DER markers (`-----BEGIN`, or `30 82` followed by a length).

## 9. Appendix: Helper Script

`rsap_to_pem.py` validates the magic and the declared lengths against the file size, reads n and e, and writes `rsa_pubkey_pkcs1.pem` and `rsa_pubkey_spki.pem`. Usage: `python3 rsap_to_pem.py rsa_pubkey.bin`. It prints the declared bit count (2048), the actual bit count (2041), the exponent, and whether n is even.
