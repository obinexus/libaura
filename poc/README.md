# CPRNG-SAT Verifier + GOSI.AURA

**Cryptographic Cost Function, Structure Verifier & Integrity Engine**
Developed by **OBINexus Computing** — *Nnamdi Michael Okpala*

---

## 🔐 Overview

This project merges the pragmatic power of `cprng-sat-verifier` with the philosophical engine of `GOSI.AURA`.

* `cprng-sat-verifier` is a SAT-style structural verifier for ZIP files that uses cryptographic cost functions to prove integrity.
* `GOSI.AURA` is a cryptographic model designed to preserve memory, logic, and authenticity—not just data.

Together, they form the foundation of **verifiable software**: not just what was done, but *why* it was done, *how*, and whether it can be **reproducibly proven.**

---

## ✨ Features

* Derive structure from ZIP archives
* Validate contents using internal logic
* Compute `md5` / `sha256` hashes
* Generate `.sig` signature files
* GPG sign `.sig` files with identity
* Verify `.asc` GPG signature authenticity
* Grounded in the GOSI.AURA integrity principle

---

## 🔧 Why GOSI.AURA

> "Not just encryption, but **integrity encoding**."

GOSI.AURA encodes the *meaning* behind every computation. Based on the Medium article [The Hidden Cipher](https://medium.com/@obinexus/the-hidden-cipher-odd-perfect-numbers-and-cryptographic-integrity-ebd1853c5fbc), it redefines cryptographic practice by embedding **proof, provenance, and philosophy** into every file.

It ensures:

* Verifiable memory
* Structural reproducibility
* Entropy-balanced determinism
* Logical accountability

---

## 🚀 Usage Examples

### Verify Structure

```bash
python cprng.py archive.zip --hash-type sha256
```

### Verify Against Known Hash

```bash
python cprng.py archive.zip --verify-hash abcd1234...
```

### Extract, Sign, and Save

```bash
python cprng.py archive.zip --target-dir ./out --sign-with "you@example.com"
```

### Verify GPG Signature

```bash
python cprng.py --verify-sig ./out/archive_signature.sha256.sig.asc
```

---

## 📄 License

MIT License — OBINexus Computing
For research, reproducibility, and righteous cryptographic design.
