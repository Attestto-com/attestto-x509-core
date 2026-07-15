# @attestto/x509-core

Low-level ASN.1 DER parsing and generic X.509 certificate field extraction.
Zero cryptography, zero runtime dependencies, browser- and Node-safe.

Extracted from [`@attestto/verify`](https://github.com/Attestto-com/attestto-verify)
as an independent building block so the same parser is shared by the verifier,
the TLS auditor, and other tools.

## What it does

- Parse DER/ASN.1 structures (`./asn1`).
- Extract generic X.509 fields from a certificate — subject, issuer, validity,
  SANs, key usage, policy OIDs, fingerprint — and from PKCS#7 SignedData
  containers (`./certificate`).

It performs no network calls, no cryptographic verification, and holds no
national-PKI or trust-store logic — those live in the consuming packages.

## License

Apache-2.0
