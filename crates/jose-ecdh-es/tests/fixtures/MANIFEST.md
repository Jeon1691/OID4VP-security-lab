# jose-ecdh-es test fixtures

All values are public test data from the sources below. Nothing here is a real key. Tests read
these files with `include_str!`; no test touches the network.

Retrieved 2026-11-25. Regenerate or verify with:

```bash
python3 -I scripts/ecdh_es_fixtures.py fetch <empty-dir>   # only step that uses the network
python3 -I scripts/ecdh_es_fixtures.py extract <dir> crates/jose-ecdh-es/tests/fixtures
python3 -I scripts/ecdh_es_fixtures.py check <dir>          # byte-compare with this directory
```

The script refuses to run if any source's SHA-256 differs from the pins below.

## Sources

| File | Source | SHA-256 of original |
| --- | --- | --- |
| `rfc7518.txt` | https://www.rfc-editor.org/rfc/rfc7518.txt | `9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc` |
| `openid-4-verifiable-presentations-1_0.html` | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html (OpenID4VP 1.0 Final; a republished page with errata would change the hash) | `e4f0abc689afd0a4f6c41b83954d7f970c5263a26143ad861216aea9918993bb` |
| `rfc7516.txt` | https://www.rfc-editor.org/rfc/rfc7516.txt (cross-check of §5.1/§5.2 only, not vendored) | `722cfcddc15f58e746891ba4b846853d3711153a774e4dd55ad6db100474a21f` |
| `rfc8725.txt` | https://www.rfc-editor.org/rfc/rfc8725.txt (cross-check of §2.5/§3.4/§3.6 only, not vendored) | `737b7013a2495dcfd5481cf4c57c87e2455d537c4cec1140c9096a71fcef0812` |

## Vendored files

| Fixture | SHA-256 | Extraction |
| --- | --- | --- |
| `rfc7518_appendix_c.json` | `757eabae4bb93302fd39924f98c979da4e16cc8bbc65827e6e8a1a589789df44` | From RFC 7518 Appendix C: Alice's ephemeral JWK and Bob's JWK (each member value found verbatim in the appendix), the printed protected header, Z, OtherInfo, the round 1 hash input and the derived key, restructured into a lab JSON schema. The script checks the appendix against itself (see its docstring). Third-party material, see `NOTICE`. |
| `openid4vp_1_0_section_8_3_example.json` | `f3a9e9931ac258a138dca8ee04b8e1ad093828717691e981928f41a827a0e588` | From OpenID4VP 1.0 §8.3, artwork `section-8.3-8` (the compact JWE, display line breaks removed), `-10` (the `kid` "ac" JWK with `d`), `-12` (decoded protected header) and `-14` (payload), HTML entities unescaped, restructured into a lab JSON schema. The script checks that the JWE's protected header decodes to the printed one and that the JWK's public members equal key "ac" of the request example (`-6`). Third-party material under the OpenID Foundation's licence, see `NOTICE`. |

## What the sources do and do not provide

- **A Concat KDF known-answer vector: yes (RFC 7518 Appendix C).** Z, every OtherInfo field and
  the 16-byte derived key for `ECDH-ES` + `A128GCM` with `apu` = "Alice", `apv` = "Bob".
- **The ECDH step: yes, indirectly (Appendix C).** Both private keys and the protected header
  are printed, so Bob's key with the header's `epk` must reproduce Z and therefore the key.
- **A complete `A128GCM` JWE: yes (OpenID4VP 1.0 §8.3).** The recipient's `d` and the payload
  are printed, so parsing, ECDH, the KDF (no `apu`/`apv`) and AES-GCM are covered end to end.
  The printed payload elides the credential (`"eyJhb...YMetA"`); the ciphertext encrypts that
  elided text, which is what the test compares. RFC 7518 has no ECDH-ES ciphertext, and
  RFC 7520 §5.5 uses `A128CBC-HS256`, which this crate does not implement.
- **An `A256GCM` vector: no.** The 32-byte path is covered by josekit interoperability only.
