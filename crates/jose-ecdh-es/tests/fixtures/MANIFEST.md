# jose-ecdh-es test fixtures

All values are public test data from the source below. Nothing here is a real key. Tests read
these files with `include_str!`; no test touches the network.

Retrieved 2026-11-25. Regenerate or verify with:

```bash
python3 -I scripts/ecdh_es_fixtures.py fetch <empty-dir>   # only step that uses the network
python3 -I scripts/ecdh_es_fixtures.py extract <dir> crates/jose-ecdh-es/tests/fixtures
python3 -I scripts/ecdh_es_fixtures.py check <dir>          # byte-compare with this directory
```

The script refuses to run if the source's SHA-256 differs from the pin below.

## Sources

| File | Source | SHA-256 of original |
| --- | --- | --- |
| `rfc7518.txt` | https://www.rfc-editor.org/rfc/rfc7518.txt | `9a9ae524b09ea700ad3f189bac115df95ba69af84b26ffdbe3cdfb8d2152b1fc` |
| `rfc7516.txt` | https://www.rfc-editor.org/rfc/rfc7516.txt (cross-check of §5.1/§5.2 only, not vendored) | `722cfcddc15f58e746891ba4b846853d3711153a774e4dd55ad6db100474a21f` |
| `rfc8725.txt` | https://www.rfc-editor.org/rfc/rfc8725.txt (cross-check of §2.5/§3.4/§3.6 only, not vendored) | `737b7013a2495dcfd5481cf4c57c87e2455d537c4cec1140c9096a71fcef0812` |

## Vendored files

| Fixture | SHA-256 | Extraction |
| --- | --- | --- |
| `rfc7518_appendix_c.json` | `757eabae4bb93302fd39924f98c979da4e16cc8bbc65827e6e8a1a589789df44` | From RFC 7518 Appendix C: Alice's ephemeral JWK and Bob's JWK (each member value found verbatim in the appendix), the printed protected header, Z, OtherInfo, the round 1 hash input and the derived key, restructured into a lab JSON schema. The script checks the appendix against itself (see its docstring). Third-party material, see `NOTICE`. |

## What Appendix C does and does not provide

- **A Concat KDF known-answer vector: yes.** Z, every OtherInfo field and the 16-byte derived
  key for `ECDH-ES` + `A128GCM` with `apu` = "Alice", `apv` = "Bob".
- **The ECDH step: yes, indirectly.** Both private keys and the protected header are printed,
  so Bob's key with the header's `epk` must reproduce Z and therefore the key.
- **A complete JWE: no.** RFC 7518 has no ECDH-ES ciphertext, and RFC 7520 §5.5 uses
  `A128CBC-HS256`, which this crate does not implement. Content decryption is covered by the
  josekit interoperability tests instead.
- **An `A256GCM` vector: no.** The 32-byte path is covered by josekit interoperability only.
