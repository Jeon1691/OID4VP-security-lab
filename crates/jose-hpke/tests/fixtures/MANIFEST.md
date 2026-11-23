# jose-hpke test fixtures

All values are public test data from the sources below. Nothing here is a real key. Tests read
these files with `include_str!`; no test touches the network.

Retrieved 2026-11-24. Regenerate or verify with:

```bash
python3 -I scripts/hpke_fixtures.py fetch  <empty-dir>   # only step that uses the network
python3 -I scripts/hpke_fixtures.py extract <dir> crates/jose-hpke/tests/fixtures
python3 -I scripts/hpke_fixtures.py check  <dir>          # byte-compare with this directory
```

The script refuses to run if any source's SHA-256 differs from the pins below.

## Sources

| File | Source (pinned) | SHA-256 of original |
| --- | --- | --- |
| `test-vectors.json` | https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json (last commit touching the file; "Add test vectors.", 2021-05-24) | `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` |
| `rfc9180.txt` | https://www.rfc-editor.org/rfc/rfc9180.txt (cross-check only, not vendored) | `f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6` |
| `jose-vectors.json` | https://raw.githubusercontent.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt/2fa0c6b2b6d82013aa87a6d83c121de6f2fec3f0/examples/jose-vectors.json (tag `draft-ietf-jose-hpke-encrypt-22`) | `235fade8057e5e114d3e6b6e39c7187509178f148e0518a4117e8a3d3c1c3884` |
| `jwe.js` | https://raw.githubusercontent.com/ietf-wg-jose/draft-ietf-jose-hpke-encrypt/2fa0c6b2b6d82013aa87a6d83c121de6f2fec3f0/scripts/jwe.js (generator of the above, same tag) | `0c14056c28cf35b4c269173bb8af67b4f2accb658b9d4cabd4711cd4babd6eff` |
| `draft-ietf-jose-hpke-encrypt-22.txt` | https://www.ietf.org/archive/id/draft-ietf-jose-hpke-encrypt-22.txt (cross-check only, not vendored) | `6e9c0df346df528d3c5dad1dea1a221716bd614dd2ec2357b3f531664f00b8cc` |
| OpenID4VP 1.1 §8.3.1 | https://openid.github.io/OpenID4VP/openid-4-verifiable-presentations-1_1-wg-draft.html (editor's draft "Published 11 November 2026"; moving document) | `14545ac3877df0a80345dd70c6d0366be1496ba69b21234b779e4d200d9ccc76` |

## Vendored files

| Fixture | SHA-256 | Extraction |
| --- | --- | --- |
| `rfc9180_base_p256_sha256_aes128gcm.json` | `432bbeaf4043d761c99a10f39d12772b0898cf8285541634e5cd6c5ff782185f` | From `test-vectors.json`, the one entry with `mode == 0`, `kem_id == 16` (0x0010 DHKEM(P-256, HKDF-SHA256)), `kdf_id == 1` (HKDF-SHA256), `aead_id == 1` (AES-128-GCM), copied unchanged as a one-element list (257 encryptions, sequence 0..256; 3 exports). Every scalar field, the six encryptions printed in RFC 9180 A.3.1.1 and the exports in A.3.1.2 are checked to appear verbatim in the RFC text. |
| `jose_hpke_22_vectors.json` | `8698029c3c91432e63c6143a82b20b7a90d7f2d05fb19cda1eaa8e0395d407dc` | From `jose-vectors.json`, the `HPKE-0`, `HPKE-0-KE` and `HPKE-7` entries copied unchanged under `vectors`. The HPKE-0 `compact` value is checked to equal draft-22 Figure 3 after RFC 8792 unfolding, and the JWK `d` to appear in Figure 1. `plaintext` is the `const plaintext` literal of `jwe.js`. |

## What draft-22 does and does not provide

- **Decryptable official vector: yes.** Appendix A.1 (HPKE-0) gives a private JWK (`d`) and a
  JWE Compact Serialization for Integrated Encryption. `jwe.js` seals it with HPKE `info`
  unset (empty, the draft-22 §5 default) and `aad = ASCII(BASE64URL(protected header))`.
- **Expected plaintext: not in the I-D text, nor in `jose-vectors.json`.** It is only in the
  generator script `jwe.js` at the same tag. The tests treat that literal as the expected
  value; a successful AEAD open under the official key is the primary check.
- **No vector uses OpenID4VP Session Info.** Binding to `session_info` (IMP-006) is tested with
  self-generated round trips only; those are supplementary, not interoperability evidence.
- `HPKE-0-KE` (Key Encryption, A.2) and `HPKE-7` (A.13) are used as official inputs that the
  HPKE-0 Integrated Encryption verifier must reject. The flattened JSON serialization of A.1 is
  used to show that JSON serialization is rejected.

## OpenID4VP Session Info examples

`tests/session_info.rs` hard-codes the two non-normative examples of §8.3.1 (the
`direct_post.jwt` and `dc_api.jwt` encodings and their hexadecimal representations) as test
literals, copied from the HTML revision hashed above.
