//! JOSE HPKE-0 Integrated Encryption codec and OpenID4VP 1.1 Session Info (IMP-004..006).
//!
//! Primitives are delegated to the `hpke` crate (RFC 9180). This crate owns compact JWE
//! parsing, protected-header policy (draft-ietf-jose-hpke-encrypt-22) and the exact
//! `OpenID4VP-si` / `OpenID4VPDCAPI-si` info encodings. See Notion 02 · Architecture §7.
