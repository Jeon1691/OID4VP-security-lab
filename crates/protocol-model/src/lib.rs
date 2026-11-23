//! Versioned OpenID4VP wire model (IMP-003).
//!
//! Will hold `ProtocolVersion`, `ResponseMode`, `RequestBinding` and identifier newtypes that
//! keep the exact wire bytes of `client_id`, `nonce`, `response_uri` and `origin` captured when a
//! request is signed. See Notion 02 · Architecture §5 and §7.2.
