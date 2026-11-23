//! Session resolution and the authoritative atomic session registry (IMP-007, IMP-011, IMP-012).
//!
//! Covers unique-uri / unique-kid / bounded-trial candidate resolution and the MVP
//! `Pending -> Consumed(result)` compare-and-set state machine. See Notion 02 · Architecture §8-9.
