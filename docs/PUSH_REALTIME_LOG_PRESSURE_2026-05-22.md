# Push Realtime Log Pressure Fix - 2026-05-22

## Context

During Android S26/A26 push verification, newly broadcast contextual transactions were not visible through the `contextual-messages/by-txid` endpoint. The indexer logs showed repeated realtime processing stalls:

- `We don't process real time vcc for a long time`
- `conflict detected, retry handling block`
- many `Unknown operation type` warnings with very large hex payloads

The large unknown-operation warnings were triggered by unrelated on-chain `cast:*` payloads. Logging the complete payload made every unknown operation expensive and amplified CPU pressure while realtime indexing was already busy.

## Change

Unknown sealed-operation diagnostics now log only:

- payload length
- a short hex prefix preview
- the event label

The indexer still records that an unknown operation was seen, but it no longer writes the full arbitrary payload into logs.

## Rollback

Rollback is the single commit containing this document and the change in `protocol/src/operation/deserializer.rs`.

## Verification

- `cargo test -p protocol`
- `cargo build -p indexer --release`

