# Contextual Push Freshest Alias Scope

Date: 2026-05-19

## Problem

After narrowing contextual push dispatch away from sender self-spends, normal message pushes could still be blocked when a stale device registration from another wallet still watched the same contextual alias. The safe multi-wallet guard correctly prevented fanout, but that also suppressed the intended recipient push.

This can happen after a wallet migration or restore previously registered outbound or contaminated aliases. New app builds now register only inbound aliases, but old server-side registrations can remain until the device reconnects.

## Change

When a contextual alias is registered by multiple non-sender wallets:

- If the chain receiver identifies one wallet, keep using that receiver-scoped wallet.
- Otherwise, choose a wallet only when it has a clearly fresher registration than the next candidate.
- The freshness margin is ten minutes.
- If there is no clear freshness winner, keep suppressing the push to avoid wrong-device fanout.

## Expected Effect

Freshly reconnected devices can receive normal contextual message pushes even when an older stale registration still contains the same alias. Ambiguous cases remain suppressed.

## Rollback

Revert this document and the `freshest_contextual_wallet` logic in `indexer/src/push.rs` to return to strict multi-wallet suppression.
