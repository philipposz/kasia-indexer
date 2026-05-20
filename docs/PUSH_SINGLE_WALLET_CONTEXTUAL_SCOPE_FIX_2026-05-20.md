# Push Single-Wallet Contextual Scope Fix 2026-05-20

## Problem

After the stricter contextual push routing rollout, Android-to-Android messages could be indexed by sync but did not produce FCM push notifications. Server logs showed `Skipping contextual push dispatch because alias matched but receiver wallet was not unique` for the route-scoped alias used by the Galaxy sender.

## Root Cause

The strict receiver-scope guard rejected every contextual alias match when the chain receiver was not useful for routing, even if the alias matched exactly one non-sender wallet. This was stricter than the intended long-term rule: only multiple matching receiver wallets must be dropped. A single matching receiver wallet is deterministic and should be delivered.

## Change

- Keep the strict no-guessing rule for multiple receiver wallets sharing the same sender/alias.
- Allow delivery when exactly one non-sender wallet matches the sender-scoped alias, even if the on-chain receiver is missing, sender/change, or otherwise not useful.
- Keep sender-only matches suppressed.
- Keep same-wallet multi-device registrations eligible because they represent one receiver wallet, not an ambiguous target choice.

## Rollback

Revert the commit containing this file and the matching change in indexer/src/push.rs, then rebuild and restart the indexer service using the normal deployment procedure.

## Validation

After rollout, a five-message Android-to-Android smoke test sent text messages with 10 seconds spacing and no manual sync before evaluation. All five arrived through FCM before sync. Server metrics after the run showed `contextual_push_skipped_ambiguous_receiver_fcm=0` and `contextual_push_skipped_ambiguous_receiver_apns=0`.
