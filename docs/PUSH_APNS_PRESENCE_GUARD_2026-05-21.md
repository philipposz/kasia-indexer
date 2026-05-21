# APNs Presence Guard

## Problem

Live-Logs on 2026-05-21 showed APNs dispatches every 30 seconds while an Android peer sent `presence_activity`. These presence pushes are silent protocol signals and must not surface as visible iOS notifications.

## Change

`PUSH_APNS_PRESENCE_ENABLED` now defaults to `false`. The server still accepts presence events and continues to deliver them to FCM, but APNs presence dispatch is skipped unless this flag is explicitly enabled after the iOS client has a verified silent-presence path.

Contextual message, payment, handshake, Pulse, and FCM push routing are unchanged.

## Rollback

Revert this document and the matching `indexer/src/push.rs` / `.env.example` changes, rebuild the indexer container, and restart `kasia-indexer`.

## Verification

After deploy, monitor `docker compose logs kasia-indexer` and confirm that `presence_activity` from Android no longer increases APNs `targets_delta` / `sent_delta`, while normal contextual pushes remain available.
