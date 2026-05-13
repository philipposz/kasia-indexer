# Presence Push Endpoint

Date: 2026-05-13

## Purpose

Android sends typing and activity state to `/v1/push/presence`. The endpoint is intentionally ephemeral and must not create a visible user notification.

## Request

`POST /v1/push/presence`

Body:

- `sender_address`
- `recipient_address`
- `event_type`: `presence_typing_start`, `presence_typing_stop`, or `presence_activity`
- `timestamp_ms`
- `auth`: existing push challenge auth payload

The authenticated wallet address must match `sender_address`.

## Delivery

- FCM receives a data-only message with `type`, `sender`, and `timestamp`.
- APNs receives a background payload with `content-available=1` and no `alert`.
- Presence events are not deduplicated by transaction id because they are not chain transactions and repeated typing/activity updates are expected.

## Rollback

Remove the `/presence` route from `indexer/src/api/v1/push.rs`, the `PushPresenceRequest` schema and `dispatch_presence` implementation from `indexer/src/push.rs`, and the OpenAPI entries in `indexer/src/api/v1.rs`.
