# Push Device Token Rebind - 2026-05-15

## Problem

APNs device tokens can stay stable across wallet changes on the same iPhone. The
push registry used the device token as the storage key, but `/v1/push/register`
rejected a registration when that token was still bound to an older wallet
pubkey.

That made wallet switches fragile:

- The old wallet could keep receiving pushes on the same physical device.
- The new active wallet could fail to register the same APNs token.
- A user without the old wallet could not self-clean the stale registration,
  because unregister is wallet-authenticated.

## Change

`/v1/push/register` now treats a valid registration for the same device token as
authoritative for the current device. If the token was bound to a different
wallet pubkey, the existing registration is replaced with the newly
authenticated wallet registration.

This keeps the normal self-healing path simple: after an indexer-side cleanup or
after a wallet switch, the app registers the current wallet again and stale token
bindings are removed automatically.

## Rollback

Revert the change in `indexer/src/push.rs` that logs
`Rebinding push device token to newly authenticated wallet` and restores the old
`device token is bound to another wallet` rejection in `PushService::register`.
