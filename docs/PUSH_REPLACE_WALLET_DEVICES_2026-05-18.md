# Push Replace Wallet Devices

## Scope

The push registration endpoint now accepts `replace_wallet_devices`.

When this flag is true and the registration is authenticated for a wallet, the indexer removes other push registrations for the same wallet before storing the current device token. Registrations for other wallets remain untouched.

## Why

This lets the apps recover from stale device registrations after wallet changes, restores or device migrations. A user can reconnect push for the current device without keeping old tokens subscribed to the wallet.

## Rollback

Revert the commit containing this document and the related `indexer/src/push.rs` changes.

After rollback, app clients can still register normally, but the stale-device cleanup flag will no longer have an effect.

## Verification

- `cargo test push`

