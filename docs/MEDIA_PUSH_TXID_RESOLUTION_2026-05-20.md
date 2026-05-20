# Media Push TxID Resolution - 2026-05-20

## Scope

The indexer exposes an exact contextual-message lookup endpoint so mobile push
handlers can resolve the transaction id contained in a push payload without
depending on recent sender/alias windows.

Changed files:

- `indexer/src/api/v1/contextual_messages.rs`
- `indexer/src/api/v1.rs`

## Behaviour

- New endpoint: `GET /contextual-messages/by-txid?tx_id=<64 hex>&sender=<wallet>`.
- `sender` is optional, but mobile clients provide it to avoid a full contextual
  message scan.
- The endpoint returns zero or one `ContextualMessageResponse` in the same array
  shape as `/contextual-messages/by-sender`.

## Rollback

Revert the commit containing this file. Mobile clients will then fall back to
the old alias-window and chain-probe behaviour.

## Verification

- Run `cargo fmt`.
- Run `cargo test -p indexer`.
