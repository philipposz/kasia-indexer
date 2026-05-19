# Push Contextual Receiver Scope 2026-05-19

## Context
After the duplicate-alias safety guard, stale client registrations could still advertise a
visible contextual alias that also belonged to the real receiver. The guard correctly prevented
fanout to unrelated wallets, but it did so before using the receiver address from the indexed
transaction. That could suppress a legitimate normal message or contact-request push while
presence pushes still worked because presence is addressed directly by wallet.

## Change
Contextual push matching now scopes alias matches to the transaction receiver when the receiver is
available. If a stale registration from another wallet advertises the same alias, the indexer still
delivers the push to the receiver wallet only. If no receiver-scoped registration exists, the
existing duplicate-alias guard remains active.

## Rollback
Revert the changes in `indexer/src/push.rs` around contextual matching and remove the receiver-scope
test. Rolling back restores the stricter duplicate-alias behavior that can suppress legitimate
pushes when stale aliases remain registered on unrelated wallets.

## Verification
- `cargo test -p indexer push::tests`
