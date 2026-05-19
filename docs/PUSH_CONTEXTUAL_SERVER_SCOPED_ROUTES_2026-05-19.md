# Push Contextual Server Scoped Routes

Date: 2026-05-19

## Change

The push indexer no longer trusts free-form contextual aliases submitted by clients for chat push delivery.

New registrations may submit `contextual_routes`, each containing:

- `peer_address`
- the inbound aliases for that peer

During contextual push dispatch the indexer now matches a registration only when:

1. the contextual alias belongs to a route whose `peer_address` equals the sender address, or
2. the alias is the server-derived contact-request inbox alias for the authenticated wallet.

The legacy `aliases` request field is ignored by the server. Stored `aliases` are now derived from server-accepted routes and the server-derived contact-request inbox aliases.

## Why

Old clients could register aliases belonging to another wallet. That caused normal message pushes to be delivered to the wrong device or to be suppressed due to duplicate alias ownership.

## Rollback

Revert this commit and redeploy the indexer. After rollback the old free-form alias registration behavior returns and stale clients may again poison contextual push routing.

## Verification

- `cargo test -p indexer push::tests -- --nocapture`

The test suite includes:

- legacy free alias registrations are ignored
- contact-request inbox aliases remain server-derived and deliverable
- contextual routes still match normal chat pushes
- presence routing remains wallet-address based and unaffected
