# Push Strict Contextual Routes - 2026-05-20

## Scope

This is the rollback-capable indexer baustein for the push/indexer incident on 2026-05-20.

## Problem

A contextual alias is not a globally unique receiver identity. Two different wallets can know the same sender and therefore register the same visible route alias for that sender. The indexer must not deliver a push only because an alias matches.

Kasia-compatible sends are on-chain/ChainSync only. Kasia does not register KBeam push routes with this indexer, does not know KBeam contact state, and must not slow or block the existing fast KBeam push path.

## Contract

Contextual message push delivery is only allowed when the route is resolved by:

- `sender_wallet`
- `receiver_wallet`
- `alias`

Peer-scoped `contextual_routes` are authoritative. A registration update replaces the token's route list. Deleted or blocked contacts disappear by omission when the app re-registers.

The server may still derive contact-request inbox aliases for the authenticated wallet, but it must not trust legacy free-form aliases for modern chat routing.

## Change

- Store `contextual_routes` on device registrations.
- Derive stored aliases from server-accepted routes plus server-derived contact-request inbox aliases.
- Match contextual chat pushes only when the alias belongs to a route whose `peer_address` matches the sender.
- Exclude sender registrations for self-spend style contextual transactions.
- If the chain receiver uniquely identifies one wallet, dispatch to that wallet only.
- If the current event does not identify the logical receiver wallet, skip chat push instead of using
  a single-wallet alias fallback.
- If several wallets claim the same alias for the same sender and no unique receiver wallet can be determined, skip the push for APNs and FCM.
- Remove freshness-based APNs/FCM guessing from the long-term route decision.

## App Registration Requirements

Android and iOS must re-register the full route list after:

- contact add, delete, accept, block, import, restore, or wallet switch
- token refresh
- foreground TTL expiry
- route or alias learning changes

## Protocol Follow-Up

Future KBeam contextual aliases should be derived from sender, receiver, and direction or route id. That prevents two receivers for the same sender from sharing the same visible alias.

## Validation

- Unit coverage in `indexer/src/push.rs` covers legacy alias ignore, server-derived contact-request aliases, sender exclusion, receiver-scoped duplicate delivery, same-wallet multi-device delivery, and multi-wallet duplicate suppression for APNs and FCM.
- Pre-strict hotfix smoke: Galaxy to Galaxy delivered by FCM to the intended Galaxy, receipt returned by FCM, and duplicate APNs contextual aliases were skipped instead of selecting iPhone by recency.
- Strict route behavior: ambiguous chat events fall back to ChainSync until the protocol upgrade
  carries a receiver-scoped route id.

## Rollback

1. Restore `/opt/kasia-indexer/backups/push.rs.pre-strict-route-20260520T105233Z` to `/opt/kasia-indexer/indexer/src/push.rs`.
2. Rebuild the container with `sudo -n docker compose build kasia-indexer` from `/opt/kasia-indexer`.
3. Restart with `sudo -n docker compose up -d kasia-indexer`.
4. Confirm `/metrics` returns HTTP 200 and push provider flags are ready.

Rollback risk: returning to the previous heuristic can again send APNs/FCM pushes to the wrong device when multiple wallets share a sender alias.
