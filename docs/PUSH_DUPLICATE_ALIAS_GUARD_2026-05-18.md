# Push Duplicate Alias Guard 2026-05-18

## Problem
Contextual push aliases can be registered by more than one wallet when a client uploads stale or foreign observed aliases. In that state a visible alias can fan out encrypted messages to unrelated devices. Those devices cannot decrypt the payload, but the notification can still surface as an empty or generic KBeam notification.

## Change
The push service now suppresses contextual dispatch for an alias when that exact alias is registered by multiple distinct wallet addresses. The message remains on-chain and normal sync can still recover it; only the unsafe push fanout is skipped.

Multiple devices for the same wallet may still share the same alias and receive pushes normally.

## Rollback
Revert the guard in `PushService::matching_registrations` and remove the two duplicate-alias tests. Rolling back restores the previous behavior where contextual aliases were matched directly against every registration that advertised them.

## Follow-up
Client registrations should still be hardened so Android and iOS only upload aliases that are trusted for the active wallet. This server guard is a safety brake, not the complete client-side cleanup.
