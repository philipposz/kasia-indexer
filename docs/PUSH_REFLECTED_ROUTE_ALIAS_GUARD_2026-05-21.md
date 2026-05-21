# Push Reflected Route Alias Guard - 2026-05-21

## Problem

Live push registrations contained route-scoped `kbr1_...` aliases on the wrong receiver route. The indexer then saw the same `(sender_wallet, alias)` claimed by multiple receiver wallets and skipped dispatch instead of guessing. This protected against false delivery, but it also broke legitimate pushes until the stale registration was replaced.

## Fix

The indexer now normalizes contextual routes before storing and after loading them. Reusable base aliases are kept, valid route-scoped aliases are derived from `(sender_wallet, receiver_wallet, alias)`, and reflected route-scoped aliases that do not match the registered route are dropped.

## Verification

- `contextual_route_normalization_filters_reflected_route_scoped_aliases`

## Rollback

Revert this commit to accept client-submitted route-scoped aliases without server-side route verification.
