# Push Contextual Alias Safe Scope - 2026-05-19

## Problem

Normal chat push notifications stopped working reliably after the receiver-wallet guard was added for contextual pushes.

Presence and typing still worked because those are not dispatched through the contextual blockchain transaction route. For contextual chat messages the transaction receiver is not always the logical chat peer; the contextual alias is the actual delivery address.

## Fix

Contextual push matching now scopes by exact alias first:

- if the alias belongs to a single wallet, dispatch to that wallet even when the chain receiver does not match;
- if the alias is registered by multiple wallets and the chain receiver identifies one wallet, dispatch only to that wallet;
- if the chain receiver is the sender itself, treat it as a contextual self-spend and exclude the sender registration before choosing a target;
- if only the sender registration matches an alias, do not dispatch a push;
- if the alias is registered by multiple wallets and no receiver scope can disambiguate it, drop the push to avoid another push fan-out.

Silent aliases remain suppressed before target matching.

## Verification

Added unit tests covering the normal single-wallet alias case where the chain receiver differs from the chat peer, sender exclusion for contextual self-spends, and sender-only suppression. Existing tests still cover duplicate alias suppression and receiver-scoped duplicate alias dispatch.

## Rollback

Revert this commit to restore strict receiver matching for contextual pushes. That may stop normal chat notifications again when the chain receiver differs from the logical peer.
