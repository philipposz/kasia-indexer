# Android FCM Push Runbook

Date: 2026-05-06

## Goal

Add Android push delivery to the existing KBeam/Kasia indexer without changing the working APNs path. The APNs configuration remains the default. FCM is disabled unless `PUSH_FCM_ENABLED=true` is set.

## Changed Behavior

- APNs registrations keep using `token_type=apns` and the existing APNs bundle-id filter.
- Android registrations use `token_type=fcm`.
- FCM tokens are trimmed but not lowercased because Firebase registration tokens are case-sensitive.
- Normal message and Pulse reply dispatch now collect APNs and FCM targets separately.
- FCM dispatch uses Firebase HTTP v1 data-only messages and OAuth via a mounted service-account JSON.
- FCM invalid-token pruning is intentionally conservative: payload validation errors are not treated as stale registration tokens.

## Required Android Server Config

Keep the existing APNs values in place and add only these values when Android push should go live:

```bash
PUSH_FCM_ENABLED=true
PUSH_FCM_PROJECT_ID=<firebase_project_id>
PUSH_FCM_SERVICE_ACCOUNT_PATH=/app/secrets/fcm/service-account.json
PUSH_FCM_TIMEOUT_MS=15000
```

The Firebase service-account JSON must be mounted on the host at `secrets/fcm/service-account.json` for the default Compose setup. Do not commit the JSON file or any Firebase private key.

## Preflight

```bash
./scripts/check-env.sh --env-file .env
cargo test -p indexer push::tests
```

The env check validates FCM only when `PUSH_FCM_ENABLED=true`.

## Rollback

Fast rollback without code changes:

```bash
PUSH_FCM_ENABLED=false
docker compose up -d
```

Full code rollback:

```bash
git revert <commit-that-added-android-fcm-push>
docker compose up -d --build
```

APNs should continue to work in both rollback modes as long as the existing APNs env and key mount remain unchanged.

## Android Client Contract

Register Android devices through the existing push registration endpoint with:

```json
{
  "token_type": "fcm",
  "platform": "android",
  "device_token": "<firebase_registration_token>"
}
```

The existing wallet auth payload is still required.
