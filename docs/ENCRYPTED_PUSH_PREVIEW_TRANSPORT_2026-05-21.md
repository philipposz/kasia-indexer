# Encrypted push preview transport

## Goal

The push server must wake devices faster than indexer sync without learning chat preview text. Push dispatch therefore carries only generic alert text plus the encrypted transaction payload when it fits the inline limit.

## Current server behavior

- Contextual push dispatch extracts sender, receiver, route alias and transaction id as routing metadata.
- The server converts the original transaction payload to hex and includes it as `payload` only when it is within `PUSH_INLINE_PAYLOAD_LIMIT`.
- APNs receives a generic alert body and `mutable-content = 1` so the iOS Notification Service Extension can decrypt locally.
- FCM receives the same encrypted payload in the data message so Android can decrypt locally.
- The server does not decrypt or construct text, caption, payment amount, reaction emoji, file names or KNS/avatar preview content.

## Privacy boundary

Cleartext preview text is created only on the receiving device. If the inline encrypted payload is absent, too large or cannot be decrypted, the client falls back to generic notification text and normal sync/indexer resolution.

## Rollback

No server code change is required for this step because the deployed push path already forwards the encrypted inline payload. If a future server change breaks this property, revert that commit and redeploy the indexer; clients will continue to work through generic notification fallback plus sync.

## Verification

Check push payloads in server logs by metadata only. Logs may include tx id, sender, route alias, type and payload length, but must not include decrypted message text.
