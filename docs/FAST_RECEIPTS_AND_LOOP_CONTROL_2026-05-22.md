# Fast Receipts und Contextual-Control-Push, 2026-05-22

## Ziel

Silent Contextual-Aliases duerfen keine sichtbare Push-Benachrichtigung erzeugen, muessen aber als verschluesselte Realtime-Signale zugestellt werden. Das betrifft Receipts, Activity und andere technische Messenger-Signale.

## Server-Aenderung

- Silent Contextual-Aliases werden nicht mehr komplett verworfen.
- Der Server sendet sie als `contextual_control`.
- APNs bekommt dafuer einen background Push ohne `alert`.
- FCM bekommt weiterhin data-only mit `HIGH` Priority.
- Die vorhandene verschluesselte Inline-Payload wird unveraendert weitergegeben.
- Der Dedupe-Key enthaelt jetzt auch den effektiven Push-Typ, damit sichtbare und technische Pushes nicht versehentlich kollidieren.

## Rollback

- In `PushService::dispatch_event` bei `ContextualAliasPolicy::Silent` wieder vor dem Dispatch zurueckkehren.
- Den effektiven Typ `contextual_control` wieder entfernen.
- `dispatch_dedupe_key` bei Bedarf wieder auf `{device_token}:{tx_id}` zuruecksetzen.

## Sicherheit

Der Server entschluesselt nichts. Er entscheidet nur anhand des Alias-Scopes, ob der Push sichtbar (`contextual`) oder technisch silent (`contextual_control`) ist.
