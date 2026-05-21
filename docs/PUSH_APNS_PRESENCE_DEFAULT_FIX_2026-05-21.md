# APNs Presence Default Fix

## Befund

Android sendet `presence_typing_start` und `presence_activity` an
`/v1/push/presence`. FCM-Ziele wurden beliefert, APNs-Ziele aber nur dann, wenn
`PUSH_APNS_PRESENCE_ENABLED=true` in der echten Server-Umgebung gesetzt war.
Der vorherige Re-Enable-Commit hatte nur `.env.example` angepasst; Code und
Compose konnten weiterhin auf `false` fallen.

## Aenderung

- `PushConfig::from_env()` defaultet `PUSH_APNS_PRESENCE_ENABLED` auf `true`.
- `docker-compose.yaml` setzt denselben Default explizit.
- Das Flag bleibt als Rollback-Schalter erhalten.

Damit erreichen Android-zu-iOS-Typing- und Activity-Events wieder APNs als
silent Push mit `content-available`, ohne sichtbare Systembenachrichtigung.

## Rollback

`PUSH_APNS_PRESENCE_ENABLED=false` setzen und den Indexer neu starten. Alternativ
diesen Commit zurueckrollen und den Container neu bauen.

## Verifikation

1. Indexer neu bauen und starten.
2. Auf Android im Chat zu einem iOS-Kontakt tippen.
3. Auf iOS muss die Activity-Bubble innerhalb weniger Sekunden sichtbar werden.
4. Es darf keine sichtbare iOS-Systembenachrichtigung fuer Presence erscheinen.
