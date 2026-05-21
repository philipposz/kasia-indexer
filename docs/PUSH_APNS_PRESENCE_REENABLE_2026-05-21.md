# APNs Presence Re-Enable

## Befund

Android-zu-iOS-Typing wurde serverseitig nicht bis APNs weitergereicht, obwohl der
Presence-Endpunkt die Events annimmt und FCM-Ziele beliefert. Ursache ist der
APNs-Presence-Guard: `PUSH_APNS_PRESENCE_ENABLED` war nicht durchgaengig im
laufenden Compose-/Code-Default aktiviert. Dadurch konnte der Dienst ohne echte
Server-Env wieder auf `false` fallen.

## Änderung

`PUSH_APNS_PRESENCE_ENABLED=true` ist jetzt Code- und Compose-Default und
aktiviert den silent APNs-Presence-Pfad wieder.
Der Payload bleibt still und enthält nur `content-available`, `type`, `sender`
und `timestamp`; sichtbare Benachrichtigungen werden dadurch nicht erzeugt.

Damit kann iOS wieder `presence_typing_start` und `presence_typing_stop` für die
Activity-Bubble verarbeiten, während Android weiter unverändert über FCM bedient
wird.

## Rollback

Für Rollback `PUSH_APNS_PRESENCE_ENABLED=false` setzen und den Push/Indexer-
Dienst neu starten. Danach werden Presence-Events weiterhin angenommen und an
FCM ausgeliefert, aber nicht mehr an APNs gesendet.

## Verifikation

1. Android-Chat mit iOS-Kontakt öffnen.
2. Auf Android tippen.
3. Auf iOS prüfen, ob die Activity-Bubble innerhalb weniger Sekunden erscheint.
4. Auf iOS prüfen, dass keine sichtbare Systembenachrichtigung für Presence
   erscheint.
