# Push Dispatch Inline Metrics - 2026-05-22

## Ziel

Der Push-Server soll bei verschluesselten Push-Previews nicht blind sein. Fuer
jeden Dispatch muss nachvollziehbar sein, ob ein verschluesselter Inline-
Envelope vorhanden war und ob APNs/FCM Ziele gefunden und erfolgreich bedient
wurden.

## Aenderung

- Der Push-Dispatch-Monitor zaehlt zusaetzlich:
  - `payload_inline`
  - `payload_missing`
  - `payload_bytes_total`
- Pro Provider wird auf `info` geloggt:
  - `provider=apns|fcm`
  - `tx_id`
  - `message_type`
  - `target_count`
  - `payload_inline`
  - `payload_len`
  - contextual Alias und Receiver, falls vorhanden
- Erfolgreiche Sends und Dedupe-Skips werden ebenfalls auf `info` geloggt,
  ohne Device-Tokens auszugeben.

## Datenschutz

Es wird weiterhin kein Klartext-Preview geloggt oder versendet. Die Logs
enthalten nur Routing-/Transport-Metadaten und Payload-Groessen.

## Rollback

Rollback-faehiger Einzelbaustein:

1. Die neuen Counter-Felder aus `PushDispatchCounters` und
   `PushDispatchSnapshot` entfernen.
2. Die `payload_inline`/`payload_missing` Zaehler im Dispatch entfernen.
3. Die neuen `info!`-Logs fuer Targets, Sent und Dedupe entfernen.
4. Den Monitor-Text optional wieder auf den vorherigen Stand setzen.

Danach Indexer neu bauen und deployen.
