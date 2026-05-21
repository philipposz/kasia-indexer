# Push Preview Privacy - 2026-05-21

## Ziel

Der Indexer darf keine lesbaren Nachrichtenvorschauen an APNs oder FCM uebergeben. Push bleibt ein schneller Wake-up und Routing-Trigger, waehrend sichtbare Details ausschliesslich aus lokal entschluesselten App-Daten kommen.

## Umsetzung

- APNs-Fallback-Alert ist generisch: `Neue KBeam-Nachricht`.
- Payment-Betraege werden nicht mehr als Klartext-Pushfeld versendet.
- Pulse-Reply-Preview und Klartext-Body werden nicht mehr in APNs/FCM-Payloads geschrieben.
- Kontextuelle Payloads bleiben als verschluesselte Payload-Daten erhalten, solange sie unter dem Inline-Limit liegen, damit Apps den schnellen Target-Sync nutzen koennen.

## Rollback

Ruecknahme ueber den Commit dieses Dokuments und der zugehoerigen Datei:

- `indexer/src/push.rs`

Rollback-Befehl:

```bash
git revert <commit>
```
