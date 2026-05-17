# Android Gift Claim Verifier - 2026-05-17

## Ziel

Android soll das KBeam-Willkommensgeschenk technisch claimen koennen, ohne in den iOS-App-Attest-Pfad zu fallen.

## Umsetzung

Der Gift-Claim akzeptiert jetzt zusaetzlich eindeutig markierte Android-Claims:

- `platform = android`
- `proofSchema = kbeam-android-local-proof-v1`
- optional `proofFormat = json-base64`
- `keyId` mit Prefix `android-local-proof-v1:`

Wenn ein Claim als Android erkannt wird, prueft der Indexer:

- `deviceToken` ist Base64-kodiertes JSON mit `platform=android` und `schema=kbeam-android-gift-device-v1`.
- `attestation` ist Base64-kodiertes JSON mit `platform=android` und `schema=kbeam-android-local-proof-v1`.
- Package Name ist `com.kbeam.android`.
- Challenge-Hash passt zur verbrauchten Challenge.
- Wallet-Hash passt zur Zieladresse.
- Installation-ID und Android-ID-Hash sind vorhanden und formal plausibel.
- `keyId` passt zur Installation-ID und Challenge.

Danach greifen weiterhin die bestehenden serverseitigen Regeln:

- Challenge wird einmalig verbraucht.
- Source-IP-Rate-Limit.
- Wallet-Unique-Slot.
- Device-Fingerprint-Unique-Slot.
- Payout-Command und Persistenz wie bisher.

Android ueberspringt bewusst Apple-App-Attest und DeviceCheck, weil diese iOS-spezifisch sind. Der Device-Fingerprint wird aus Package, Android-ID-Hash und Installation-ID gebildet.

## Rollback

1. In `indexer/src/gift.rs` die optionalen Request-Felder `platform`, `proof_schema`, `proof_format` entfernen.
2. Die Android-Erkennung in `GiftService::claim` entfernen.
3. `verify_android_local_proof`, `parse_android_json`, `require_json_string`, `json_string` und die Android-Konstanten entfernen.
4. Danach faellt Android wieder in den bisherigen iOS-App-Attest-Pfad und wird mit CBOR-Fehler abgelehnt.

## Verifikation

- `cargo check -p indexer` erfolgreich.
- Live-Smoke vor dem Fix zeigte: `invalid app attestation: attestation payload is not valid CBOR`.
- Deploy auf `jarvis@kbeam.app` in `/opt/kasia-indexer` mit `sudo -n docker compose up -d --build kasia-indexer` erfolgreich.
- Container `kasia-indexer-kasia-indexer-1` laeuft danach `healthy`.
- Android-App-Claim vom echten Galaxy wurde nach dem Deploy akzeptiert; die App zeigte `Gesendet` mit Auszahlungs-TX.
