# Push Route Scoped Receiver Fix 2026-05-20

## Ziel

Push-Zustellung darf nicht mehr nur aus einem Alias abgeleitet werden. Eine KBeam-Contextual-Route ist ab diesem Baustein dreiteilig: `sender_wallet`, `receiver_wallet`, `alias`.

## Umsetzung

- `ContextualPushRoute` akzeptiert weiterhin `peer_address`, zusätzlich aber `sender_wallet` als Alias fuer den Sender und `receiver_wallet` fuer den authentifizierten Empfaenger.
- Der Server normalisiert `receiver_wallet` auf die Wallet aus der signierten Registrierung. Abweichende Receiver-Werte werden nicht als fremde Route uebernommen.
- Wenn ein Contextual-Alias ohne eindeutigen Receiver mehrere Wallets trifft, wird nicht zugestellt. Die alte Freshest-Wallet-Heuristik wurde entfernt.
- Ambiguous-Receiver-Skips werden getrennt in `/v1/metrics` gezaehlt:
  - `contextual_push_skipped_ambiguous_receiver_fcm`
  - `contextual_push_skipped_ambiguous_receiver_apns`

## Rollback

Rollback dieses Bausteins entfernt die neuen Metrikfelder, stellt die alte Contextual-Route ohne `receiver_wallet` wieder her und reaktiviert die vorherige Alias-Auswahl. Danach muss der Indexer neu gebaut und deployed werden.

## Verifikation

- `cargo fmt --all`
- `cargo test -p indexer contextual_matching_skips_duplicate_alias_without_receiver_scope`
- `cargo test -p indexer contextual_matching_scopes_duplicate_alias_to_receiver_wallet`
