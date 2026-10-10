# Decisioni architetturali

Gli ADR registrano decisioni durature, contesto e conseguenze. Lo stato **Accettato** indica una decisione concordata, non che sia già implementata.

| ADR | Decisione | Stato |
| --- | --- | --- |
| [0001](0001-shared-repository-context.md) | GitHub come fonte condivisa tra chat e strumenti | Accettato |
| [0002](0002-operating-modes.md) | Transparent, Learning e Defender | Accettato; implementazione nei limiti di ADR 0005 |
| [0003](0003-backend-authentication-authority.md) | Autenticazione esclusiva del backend IMAP; osservazione passiva degli esiti | Accettato; implementazione nei limiti di ADR 0005 |
| [0004](0004-account-authentication-signals.md) | Username dichiarata ed esito reale con IP/GeoIP/JA4, senza conservare segreti | Accettato; estrazione, log e persistenza implementati |
| [0005](0005-mode-runtime-and-learning.md) | Default, migrazione YAML, apprendimento Redis e gestione errori | Accettato; implementato |

Per una nuova decisione copiare [template.md](template.md) in un file numerato con nome descrittivo. Usare gli stati Proposto, Accettato, Rifiutato o Sostituito. Quando cambia una decisione, aggiungere un nuovo ADR e aggiornare il precedente con un collegamento alla sostituzione.
