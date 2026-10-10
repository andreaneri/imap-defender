# 0002 — Separare modalità operative e livello di ispezione

- Data: 2026-10-09
- Stato: Accettato
- Implementazione: pendente; questo ADR non modifica il runtime

## Contesto

Il codice usa `security.deep_inspection_mode` per scegliere tra Light e Deep Inspection. Entrambi possono applicare mitigazioni. Occorre poter osservare il traffico, apprendere dagli esiti e attivare la difesa in momenti distinti.

## Decisione

Adottare tre modalità:
- **Transparent**: relay, metriche e diagnostica; nessuna contromisura deliberata.
- **Learning**: osservazione degli esiti reali e popolamento di Redis; nessuna contromisura basata sulle classificazioni.
- **Defender**: valutazione multi-segnale e politiche configurabili di rate limiting, rallentamento e blocco, con eccezioni controllate e motivazione delle decisioni.

Separare la modalità operativa dalla profondità di ispezione. Light non è sinonimo di Transparent; Deep non è sinonimo di Defender.

Le fingerprint TLS non sono identità univoche. Il mock delle credenziali non può alimentare una base affidabile: l'apprendimento deve usare l'esito del backend. [ADR 0003](0003-backend-authentication-authority.md) precisa che il backend è l'unica autorità di autenticazione e il proxy osserva passivamente già in Transparent.

## Conseguenze

Osservazione ed enforcement possono essere collaudati separatamente. L'implementazione deve definire migrazione YAML, default, timeout, dipendenze Redis e politiche per indisponibilità prima di modificare il runtime. Nessun valore YAML nuovo è attivabile per effetto di questo ADR.

Resta da progettare il comportamento per LOGIN, SASL e comandi preliminari, preservando protocollo e buffer.

## Verifica e riferimenti

I futuri test devono dimostrare assenza di ritardi/blocchi di rischio in Transparent e Learning, persistenza degli esiti reali in Learning, e applicazione delle politiche solo in Defender. Devono coprire compatibilità IMAP, errori Redis, cancellazione e concorrenza.

Vedere [architecture.md](../architecture.md) e [TODO.md](../../TODO.md).
