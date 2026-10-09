# imap-defender

**IMAP Defender** è un prototipo di proxy IMAP in Go per sperimentare la mitigazione degli accessi automatizzati e proteggere i backend di posta. Termina TLS in ingresso e utilizza segnali come fingerprint JA4, GeoIP opzionale e Redis per valutare il rischio.

> **Stato: prototipo sperimentale, non pronto per la produzione.** La Deep Inspection usa ancora un mock di autenticazione e non gestisce tutti i flussi IMAP. Non esporre il servizio a traffico reale o credenziali di utenti reali.

## Stato del progetto

L'implementazione attuale distingue **Light** e **Deep Inspection** tramite `security.deep_inspection_mode`. Le modalità operative **Transparent**, **Learning** e **Defender** sono concordate ma non ancora implementate.

Per il comportamento effettivo, le limitazioni e l'evoluzione prevista consultare [Architettura e stato](docs/architecture.md); per le attività aperte consultare [TODO.md](TODO.md).

## Avvio locale

Requisiti: Go secondo [go.mod](go.mod), OpenSSL e Docker Compose (o Podman Compose compatibile).

```sh
make help
make certs
make up
```

Lo stack di test espone il proxy sulla porta `993` e avvia Redis e Dovecot. I certificati generati sono destinati esclusivamente ai test locali. Il database GeoLite2 Country è opzionale: in sua assenza il proxy usa il country code neutro `ZZ`.

Per arrestare lo stack:

```sh
make down
```

## Sviluppo

```sh
make test
make bench
make build-local
```

I test automatici non certificano la compatibilità IMAP end-to-end né la sicurezza per la produzione. Per configurazione, GeoLite2, hot reload e altri comandi Make consultare la [documentazione tecnica](docs/DOCUMENTAZIONE.md).

## Documentazione e collaborazione

- [Architettura e stato](docs/architecture.md): comportamento implementato, limiti e direzione architetturale.
- [Documentazione tecnica](docs/DOCUMENTAZIONE.md): dettagli operativi e implementativi.
- [ADR](docs/adr/README.md): motivazioni e storia delle decisioni architetturali.
- [TODO](TODO.md): attività da realizzare e avanzamento.
- [AGENTS.md](AGENTS.md): convenzioni e workflow per gli assistenti.
- [Istruzioni del progetto ChatGPT](docs/chatgpt-project-instructions.md): contesto condiviso del progetto.
