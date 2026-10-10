# imap-defender

**IMAP Defender** è un prototipo di proxy IMAP in Go per sperimentare la mitigazione degli accessi automatizzati e proteggere i backend di posta. Termina TLS in ingresso e utilizza segnali come fingerprint JA4, GeoIP opzionale e Redis per valutare il rischio.

> **Stato: prototipo sperimentale, non pronto per la produzione.** Il backend IMAP è l'unica autorità di autenticazione ([ADR 0003](docs/adr/0003-backend-authentication-authority.md)). L'osservatore dei comandi LOGIN/AUTHENTICATE e delle risposte tagged è sperimentale; non è ancora garantita la compatibilità con tutte le varianti del protocollo. Non esporre il servizio a traffico reale o credenziali di utenti reali.

## Stato del progetto

Il relay inoltra greeting, comandi e risposte senza ricostruire le credenziali. `security.mode` seleziona **Transparent** (default, senza letture/scritture Redis o mitigazioni), **Learning** (eventi reali in Redis senza mitigazioni) e **Defender** (Risk Engine preesistente e apprendimento). Rate limiting ed eccezioni Defender restano da implementare. La migrazione dei vecchi YAML e il comportamento con Redis indisponibile sono descritti in [ADR 0005](docs/adr/0005-mode-runtime-and-learning.md).

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
