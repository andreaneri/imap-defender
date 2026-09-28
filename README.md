# imap-defender
<<<<<<< HEAD
a light reverse proxy tls with a rate limiter fingerprint (JA4) based
=======

Proxy IMAP in Go pensato per terminare TLS e applicare controlli di rischio prima di inoltrare le sessioni a un backend IMAP. Il prototipo include fingerprint JA4, lookup GeoIP opzionale, mitigazioni `ALLOW` / tarpit / `DROP`, modalità di ispezione del comando `LOGIN` e tracciamento asincrono su Redis.

## Stato

L'autenticazione in modalità Deep Inspection usa ancora un mock (`mario` / `segreta`): non collegare questo prototipo a un servizio esposto o considerarlo pronto per la produzione. La modalità Light non ispeziona le credenziali e si basa solo sui segnali perimetrali disponibili. Consultare [TODO.md](TODO.md) per il backlog e [la documentazione tecnica](docs/DOCUMENTAZIONE.md) per architettura e operatività.

## Avvio locale

Requisiti: Go compatibile con `go.mod`, OpenSSL e Docker Compose oppure Podman Compose.

```sh
make help
make certs
make up
```

Compose pubblica il proxy sulla porta `993` e avvia Redis e Dovecot. Il database GeoLite2 Country è opzionale: se non è presente in `geoip/`, il proxy continua usando il country code neutro `ZZ`. Per scaricare e aggiornare il database, seguire la procedura GeoLite nella [documentazione](docs/DOCUMENTAZIONE.md#provisioning-e-aggiornamento-di-geolite2-country).

Per arrestare lo stack:

```sh
make down
```

## Sviluppo

```sh
make test
make build-local
```

I certificati di test, i database GeoLite e gli eseguibili compilati sono file locali esclusi da Git. Per configurazione, hot reload, log e altri target Make, vedere [docs/DOCUMENTAZIONE.md](docs/DOCUMENTAZIONE.md).
>>>>>>> fb14916 (docs: add project documentation and backlog)
