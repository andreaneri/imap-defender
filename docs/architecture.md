# IMAP Defender — Architettura e stato

## Riferimento

Questa fotografia descrive il codice al commit `1a5d536a1ea575256ee90072d3c160e93c2ace0f` di `main`. Va aggiornata quando cambia il comportamento. [DOCUMENTAZIONE.md](DOCUMENTAZIONE.md) conserva la guida tecnica e operativa estesa; [TODO.md](../TODO.md) raccoglie il backlog. Le descrizioni progettuali nella guida estesa vanno confrontate con il codice.

## Implementazione attuale

La logica è in `main.go`, i test in `main_test.go`. Il proxy termina TLS, ricava JA4 tramite `GetConfigForClient`, consulta GeoIP opzionale e Redis e inoltra verso il backend mediante TCP senza TLS nel collegamento a valle.

| Componente | Comportamento verificato nel codice |
| --- | --- |
| Configurazione | YAML validato e pubblicato tramite `AtomicConfig`; selezione Light/Deep tramite `deep_inspection_mode` |
| Light | Consulta trust JA4 e paese, valuta il rischio e può rallentare o chiudere prima del relay; non osserva l'esito IMAP |
| Deep Inspection | Greeting sintetico, parser limitato a LOGIN, verifica credenziali mock, valutazione rischio, evento Redis e replay al backend |
| Risk Engine | Score limitato a 0–100; azioni ALLOW, TARPIT_SOFT (3 s), TARPIT_HARD (12 s), DROP; nessun rate limiter a contatori |
| GeoIP | Country code ZZ per DB assente, IP locali o lookup senza risultato; IT e ZZ non aggiungono peso geografico |
| Redis | Lookup sincrono di trust con timeout di 200 ms; coda asincrona e pipeline per gli eventi Deep |
| Persistenza | Trust JA4 per 30 giorni su successo del mock; hash con ultimo evento per coppia JA4/account, TTL 7 giorni |
| Lifecycle | Gestione SIGINT/SIGTERM, attesa limitata delle connessioni e del worker; SIGHUP per configurazione, certificati e GeoIP |
| CI | Vet, test con race detector e build Linux |

Gli eventi contengono JA4, username, indirizzo remoto, esito e timestamp. Il valore chiamato `RemoteIP` è attualmente l'indirizzo remoto con porta; il paese non è memorizzato nell'evento Redis.

## Limiti attuali

- Le modalità Transparent, Learning e Defender non sono implementate. Light può applicare mitigazioni e non equivale a Transparent.
- Deep usa `verifyCredentialsTBD` e registra il successo prima di osservare il backend: gli eventi non dimostrano un'autenticazione reale.
- Greeting, comandi precedenti a LOGIN, quoted strings, literal e autenticazione SASL richiedono gestione conforme al protocollo.
- Il replay LOGIN ricostruisce le credenziali senza escaping appropriato.
- Il trust è globale per JA4: client diversi possono condividere la fingerprint.
- La coda piena scarta gli eventi senza bloccare; un errore di lookup Redis produce invece `false` e può aumentare il rischio.
- L'hot reload richiede ulteriori verifiche sul ciclo di vita della configurazione TLS condivisa e sulle impostazioni che necessitano ricreazione dei componenti.
- Mancano le metriche applicative e le politiche complete di rate limiting ed eccezioni.

Il prototipo richiede questi interventi prima dell'uso in produzione.

## Architettura concordata

Le responsabilità da mantenere distinte sono:
1. **Proxying**: TLS, connessioni e inoltro IMAP conforme.
2. **Osservazione**: segnali di connessione ed esiti reali del backend, senza alterare il flusso.
3. **Classificazione**: correlazione dei segnali e valutazione motivata del rischio.
4. **Enforcement**: applicazione della politica solo nella modalità Defender.
5. **Persistenza e osservabilità**: Redis per i dati operativi, log e metriche con raccolta limitata.

Questa separazione è logica; non prescrive nuovi package o dipendenze.

| Modalità concordata | Osservazione | Apprendimento Redis | Contromisure di rischio |
| --- | --- | --- | --- |
| Transparent | Metriche e diagnostica | Non richiesto | Nessuna |
| Learning | Traffico ed esiti reali | Sì | Nessuna |
| Defender | Segnali ed esiti reali | Secondo politica configurata | Rate limiting, rallentamento e blocco |

Le normali chiusure per errori di rete o protocollo restano distinte dalle contromisure. Il livello di ispezione e la modalità operativa sono dimensioni indipendenti. Compatibilità della configurazione, default, comportamento in caso di Redis indisponibile, limiti e whitelist richiedono specifiche e test nell'intervento implementativo.

## Decisioni e collaborazione

- [ADR 0001](adr/0001-shared-repository-context.md): GitHub come fonte condivisa.
- [ADR 0002](adr/0002-operating-modes.md): tre modalità operative indipendenti dal livello di ispezione.
- [AGENTS.md](../AGENTS.md): workflow e verifica per gli assistenti.
- [Istruzioni del progetto ChatGPT](chatgpt-project-instructions.md): testo da inserire nelle impostazioni del progetto.
