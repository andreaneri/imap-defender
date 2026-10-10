# TODO - Adaptive IMAP Proxy (imap-defender)

Questo documento traccia le attività rimanenti per portare l'applicazione da prototipo consolidato a componente pronto per il rilascio in produzione.

---

## 1. Prerequisiti Operativi e Avvio Immediato (Quick Start)
- [x] **Generazione certificati SSL/TLS di test**:
  - Eseguire `make certs` per creare `cert.pem` e `key.pem` richiesti da `config.yaml`.
- [x] **Resilienza / Fallback Database GeoIP (`GeoLite2-Country.mmdb`)**:
  - Rendere opzionale l'apertura del file `.mmdb` all'avvio in `main.go`.
  - Se il database non è presente sul filesystem: loggare un warning (`slog.Warn`) e adottare il country code di default `"ZZ"` anziché terminare il processo con errore fatale.
- [x] **Provisioning Database MaxMind reale**:
  - Fornire la procedura per il download e aggiornamento periodico (es. cron / script) del database MaxMind GeoLite2 in ambiente di produzione.

---

## 2. Autenticazione e osservazione degli esiti reali
- [ ] **Eliminazione della verifica locale delle credenziali** ([ADR 0003](docs/adr/0003-backend-authentication-authority.md)):
  - Rimuovere `verifyCredentialsTBD`, risposte di autenticazione sintetiche, replay LOGIN ricostruito e pesi di rischio basati su verifica locale.
  - Rimuovere l'ipotesi di connettori LDAP/AD e pre-screening account: l'autenticazione appartiene al backend IMAP.
- [ ] **Osservatore bidirezionale delle autenticazioni**:
  - Inoltrare byte invariati, incluso greeting, comandi preliminari e risposte tagged, osservando LOGIN e relativi esiti reali per sessione/tag.
  - Non conservare password né dati SASL sensibili; distinguere esiti indeterminati e coprire quoted strings, literal e AUTHENTICATE nei test.
  - In Transparent osservare senza enforcement o persistenza obbligatoria; in Learning alimentare Redis con eventi reali, in Defender usare i segnali secondo politica.
- [ ] **Test end-to-end con backend Dovecot**:
  - Configurare account di test e verificare OK/NO del backend, comandi preliminari, più autenticazioni e disconnessioni, senza alterare il flusso.

---

## 3. Robustezza del Servizio e Ciclo di Vita (Lifecycle)
- [x] **Graceful Shutdown (`SIGINT`, `SIGTERM`)**:
  - Intercettare `os.Interrupt` (`syscall.SIGINT`) e `syscall.SIGTERM`.
  - Chiudere ordinatamente il listener TCP (`listener.Close()`), impedendo nuove connessioni.
  - Svuotare la coda residua del canale asincrono Redis prima della chiusura del client (`rt.Close()`).
  - Attendere la conclusione delle goroutine di connessione attive con un timeout di grazia (es. 10 secondi tramite `context.WithTimeout` e `sync.WaitGroup`).
- [x] **Healthcheck di liveness per il container**:
  - Aggiungere un endpoint o controllo socket per il container (`docker-compose.yaml`); la readiness delle dipendenze è tracciata separatamente nella sezione Configurazione e Packaging.
- [x] **Chiusura affidabile del worker Redis**:
  - `RedisTracker.Close()` chiude la coda e il client immediatamente: il worker può ancora avere eventi da processare mentre il client è già chiuso. Interrompere gli ingressi, drenare la coda, attendere il worker e poi chiudere il client, con un limite di tempo e gestione dell'errore.
- [x] **Gestione degli errori del listener**:
  - `Start()` ripete `Accept()` senza uscire quando il listener è chiuso o restituisce un errore permanente. Gestire la chiusura e distinguere gli errori temporanei da quelli fatali.
- [x] **Chiusura delle connessioni relay**:
  - Nei relay bidirezionali, al termine di una delle due `io.Copy` l'altra direzione può restare bloccata. Propagare half-close quando supportato, chiudere le connessioni in modo coordinato e attendere entrambe le copie.
- [ ] **Protezione delle credenziali nei comandi IMAP**:
  - Il comando LOGIN ricostruito viene interpolato senza escaping. Implementare la codifica IMAP appropriata per virgolette e caratteri speciali e non registrare password o comandi che le contengono.

---

## 4. Correttezza del Protocollo e Backend
- [ ] **Allineamento del flusso IMAP in Deep Inspection**:
  - Il proxy invia un greeting sintetico senza leggere/inoltrare quello del backend e poi cerca LOGIN prima di inoltrare al backend i comandi preliminari. Implementare una state machine IMAP che preservi greeting, capability, comandi e risposte nel corretto ordine, oppure limitare esplicitamente i comandi supportati.
- [ ] **Parsing completo del comando LOGIN**:
  - `parseIMAPLogin` usa tokenizzazione per spazi e non implementa le stringhe IMAP quoted con escape o gli argomenti literal. Sostituirlo con parsing conforme al protocollo, applicare limiti espliciti a riga e credenziali e coprire i casi limite nei test.
- [ ] **Verifica e propagazione dell'esito del backend**:
  - In modalità Deep il proxy considera riuscita l'autenticazione quando il mock accetta le credenziali, ma non osserva la risposta tagged del backend; registra quindi successi falsi e non inoltra al client l'esito reale. Collegare la decisione e l'evento alla risposta del backend.
- [ ] **Preservazione dell'input quando LOGIN non è il primo comando**:
  - Il parser consuma fino a dieci righe e, se non trova LOGIN, la connessione viene chiusa; eventuali comandi già letti non raggiungono il backend. Definire il comportamento per sessioni che non inviano LOGIN subito e preservare tutti i byte letti.

---

## 5. Configurazione e Packaging
- [x] **Allineamento della versione Go del container**:
  - `go.mod` richiede Go 1.24.4; lo stage builder è stato aggiornato a `golang:1.24-alpine`.
- [x] **Validazione della configurazione all'avvio e al reload**:
  - Validare indirizzi, soglie, pesi, buffer Redis e percorsi richiesti prima di avviare o pubblicare una nuova configurazione. Il reload deve rifiutare configurazioni semanticamente non valide senza sostituire quella attiva.
- [x] **Impostazione sicura delle soglie**:
  - Rifiutare soglie non ordinate o fuori dall'intervallo del punteggio (0–100) e pesi negativi; attualmente lo YAML viene caricato senza validazione e tali valori possono rendere incoerenti le decisioni del Risk Engine.
- [ ] **Readiness delle dipendenze containerizzate**:
  - `docker-compose.yaml` avvia il proxy con `depends_on`, che non verifica la readiness di Redis o Dovecot. Aggiungere healthcheck e attesa/retry delle dipendenze, distinguendo i servizi necessari alla partenza da quelli necessari solo alle richieste.

---

## 6. Repository, CI/CD e Versionamento
- [x] **Inizializzazione Git**:
  - Eseguire `git init`.
  - Aggiungere il remote: `git remote add origin https://github.com/andreaneri/imap-defender.git`.
  - Impostare il branch principale (`main`).
- [ ] **Commit strategy iniziale**:
  - Separare commit di codice dai commit di documentazione (rispettando le memory policies).
  - Messaggi di commit in lingua inglese.
- [x] **File `README.md` principale**:
  - Redigere una guida introduttiva di alto livello con: descrizione del progetto, architettura concettuale, requisiti, comandi rapidi di avvio (`make help`, `make certs`, `make up`), e puntamento a `docs/DOCUMENTAZIONE.md`.
- [x] **GitHub Actions / Pipeline CI**:
  - Creare workflow `.github/workflows/ci.yml` per validare automaticamente su ogni PR/push:
    - Linting (`golangci-lint` o `go vet`).
    - Test di unità e integrazione con race detector (`make test`).
    - Build binari statici (`make build-linux`).

---

## 7. Metriche e Osservabilità Avanzata
- [ ] **Endpoint Metriche Prometheus**:
  - Esportare metriche chiave su porta HTTP interna (es. `:9090/metrics`):
    - Connessioni TCP totali e attive.
    - Distribuzione azioni Risk Engine (`ALLOW`, `TARPIT_SOFT`, `TARPIT_HARD`, `DROP`).
    - Tempi di permanenza nei tarpit.
    - Dimensione della coda bufferizzata Redis e dropped logs counter.
- [ ] **Dashboard Grafana / Template Loki**:
  - Fornire dashboard preconfigurate per visualizzare in tempo reale gli eventi estratti dai log JSON (`log/slog`).

---

## 8. Evoluzione architetturale
- [ ] **Separazione delle responsabilità in package Go**:
  - Rifattorizzare progressivamente l'attuale `main.go`, mantenendo `package main` come punto di ingresso e composition root.
  - Individuare confini coerenti per protocollo IMAP, proxy/TLS e relay, osservazione, risk engine, Redis e configurazione, senza imporre un package per ciascuna responsabilità prima dell'analisi delle dipendenze.
  - Evitare package generici come `utils`, interfacce premature e dipendenze circolari; mantenere API interne minime.
  - Procedere per piccoli commit senza cambiamenti funzionali, spostando e adattando i test insieme al codice; verificare `make test`, `make build-local`, `make build-linux` e `go vet ./...`.
  - Pianificare la sequenza rispetto alle correzioni del protocollo IMAP e all'implementazione delle modalità operative, evitando di mescolare refactoring e nuove funzionalità nella stessa PR.
- [ ] **Implementazione delle modalità operative** ([ADR 0002](docs/adr/0002-operating-modes.md)):
  - Definire compatibilità e migrazione della configurazione da `deep_inspection_mode`, valori predefiniti e comportamento in caso di Redis indisponibile.
  - Implementare Transparent senza mitigazioni deliberate, Learning con osservazione degli esiti reali e apprendimento Redis, Defender con enforcement configurabile.
  - Aggiungere test di protocollo, concorrenza, timeout e comportamento per ciascuna modalità.
