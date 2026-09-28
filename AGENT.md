# AGENT.md - Guida Operativa per Agenti AI

Questo documento fornisce il contesto tecnico, le convenzioni architetturali e i vincoli operativi per qualsiasi agente AI che collabora sullo sviluppo e manutenzione della codebase **`imap-defender`**.

---

## 1. Panoramica del Progetto
**`imap-defender`** è un reverse proxy inverso perimetrale ad alte prestazioni scritto in Go per il protocollo IMAP4rev1 su TLS standard (porta `:993`). Il suo obiettivo primario è proteggere i server IMAP a valle (es. Dovecot) da attacchi di forza bruta, credential stuffing, password spraying e scansioni automatizzate attraverso:
1. **Fingerprinting crittografico TLS JA4+** all'handshake tramite callback nativo (`crypto/tls.GetConfigForClient`).
2. **Mitigazione proattiva tramite Tarpitting** (`time.Sleep` super-lineare) e `DROP` prima di contattare il backend.
3. **Modalità duale configurabile**:
   - *Light Mode*: protezione perimetrale pura a Layer 4 (solo JA4 + GeoIP), zero overhead applicativo.
   - *Deep Inspection Mode*: ispezione applicativa inline a Layer 7 del comando `TAG LOGIN`, con replay trasparente al backend e buffer alignment.
4. **Adaptive Risk Scoring Engine euristico**: valutazione multi-segnale (JA4 noto/ignoto, GeoIP anomalo, esistenza account, validità password) con score normalizzato 0-100.
5. **Persistenza asincrona non bloccante su Redis**: coda bufferizzata con principio *fail-open* sui log e pipelining dei comandi.
6. **Zero-downtime Hot Reload POSIX**: intercettazione segnale `SIGHUP` con gestione atomica Copy-on-Write (`atomic.Value`) e ricarica a caldo di configurazione, certificati TLS e database GeoIP.

---

## 2. Stack Tecnologico e Dipendenze
- **Linguaggio**: Go 1.24+ (ottimizzato e compatibile con Go 1.27: zero allocazioni sullo stack, memory allocator size-specialized).
- **Modulo Go**: `github.com/andreaneri/imap-defender`.
- **Librerie esterne autorizzate**:
  - `github.com/exaring/ja4plus`: calcolo del fingerprint crittografico TLS JA4 (accetta `*tls.ClientHelloInfo`).
  - `github.com/oschwald/geoip2-golang`: lookup geolocalizzazione MaxMind GeoIP2 in memory-mapping (`mmap`).
  - `github.com/redis/go-redis/v9`: client Redis con supporto pipeline, hash e context timeout.
  - `gopkg.in/yaml.v3`: parsing dichiarativo della configurazione YAML.
- **Logging**: pacchetto nativo `log/slog` della standard library con handler JSON su `os.Stdout`. **Non utilizzare pacchetti log obsoleti né librerie esterne non necessarie.**

---

## 3. Mappa dei File e Struttura del Repository
```text
imap-defender/
├── main.go               # Codice sorgente applicativo monolitico e strutturato
├── main_test.go          # Suite di unit test, integration test in-memory e benchmark
├── config.yaml           # Configurazione dichiarativa runtime (server, redis, logging, security)
├── Makefile              # Comandi standardizzati del ciclo di vita (build, test, bench, up, down, reload)
├── Dockerfile            # Multi-stage build (golang:alpine -> scratch minimale)
├── docker-compose.yaml   # Stack container (imap-proxy, imap-redis, imap-backend) con supporto Podman
├── .dockerignore         # Esclusioni per il build context
├── go.mod / go.sum       # Definizione modulo e checksum delle dipendenze
├── TODO.md               # Backlog delle attività e priorità di implementazione
├── AGENT.md              # Questo documento (guida per agenti AI)
└── docs/
    ├── DOCUMENTAZIONE.md # Documentazione tecnica, architetturale ed operativa consolidata
    └── processed/        # Archivio storico immutabile dei documenti di analisi originali (#1 - #24)
```

---

## 4. Regole Fondamentali e Convenzioni Ingegneristiche

### 4.1 Lingua e Comunicazione
- **Risposte all'utente**: rigorosamente in **italiano**.
- **Commenti nel codice**: rigorosamente in **inglese** (`// English comments only`).
- **Messaggi di commit Git**: rigorosamente in **inglese** (es. `feat: add graceful shutdown for SIGINT and SIGTERM`).

### 4.2 Strategia di Versionamento e Commit
- **Separazione codice / documentazione**: separare SEMPRE le modifiche al codice sorgente dalle modifiche alla documentazione in commit distinti.
- **Non rompere la compilabilità**: ogni commit sul codice deve compilare senza errori ed eseguire con successo `make test`.

### 4.3 Standard di Verifica (Validation Mandatory)
- **Utilizzare sempre i target del `Makefile`**:
  - `make test`: esegue gli unit e integration test con il **Race Detector** (`go test -race -v .`).
  - `make bench`: esegue i benchmark con conteggio allocazioni (`go test -bench=. -benchmem -run=^$ .`).
  - `make build-local`: compila il binario per l'architettura host corrente.
  - `make build-linux`: cross-compila il binario statico autonomo per produzione Linux AMD64 (`CGO_ENABLED=0`).
  - `make reload`: testa l'invio del segnale `SIGHUP` per l'hot reload.

### 4.4 Principi Architetturali da Rispettare
1. **Thread-Safety e Zero Race Conditions**:
   - Qualsiasi lettura/scrittura di configurazione runtime DEVE passare attraverso `atomicCfg.Load()` e `atomicCfg.Store()`.
   - L'accesso al certificato TLS o al database GeoIP DEVE essere protetto da `p.mu.RLock()` / `p.mu.RUnlock()`.
   - Il passaggio del fingerprint JA4 tra l'handshake e la goroutine di sessione DEVE usare `sync.Map` indicizzata per `remoteAddr`.
2. **Principio Fail-Open sulla Telemetria**:
   - Mai bloccare o rallentare una connessione IMAP se Redis rallenta o la coda è piena: adottare sempre `select { case rt.eventQueue <- event: default: slog.Warn(...) }`.
3. **Buffer Alignment e Preservazione del Protocollo IMAP**:
   - Al momento dell'hand-off verso il backend dopo il parsing del login, inoltrare SEMPRE `clientReader` (`io.Copy(backendConn, clientReader)`) per non perdere byte già letti nel buffer.
   - Preservare rigorosamente il `Tag` inviato dal client in tutte le risposte simulate (`TAG NO ...`).
4. **Gestione delle Risorse di Rete e File Descriptor**:
   - Ogni risorsa aperta (`net.Conn`, `Reader`, `mmap`, `File`) deve prevedere una chiusura ordinata (`defer Close()`).
   - Nel ricaricamento del database GeoIP (`SIGHUP`), chiudere esplicitamente il vecchio descriptor (`oldGeoDB.Close()`) dopo l'aggiornamento del puntatore per prevenire file descriptor leak.

---

## 5. Come Estendere la Codebase

Quando ti viene richiesto di implementare una nuova funzionalità (ad es. da `TODO.md`):
1. **Verifica preventiva**: consulta `docs/DOCUMENTAZIONE.md` e `main.go` per comprendere il modulo impattato.
2. **Modifiche chirurgiche**: applica modifiche mirate senza riscrivere sezioni non correlate.
3. **Aggiornamento Test**: per ogni modifica logica a `EvaluateRisk` o `parseIMAPLogin`, aggiorna i relativi table-driven test in `main_test.go`.
4. **Allineamento Documentazione**: rifletti ogni modifica strutturale o di configurazione in `docs/DOCUMENTAZIONE.md`.
5. **Validazione finale**: esegui `make test` e `make bench` per certificare che non vi siano regressioni né race condition.
