# Adaptive IMAP Proxy - Documentazione Architetturale e Tecnica

> **Nota di aggiornamento:** [ADR 0003](adr/0003-backend-authentication-authority.md) elimina dall'architettura obiettivo l'autenticazione locale e il pre-screening LDAP/AD. Il backend IMAP è l'unica autorità di autenticazione; il proxy osserverà passivamente richieste e risposte reali già in Transparent. I riferimenti sottostanti a verifica credenziali locale, `UserExists`/`PasswordValid` e risposte LOGIN sintetiche descrivono esclusivamente il prototipo attuale e **non sono indicazioni implementative**. La riscrittura tecnica delle sezioni di protocollo e scoring accompagnerà la modifica del runtime.
>
> Per la fotografia del comportamento implementato, i limiti e le modalità concordate consultare [architecture.md](architecture.md). Questa guida contiene anche descrizioni progettuali: verificarle rispetto al codice corrente. Le decisioni condivise sono negli [ADR](adr/README.md).

## Indice dei Contenuti
1. [Visione Generale dell'Architettura](#1-visione-generale-dellarchitettura)
2. [Ciclo di Vita della Connessione e Fingerprinting TLS (JA4+)](#2-ciclo-di-vita-della-connessione-e-fingerprinting-tls-ja4)
3. [Rate Limiting e Strategia di Tarpitting](#3-rate-limiting-e-strategia-di-tarpitting)
4. [Parsing del Protocollo IMAP Inline](#4-parsing-del-protocollo-imap-inline)
5. [Adaptive Risk Scoring Engine](#5-adaptive-risk-scoring-engine)
6. [Persistenza e Tracciamento Asincrono (Redis)](#6-persistenza-e-tracciamento-asincrono-redis)
7. [Configurazione, Sicurezza e Hot Reload](#7-configurazione-sicurezza-e-hot-reload)
8. [Deployment, Monitoraggio e Testing](#8-deployment-monitoraggio-e-testing)

---

## 1. Visione Generale dell'Architettura

L'Adaptive IMAP Proxy è uno scudo perimetrale inverso (Reverse Proxy TLS) progettato per posizionarsi davanti a un server IMAP a valle (es. Dovecot). Il suo scopo è proteggere il backend da attacchi di forza bruta, credential stuffing, password spraying e scansioni automatizzate attraverso:
- Ispezione crittografica del traffico TLS (fingerprint JA4+).
- Rate limiting adattivo e tarpitting progressivo.
- Ispezione applicativa opzionale dei comandi di autenticazione IMAP (`LOGIN`).
- Valutazione multi-segnale del rischio tramite Risk Engine euristico.
- Persistenza asincrona non bloccante su Redis.

### 1.1 Topologia di Rete e Tunneling Bidirezionale
Il proxy si posiziona come terminatore TLS primario (default `:993`), intercetta l'handshake e, qualora la connessione superi i controlli di sicurezza, stabilisce una connessione TCP/TLS verso il server IMAP di backend (es. `127.0.0.1:143`):

```text
[Client IMAP]
     │ (Connessione TLS porta 993)
     ▼
┌────────────────────────────────────────┐
│        ADAPTIVE IMAP PROXY (Go)        │
│  1. Terminazione TLS                   │
│  2. Calcolo Fingerprint JA4            │
│  3. Valutazione Rate Limit / Risk      │
└────────────────────────────────────────┘
     │ (Inoltro TCP/TLS verso backend)
     ▼
[Server IMAP Backend] (es. Dovecot 127.0.0.1:143)
```

Il port-forwarding trasparente viene realizzato mediante inoltro concorrente bidirezionale dei flussi:
```go
go io.Copy(backendConn, tlsConn)
io.Copy(tlsConn, backendConn)
```

### 1.2 Mappa Funzionale dei Macro-Moduli
L'architettura è strutturata in 5 componenti modulari coordinati da una configurazione centrale caricata a caldo:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                          CONFIGURAZIONE YAML                            │
│           (Gestione Porte, Indirizzi, Pesi del Rischio e Modalità)     │
└─────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
 1. PROXY & INTERCETTORE TLS  ◄─────────────►  5. HOT RELOAD ENGINE
 ──► Accetta connessioni TCP                   ──► Ascolta segnali SIGHUP
 ──► Estrae Grezzo JA4 (ja4plus)               ──► Aggiorna parametri atomici
 ──► Mappa concorrente IP <-> JA4              ──► Sostituisce Certificati SSL
                                     │
                                     ▼
 2. INLINE IMAP PARSER (Opzionale / Configurabile)
 ──► Sospende il flusso, invia il Greeting IMAP
 ──► Intercetta `TAG LOGIN username password` (Protezione DoS/Buffer)
                                     │
                                     ▼
 3. ADAPTIVE RISK ENGINE
 ──► Correlazione dei 4 Segnali (JA4, GeoIP, Utenza, Password)
 ──► Calcolo Score (0-100) ──► Decisione (Allow, Tarpit Soft/Hard, Drop)
                                     │
                                     ▼
 4. ASYNC REDIS TRACKER
 ──► Pipeline non bloccante su coda Goroutine (Fail-Open sui log)
 ──► Whitelist JA4 Fidati (30gg) & Storico analitico dell'ultimo login (7gg)
```

---

## 2. Ciclo di Vita della Connessione e Fingerprinting TLS (JA4+)

### 2.1 Integrazione nel ciclo di vita della connessione
Per estrarre il fingerprint JA4 senza bloccare l'handshake e senza riscrivere uno stack TLS custom, il proxy sfrutta i callback nativi del pacchetto Go `crypto/tls` (nello specifico `GetConfigForClient`).

Il ciclo di vita di ciascuna connessione segue questa sequenza:
1. **TCP Handshake**: Il client stabilisce la connessione TCP grezza con il listener del proxy.
2. **TLS ClientHello**: Il client trasmette il record iniziale contenente le sue capacità crittografiche (cipher suites, estensioni, signature algorithms).
3. **Intercettazione tramite `GetConfigForClient`**: Il callback di `tls.Config` viene scatenato *dopo* la ricezione del `ClientHello` ma *prima* che il server invii il `ServerHello`. Restituire `nil, nil` indica a Go di utilizzare la configurazione TLS di default, evitando la creazione di configurazioni per-connection ad alto overhead.
4. **Calcolo del Fingerprint JA4**: Dal parametro `tls.ClientHelloInfo`, il proxy invoca direttamente `ja4plus.JA4(hello)`. La libreria JA4 analizza TLS version, cipher suites, estensioni ed eventuali protocolli ALPN ordinando i valori per calcolare il digest deterministico.
5. **Esecuzione sincrona dell'handshake**: In `handleConnection`, viene invocato esplicitamente `tlsConn.Handshake()`. Questo isola la logica di sicurezza crittografica da quella applicativa del protocollo IMAP prima di qualsiasi operazione di I/O.
6. **Passaggio dati e contestualizzazione**: Poiché `GetConfigForClient` non ha accesso diretto al context della goroutine di connessione, il passaggio del fingerprint JA4 alla logica di routing/decisione viene delegato a una mappa concorrente indicizzata per indirizzo remoto del client (`RemoteAddr`).

### 2.2 Anatomia del Fingerprint JA4
Una stringa JA4 generata (es. `t13d151600_c02f,c030_001d,0017,0018`) si compone di tre sezioni strutturate:
- `t13d151600`: Protocollo e setup (TLS 1.3, presenza SNI, numero di cipher suite ed estensioni).
- `c02f,c030`: Troncamento ordinato delle cipher suites offerte dal client.
- `001d,0017,0018`: Troncamento ordinato delle estensioni e algoritmi supportati.

---

## 3. Rate Limiting e Strategia di Tarpitting

### 3.1 Design a Sliding Window
Invece di un approccio Fixed Window (soggetto a picchi ai confini della finestra temporale), il proxy adotta una Sliding Window Counter approssimata in memoria, gestita dalla struttura `JA4TarpitLimiter` e protetta da lock a grana fine (`sync.RWMutex` sulla mappa dei bucket e `sync.Mutex` per singolo `WindowBucket`).

Il calcolo della frequenza stimata per ciascun fingerprint JA4 si basa sulla sovrapposizione tra la finestra precedente e quella corrente:
```go
weight := float64(tl.window - elapsed) / float64(tl.window)
estimatedCount := float64(bucket.prevCount)*weight + float64(bucket.currentCount)
```

Per prevenire memory leak derivanti da fingerprint JA4 temporanei o generati da scanner usa-e-getta, un worker di cleanup in background (`startCleanupWorker`) gira periodicamente (es. ogni 10 minuti) eliminando i bucket inattivi da più del doppio della finestra (`elapsed > window * 2`).

### 3.2 Fasi di Mitigazione e Tarpitting Progressivo
Il Rate Limiter valuta il JA4 e categorizza la richiesta su quattro livelli progressivi:
1. **Fase Verde (Sotto `SoftLimit`)**: Traffico considerato regolare, nessun ritardo introdotto (`delay = 0`), inoltro immediato al backend.
2. **Fase Gialla (Superamento `SoftLimit`)**: Il client inizia ad accelerare in modo anomalo. Viene applicata una penalità temporale minima per assorbire la raffica.
3. **Fase Arancione (Tarpitting Aggressivo)**: All'aumentare dell'eccedenza rispetto alla soglia soft, il ritardo cresce in modo super-lineare:
   $$\text{delay} = \text{BaseDelay} \times (\text{excess} \times 1.5)$$
   Viene imposto un limite massimo di salvaguardia (es. 15 secondi) per impedire il trattenimento indefinito delle goroutine.
4. **Fase Rossa (`estimatedCount >= HardLimit`)**: Raggiunta la soglia critica di abuso, la connessione viene troncata istantaneamente (`DROP`) senza raggiungere il backend.

### 3.3 Collocazione Strategica del Ritardo (`time.Sleep`)
L'iniezione del ritardo artificiale avviene in `handleConnection` **dopo** il completamento dell'handshake crittografico TLS ma **prima** dell'apertura del socket TCP (`net.DialTimeout`) verso il backend IMAP. In questo modo:
- I bot e gli scanner mantengono i propri socket/thread impegnati in attesa della risposta.
- Il server di posta vero e proprio a valle (Dovecot) non alloca alcuna risorsa per le connessioni sotto tarpit.
- L'overhead sul proxy Go è limitato a pochi kilobyte di memoria per goroutine sospesa.

---

## 4. Parsing del Protocollo IMAP Inline

### 4.1 Relay e osservazione passiva

`relayObserved` inoltra il greeting, i comandi e le risposte originali. Il backend è l’unica autorità di autenticazione: nessuna verifica locale, risposta sintetica o ricostruzione di LOGIN. L’osservatore registra solo metodo ed esito, senza account, password o payload SASL. Non alimenta ancora Redis.

Il writer osserva i byte prima della scrittura al peer, affinché una risposta immediata non preceda la registrazione del tag. Un errore di scrittura termina il relay e finalizza le autenticazioni senza risposta conclusiva come `INDETERMINATE`.

### 4.2 Framing dei literal e SASL

Il parser streaming riconosce marker finali `{n}`, `{n+}` e `~{n}`, contando e saltando esattamente i byte del literal in entrambe le direzioni, anche attraverso frammenti TCP. Le righe che proseguono un literal non diventano nuovi comandi. I marker nelle stringhe quoted del client sono ignorati; gli escape sono gestiti senza conservare gli argomenti.

Durante AUTHENTICATE vengono ignorati gli argomenti iniziali, le risposte successive e la cancellazione `*`; le challenge `+` del server non vengono conservate. Solo la risposta tagged OK/NO/BAD conclude l’osservazione del tentativo. Il parser non decodifica i meccanismi SASL.

### 4.3 Limiti e risultati indeterminati

Sono conservati soltanto i primi due token del framing: tag fino a 128 byte, verbo fino a 16 byte; al massimo 64 autenticazioni pendenti. Le lunghezze dei literal usano un contatore uint64 con controllo overflow e non determinano allocazioni del corpo. Anche argomenti molto lunghi vengono attraversati senza essere copiati.

Tag pendenti duplicati, superamento dei limiti, marker incompleti, framing CRLF non valido o perdita di sincronizzazione sospendono l’osservazione per tutta la sessione. I tentativi pendenti diventano `INDETERMINATE`; il relay continua invariato. Una risposta anticipata mentre il client è ancora nel framing di un literal conserva il risultato reale ma sospende l’osservazione successiva. BYE e chiusura del relay finalizzano i tentativi pendenti una sola volta. BAD resta distinto da NO e da un successo.

Il parser è deliberatamente conservativo: non è un validatore IMAP completo, non decodifica traffico compresso né livelli di sicurezza negoziati da SASL. Il limite del tag riguarda solo la telemetria e non rifiuta il traffico. La callback interna deve restare breve; la persistenza Learning richiederà una coda non bloccante.

### 4.4 Verifica e modalità operative

`observer_test.go` copre literal e payload contraffatti, frammentazione fino al singolo byte, quoted strings, SASL, limiti e finalizzazione. `main_test.go` verifica l’inoltro byte per byte; il collaudo con Dovecot resta nel TODO.

Transparent, Learning e Defender sono ancora da implementare. L’osservatore non applica contromisure, ma la valutazione del rischio per connessione precedente al relay può ancora ritardare o bloccare: il comportamento complessivo non è ancora Transparent.

---

## 5. Adaptive Risk Scoring Engine

### 5.1 Matrice di Decisione Basata su Reputazione e Comportamento
La classificazione del traffico correla lo stato crittografico dello stack TLS (JA4) con l'esito dell'autenticazione applicativa:

| Stato JA4 + Esito Credenziali | Profilo Comportamentale | Politica Applicata |
| :--- | :--- | :--- |
| **JA4 Conosciuto + Login OK** | Utente legittimo e client abituale | **ALLOW Istantaneo**: Inoltro diretto a bassissima latenza. |
| **JA4 Conosciuto + Login KO** | Utente reale con refuso nella password | **Tarpitting Lieve (2-3s)**: Rallentamento controllato a salvaguardia dell'esperienza utente. |
| **JA4 Sconosciuto + Login OK** | Nuovo client/dispositivo legittimo | **ALLOW + Trust Progressive**: Connessione permessa, fingerprint registrato per osservazione su Redis. |
| **JA4 Sconosciuto + Login KO** | Potenziale scanner o attacco a dizionario | **Tarpitting Aggressivo (10-15s)**: Trattenimento socket per saturare il client ostile. |
| **JA4 Anomalo Multi-Utente** | Attacco coordinato di Password Spraying | **Hard Block**: Taglio TCP immediato o drop al pre-handshake. |

### 5.2 Algoritmo di Scoring Euristico e Pesi di Rischio
Il proxy analizza i segnali in due momenti temporali distinti del ciclo di vita della connessione:

```text
  [ Client Connesso ]
          │
          ▼
┌─────────────────────────────────────────┐
│ FASE 1: PRE-LOGIN (Filtro di Rete)      │
│ 1. Verifica FP su Redis (Noto / Ignoto) │
│ 2. Geolocalizzazione IP (GeoIP)         │
└─────────────────────────────────────────┘
          │
          ▼ (Se il punteggio è parziale, riceve il comando LOGIN)
          ▼
┌─────────────────────────────────────────┐
│ FASE 2: POST-LOGIN (Filtro Applicativo) │
│ 3. Esistenza Utente (Pre-screening/LDAP)│
│ 4. Esito Password (LDAP binding)        │
└─────────────────────────────────────────┘
          │
          ▼
  [ Calcolo Score Finale ] ───► Scelta Azione (Allow / Tarpit / Drop)
```

Il punteggio totale ($S \in [0, 100]$) viene calcolato sommando algebricamente 4 fattori di rischio indipendenti:

1. **Stato del Fingerprint JA4**:
   - Non noto nella cache Redis (`!JA4Known`): $+25$ punti di sospetto base.
2. **Geolocalizzazione dell'IP**:
   - Provenienza estera o anomala (`CountryCode != "IT"` e `!= "ZZ"`): $+35$ punti.
3. **Pre-screening Esistenza Utenza (Anti-Scanning)**:
   - Username non censito (`!UserExists`): $+50$ punti (indicatore critico di brute-force o dizionario).
4. **Validità delle Credenziali (Password Binding)**:
   - Password non valida (`!PasswordValid`): $+30$ punti.
   - Password valida su utente esistente: $-20$ punti (sconto reputazionale per mitigare anomalie di geoIP, es. utenti in viaggio).

**Soglie di Mitigazione Dinamiche**:
- $S \ge 90$: **DROP** (Chiusura immediata del socket TCP, delay 0).
- $S \ge 60$: **TARPIT HARD** (Ritardo forzato di 12 secondi).
- $S \ge 30$: **TARPIT SOFT** (Ritardo forzato di 3 secondi).
- $S < 30$: **ALLOW** (Inoltro a latenza zero verso il backend).

### 5.3 Geolocalizzazione Reale in Memoria (MaxMind GeoIP2 / MMDB)
Per determinare la nazionalità dell'indirizzo IP di provenienza senza penalizzare la latenza con chiamate HTTP/DNS esterne, il proxy integra la libreria ad alte prestazioni `github.com/oschwald/geoip2-golang`:
- **Memory-Mapping (`mmap`)**: il database binario (es. `GeoLite2-Country.mmdb`) viene mappato nello spazio di memoria virtuale del processo, garantendo lookup istantanei nell'ordine delle decine di nanosecondi.
- **Isolamento Reti Private e Loopback**: prima di interrogare il database, gli indirizzi locali (`ip.IsLoopback()`) o appartenenti agli intervalli privati RFC 1918 (`ip.IsPrivate()`, come `127.0.0.1`, `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`) vengono intercettati e mappati sul codice convenzionale `"ZZ"`. In questo modo non subiscono penalità di rischio durante i test in laboratorio o in reti interne.
- **Database opzionale**: se il file configurato non esiste all'avvio o durante un reload `SIGHUP`, il proxy registra un warning e continua senza lookup GeoIP; gli indirizzi pubblici ricevono il codice `"ZZ"`, trattato come neutro dal Risk Engine. Errori diversi dall'assenza del file restano fatali all'avvio o annullano il reload, così un database corrotto non viene ignorato silenziosamente.
- **Ricarica a Caldo del Database senza Leak**: al ricevimento del segnale `SIGHUP`, il proxy apre la nuova istanza del database e, solo dopo aver aggiornato in modo thread-safe il puntatore `proxy.geoDB` sotto mutex, invoca `oldGeoDB.Close()`, prevenendo il consumo incontrollato di file descriptor.

#### Provisioning e aggiornamento di GeoLite2 Country

Per ambienti reali usare il database binario `GeoLite2-Country` e mantenere aggiornati i dati secondo i termini di licenza GeoLite. La procedura ufficiale è descritta nella [guida di aggiornamento MaxMind](https://dev.maxmind.com/geoip/updating-databases/) e nella [pagina GeoLite](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).

1. Creare un account MaxMind GeoLite e generare una license key. Trattarla come una password: non inserirla nel repository, in `config.yaml` o nei log.
2. Installare `geoipupdate` versione 4 o successiva secondo le istruzioni per il sistema operativo. Creare la directory `geoip/` accanto al `docker-compose.yaml` e configurare `/etc/GeoIP.conf` con permessi `0600`:

   ```text
   AccountID ACCOUNT_ID
   LicenseKey LICENSE_KEY
   EditionIDs GeoLite2-Country
   DatabaseDirectory /percorso/assoluto/imap-defender/geoip
   ```

   Sostituire i valori account e percorso con quelli dell'ambiente. La directory host `geoip/` è montata in sola lettura nel container su `/geoip`, percorso impostato in `config.yaml`.
3. Eseguire `geoipupdate` una prima volta e verificare la presenza di `geoip/GeoLite2-Country.mmdb`. Il proxy può avviarsi anche senza il file, ma in quel caso usa il country code neutro `ZZ`.
4. Pianificare `geoipupdate` almeno due volte a settimana, come suggerito da MaxMind. Dopo l'aggiornamento inviare `SIGHUP` al proxy (`make reload`) affinché apra il nuovo database. Esempio di crontab (adattare percorsi e utente):

   ```cron
   23 3 * * 2,5 /usr/bin/geoipupdate && cd /percorso/assoluto/imap-defender && make reload
   ```

5. Verificare i log del proxy: il reload riuscito viene registrato come completato; un file MMDB assente mantiene il fallback `ZZ`, mentre un file non valido fa fallire il reload e lascia in uso la configurazione/database attivi precedenti.

GeoLite è soggetto a licenza e attribuzione MaxMind; consultare la [licenza GeoLite](https://www.maxmind.com/en/geolite/eula) e verificare che il caso d'uso sia consentito.

---

## 6. Persistenza e Tracciamento Asincrono (Redis)

### 6.1 Architettura Non Bloccante e Principio Fail-Open
Per non vincolare la reattività della terminazione di rete alla latenza del database di cache, la persistenza su Redis (`github.com/redis/go-redis/v9`) è disaccoppiata tramite un canale Go bufferizzato (`eventQueue chan LoginEvent`) svuotato da worker dedicati in background.

In condizioni di picco estremo o di Redis degradato/offline:
- La chiamata `TrackEventAsync` adotta il pattern `select ... default`: se la coda è satura, il log viene scartato (*fail-open* sui log) evitando categoricamente di sospendere le goroutine che servono i client IMAP.
- La verifica preliminare sincrona (`IsJA4Trusted`) applica un timeout aggressivo di salvaguardia (200ms). In caso di timeout o errore di rete, scatta il default conservativo (`trusted = false`).
- Alla chiusura, il tracker rifiuta nuove scritture, drena la coda e attende il worker fino a 10 secondi; allo scadere annulla le operazioni pendenti, chiude il client Redis e registra quanti eventi erano ancora in coda.

### 6.2 Schema delle Chiavi e Pipelining
Per massimizzare il throughput e minimizzare i round-trip TCP verso il cluster/istanza Redis, le operazioni di scrittura vengono raggruppate in pipeline atomiche (`pipe.Exec(ctx)`):

1. **Whitelist JA4 Fidati**:
   - **Chiave**: `proxy:ja4:trusted:<ja4_hash>`
   - **Tipo**: String (`"1"`)
   - **TTL**: 30 giorni (rinnovato a ogni autenticazione riuscita `Success: true`).
2. **Storico Analitico Utente / Client**:
   - **Chiave**: `proxy:analytics:ja4:<ja4_hash>:user:<username>`
   - **Tipo**: Hash Redis (`HSet`)
   - **Campi**: `ip` (Remote IP), `esito` (`OK`/`KO`), `timestamp` (formato ISO/RFC3339).
   - **TTL**: 7 giorni (`Expire`).

---

## 7. Configurazione, Sicurezza e Hot Reload

### 7.1 Schema di Configurazione Esterna (`config.yaml`)
L'intero comportamento del proxy è controllato tramite un file di configurazione dichiarativo `config.yaml` caricato tramite la libreria `gopkg.in/yaml.v3`. Questo evita ricompilazioni del codice per modificare indirizzi, porte, modalità di ispezione o pesi di rischio.

Lo schema è articolato in 3 macro-sezioni:
- **`server`**: indirizzo di bind (`listen_addr`), endpoint backend Dovecot (`backend_imap_addr`), percorsi certificato e chiave TLS (`cert_file`, `key_file`).
- **`redis`**: endpoint Redis (`addr`) e dimensione buffer di coda eventi asincrona (`queue_buffer_size`).
- **`security`**:
  - `deep_inspection_mode`: booleano che commuta tra modalità perimetrale TLS e deep inspection IMAP.
  - `thresholds`: soglie di intervento per `tarpit_soft`, `tarpit_hard` e `drop`.
  - `weights`: pesi numerici per `ja4_unknown`, `geo_anomaly`, `user_not_found`, `password_invalid`, `login_success_discount`.

La funzione `LoadConfig(filename string) (*Config, error)` esegue la lettura e l'unmarshaling nel modello di strutture fortemente tipizzate Go (`Config`, `ServerConfig`, `RedisConfig`, `SecurityConfig`), poi valida i campi obbligatori, gli indirizzi TCP e la dimensione positiva della coda Redis. Le soglie devono rispettare `0 < tarpit_soft < tarpit_hard < drop <= 100`; ciascun peso deve essere compreso tra 0 e 100. La stessa validazione viene applicata durante `SIGHUP`, prima di pubblicare la configurazione ricaricata.

### 7.2 Zero-Downtime Hot Reload via Segnale POSIX SIGHUP
Per consentire l'aggiornamento delle policy, dei pesi di rischio, degli indirizzi e dei certificati crittografici TLS in produzione senza disconnettere i client attivi e senza riavviare il processo, il proxy adotta il meccanismo standard POSIX basato sull'intercettazione del segnale `SIGHUP` (`syscall.SIGHUP`).

1. **Prevenzione delle Race Condition tramite `atomic.Value`**:
   L'accesso alla configurazione runtime è incapsulato nella struttura `AtomicConfig`:
   ```go
   type AtomicConfig struct {
       value atomic.Value
   }
   func (ac *AtomicConfig) Store(cfg *Config) { ac.value.Store(cfg) }
   func (ac *AtomicConfig) Load() *Config     { return ac.value.Load().(*Config) }
   ```
   All'arrivo del segnale, un thread in background rilegge il file YAML in una nuova istanza isolata. Lo switch del puntatore tramite `atomic.Value.Store()` avviene in un singolo ciclo di clock (semantica Copy-on-Write): le connessioni in corso continuano a fare riferimento alla struct precedente, mentre le nuove connessioni adottano immediatamente i nuovi parametri.

2. **Sostituzione Runtime dei Certificati SSL/TLS**:
   Poiché la struttura `tls.Config` della libreria standard non è nativamente protetta da puntatori atomici, la rotazione dei certificati (`tls.LoadX509KeyPair`) è protetta da un `sync.RWMutex` su `IMAPProxy`:
   ```go
   proxy.mu.Lock()
   proxy.tlsConfig.Certificates = []tls.Certificate{cert}
   proxy.mu.Unlock()
   ```

3. **Resilienza e Rollback Automatico**:
   Se il nuovo file YAML contiene errori sintattici o i nuovi file di certificato non sono leggibili/validi, il ricaricamento viene abortito con log d'errore e il proxy mantiene intatta la configurazione precedente attiva, garantendo l'assoluta continuità operativa.

---

## 8. Deployment, Monitoraggio e Testing

### 8.1 Containerizzazione Multi-Stage e Immagine Minimalista `scratch`
Il deployment del proxy adotta il pattern multi-stage di Docker/Podman:
1. **Stage 1 (Builder)**: basato su `golang:alpine`, recupera i certificati CA di sistema e compila un binario monolitico statico privo di dipendenze C (`CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w"`).
2. **Stage 2 (Runtime)**: basato su un'immagine vuota `scratch` che ospita esclusivamente:
   - Il binario compilato `/imap-ja4-proxy`.
   - Il bundle dei certificati CA `/etc/ssl/certs/ca-certificates.crt`.
   - I file di configurazione (`config.yaml`) e le chiavi TLS montati come volumi esterni.

Questo setup offre:
- **Superficie d'attacco zero**: assenza totale di shell (`/bin/sh`, `bash`), package manager o utility di sistema, mitigando qualsiasi exploit di escape o execution.
- **Dimensione ridotta**: footprint complessivo del container di circa 15-20 MB.
- **Supporto all'Hot Reload in container**: invio del segnale direttamente tramite il runtime:
  ```bash
  docker kill --signal=HUP imap-proxy
  ```

### 8.2 Orchestrazione Locale con Docker Compose / Podman
Lo stack completo include 3 container interconnessi su una rete bridge isolata (`imap-net`):
1. **`imap-proxy`**: terminatore TLS, unico container ad esporre la porta `:993` verso l'host.
2. **`imap-redis`**: istanza `docker.io/library/redis:7-alpine`, non esposta verso l'host, accessibile solo sulla rete interna da `imap-proxy`.
3. **`imap-backend`**: istanza `docker.io/dovecon/dovecot:latest`, accessibile solo tramite `imap-proxy:143`.

#### Accorgimenti per Podman (Rootless & SELinux)
Per garantire la perfetta interoperabilità sia con Docker che con Podman (rootless):
- **Nomi immagini completamente qualificati (FQIN)**: es. `docker.io/library/redis:7-alpine` per evitare prompt interattivi del runtime agnostico di Podman.
- **Etichettatura SELinux (Flag `:Z`)**: aggiunto a ogni volume montato (`./config.yaml:/config.yaml:Z`) per permettere al container scratch/unprivileged di leggere i file senza violazioni *Permission Denied* su RHEL/Fedora/CentOS.
- **Porte privilegiate (< 1024) in Rootless**: la porta 993 richiede autorizzazione per utenti non-root. Su macchine Linux di test è possibile abbassare la soglia con:
  ```bash
  sudo sysctl net.ipv4.ip_unprivileged_port_start=993
  ```
  oppure mappare una porta non privilegiata sull'host (es. `- "8993:993"`).

Comandi di gestione:
```bash
# Docker o Podman
podman compose up -d --build   # oppure: docker compose up -d --build
podman compose logs -f imap-proxy
podman compose kill -s HUP imap-proxy
podman compose down
```

### Chiusura ordinata

Il processo intercetta `SIGINT` e `SIGTERM`. Alla ricezione del segnale smette di accettare connessioni, chiude i socket client attivi per sbloccare gli handler, interrompe i tarpit e attende gli handler fino a 10 secondi. Dopo l'arresto del listener, il tracker Redis svuota la coda fino a un ulteriore limite di 10 secondi prima di chiudere il client. Se uno dei limiti scade, registra un warning e procede con l'arresto.

Il servizio Compose usa `imap-ja4-proxy --healthcheck` come controllo di liveness: il comando legge e valida la configurazione e apre una connessione TCP loopback alla porta del proxy. Il probe verifica che il listener sia attivo; la readiness di Redis e Dovecot resta gestita dalle rispettive connessioni applicative.

Il relay IMAP mantiene aperte entrambe le direzioni fino al completamento dei flussi. Quando una direzione raggiunge EOF, inoltra l'half-close se la connessione lo supporta; in caso di errore chiude entrambi i socket per sbloccare la copia opposta. In modalità Deep il flusso client continua a partire dal `bufio.Reader` già usato dal parser, preservando i byte letti in anticipo.

### 8.3 Logging Strutturato JSON ad Alte Prestazioni (`log/slog`)
A partire dalla versione Go 1.21+, il proxy adotta il pacchetto nativo `log/slog` configurato con handler JSON su `os.Stdout`.

#### Campi Chiave Indicizzabili
I log emessi dal Risk Engine e dai worker di mitigazione contengono attributi tipizzati stabili, pronti per l'ingestione in pipeline SIEM (Grafana Loki, ELK, Datadog):
```json
{"time":"2026-09-26T18:32:15Z","level":"INFO","msg":"Risk Engine eseguito","remote_ip":"192.0.2.55:54122","score":60,"ja4_known":false,"country":"US"}
{"time":"2026-09-26T18:32:15Z","level":"INFO","msg":"Mitigazione Deep eseguita","remote_ip":"192.0.2.55:54122","username":"mario","action":"TARPIT_HARD","delay":12000000000}
```

- **Livello dinamico**: configurabile via YAML (`logging.level: "info" | "debug" | "warn" | "error"`).
- **Riconfigurazione a caldo**: modificando `logging.level` in `config.yaml` e inviando `SIGHUP`, la funzione `initLogger` riadatta istantaneamente la soglia minima di log senza riavviare il servizio.

### 8.4 Suite di Testing, Race Detector e Benchmark (`main_test.go`)
La qualità e le prestazioni del proxy sono verificate mediante test nativi Go (`testing`):

1. **Unit Test Table-Driven (`TestEvaluateRisk`)**:
   - Valuta i 4 scenari cardine: Utente Legittimo (`ALLOW`), Errore Password Utente Reale (`TARPIT_SOFT`), Botnet da IP estero su utente inesistente (`DROP`), Utente in roaming estero con credenziali corrette (`TARPIT_SOFT`).
2. **Integration Test In-Memory (`TestParseIMAPLogin`)**:
   - Emula il flusso del socket TCP/TLS tramite `strings.NewReader` e `bufio.Reader`.
   - Verifica comandi con/senza virgolette, comandi preliminari interlocutori (`CAPABILITY`, `NOOP`) e chiusure anticipate.
3. **Validazione Concorrente (Race Detector)**:
   - Eseguibile con `go test -race -v .` per certificare l'assenza di data race su `sync.Map`, `atomic.Value` e puntatori condivisi.
4. **Benchmark Prestazionali ad Alto Throughput (`Benchmark...`)**:
   - `BenchmarkEvaluateRisk`: tempo medio di calcolo di appena **~13.5 ns/op**, con **0 B/op** e **0 allocs/op** (calcolo interamente allocato sullo stack).
   - `BenchmarkParseIMAPLogin`: parsing completo ed estrazione token in **~0.2 µs/op** (220 ns/op) con sole 3 allocazioni minime per la sanitizzazione delle stringhe.
   - Comando di esecuzione: `go test -bench=. -benchmem -run=^$ .`

### 8.5 Compatibilità e Ottimizzazioni Go 1.27
L'architettura del software sfrutta nativamente i miglioramenti del runtime introdotti in Go 1.27:
- **Size-Specialized Malloc**: riduzione del 30% del costo di allocazione per oggetti a vita breve. Le struct di calcolo (`ClientContext`, `SecurityConfig`) beneficiano di zero allocazioni heap (`0 B/op`).
- **Garbage Collector ottimizzato per channel/buffer**: il riciclo rapido della struct `LoginEvent` dereferenziata dal worker Redis azzera i cicli di stop-the-world sotto carichi da migliaia di RPS.
- **Timer channels sincroni**: il proxy non soffre di leak legati ai vecchi comportamenti dei timer asincroni.

### 8.6 Automazione e Ciclo di Vita tramite Makefile
Il file `Makefile` alla radice standardizza l'intero workflow sia su macOS (Apple Silicon / Intel) sia in cross-compilazione per server Linux AMD64:
- `make init`: risoluzione e download dipendenze Go.
- `make certs`: generazione certificati autofirmati di test con OpenSSL (`cert.pem`, `key.pem`).
- `make test`: esecuzione unit/integration test con `-race`.
- `make bench`: esecuzione benchmark di velocità e allocazione memoria (`-benchmem`).
- `make build-local`: compilazione nativa per l'architettura host.
- `make build-linux`: cross-compilazione statica `CGO_ENABLED=0 GOOS=linux GOARCH=amd64` per produzione.
- `make up` / `make down`: orchestrazione dello stack multi-container (auto-detection Podman/Docker).
- `make reload`: invio del segnale POSIX `SIGHUP` per l'hot-reload live della configurazione e dei certificati.
- `make logs`: streaming dei log JSON strutturati in tempo reale.

### 8.7 Collaudo Operativo End-to-End con OpenSSL
Per testare manualmente le risposte del proxy, del Risk Engine e delle politiche di Tarpit/Drop senza ricorrere a un client di posta grafico, si utilizza `openssl s_client`:

```bash
openssl s_client -connect localhost:993 -crlf -quiet
```
*(Nota: il flag `-crlf` è obbligatorio per terminare ogni comando IMAP con `\r\n`).*

#### Scenari di Laboratorio:
1. **Utente Legittimo (`ALLOW`)**:
   - All'handshake, il proxy invia: `* OK [CAPABILITY IMAP4rev1] Adaptive IMAP Proxy Ready`
   - Invio comando: `A001 LOGIN mario segreta`
   - Risultato: Score basso (< 30), connessione immediatamente agganciata a Dovecot e fingerprint JA4 salvato nella whitelist Redis con TTL a 30 giorni.
2. **Utente Reale con Refuso nella Password (`TARPIT_SOFT`)**:
   - Invio comando: `A002 LOGIN mario password_sbagliata`
   - Risultato: Il terminale resta sospeso per **3 secondi**, trascorsi i quali riceve: `A002 NO Authentication failed.` e viene disconnesso. Score calcolato: 30 (JA4 noto 0, Geo IT 0, User trovato 0, Password KO +30).
3. **Attacco Botnet / Account Inesistente (`DROP` / `TARPIT_HARD`)**:
   - Invio comando: `A003 LOGIN admin password123`
   - Risultato: Con JA4 sconosciuto (+25), Geo anomala (+35) e account inesistente (+50), lo score raggiunge il cap di 100/100, scatenando il **`DROP` istantaneo** (chiusura del socket TCP senza output) oppure il `TARPIT_HARD` di 12 secondi.
