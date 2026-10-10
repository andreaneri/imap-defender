# IMAP Defender — Istruzioni per gli assistenti

## Repository e fonti di verità

- Repository: https://github.com/andreaneri/imap-defender
- Branch principale: `main`.
- Linguaggio e dipendenze: fare riferimento a `go.mod` e `go.sum`; non presumere versioni diverse.
- Licenza: fare riferimento a `LICENSE`.

All'inizio di ogni attività verificare il repository, il branch, il commit di partenza e i file coinvolti. Con checkout locale verificare anche `git status` e i remote; tramite connettore leggere il branch e fissare le letture al suo SHA. Non presumere che i contenuti esaminati in un'altra chat siano aggiornati.

Leggere [l'architettura](docs/architecture.md), [gli ADR](docs/adr/README.md) e le sezioni pertinenti di [DOCUMENTAZIONE.md](docs/DOCUMENTAZIONE.md) e [TODO.md](TODO.md). Il codice determina il comportamento implementato; i documenti distinguono stato attuale, decisioni e lavoro futuro.

## Obiettivo e modalità concordate

Proteggere il backend IMAP da attacchi automatizzati mantenendo la compatibilità con i client legittimi.

- **Transparent**: inoltra il traffico e raccoglie metriche e diagnostica, senza ritardi o blocchi deliberati.
- **Learning**: osserva traffico ed esiti reali delle autenticazioni e popola Redis, senza applicare contromisure basate sulle classificazioni.
- **Defender**: usa i segnali raccolti per applicare rate limiting, rallentamento, blocco ed eccezioni configurabili, con decisioni motivabili.

Queste tre modalità sono il progetto concordato, ancora da implementare. Il parametro attuale `security.deep_inspection_mode` seleziona Light o Deep Inspection: non rappresenta le tre modalità operative. Vedere [ADR 0002](docs/adr/0002-operating-modes.md).

## Principi tecnici

- Preferire Go e la libreria standard; limitare dipendenze e framework non necessari.
- Separare le responsabilità di proxying, osservazione, classificazione ed enforcement senza introdurre rifattorizzazioni non richieste.
- Trattare fingerprint TLS, IP, paese, account ed esito come segnali distinti. Una fingerprint TLS non identifica univocamente un client e un successo non giustifica una whitelist globale incondizionata.
- Il backend IMAP è l'unica autorità per l'autenticazione: nessuna verifica locale di credenziali, nessun connettore LDAP/AD di pre-screening e nessuna risposta LOGIN sintetica nel comportamento obiettivo. Osservare l'esito reale del backend senza modificare i byte ([ADR 0003](docs/adr/0003-backend-authentication-authority.md)); il mock attuale non è prova di autenticazione.
- Non registrare password, token, chiavi private o comandi contenenti credenziali. Ridurre i dati personali raccolti e documentare TTL e finalità.
- Preservare greeting, tag, capability, comandi, risposte e byte già letti nel buffer; quando appropriato, il relay deve usare il `bufio.Reader` esistente.
- Gestire timeout, connessioni, goroutine e cancellazione dei context; chiudere le risorse e attendere le copie del relay.
- Leggere/pubblicare la configurazione tramite `AtomicConfig`; rispettare la sincronizzazione delle risorse condivise. Verificare il ciclo di vita di `tls.Config` e GeoIP durante il reload senza presumere che un lock parziale elimini tutte le race.
- La coda di telemetria non deve bloccare le sessioni quando è piena. Distinguere questo requisito dalla politica sulle letture Redis per decisioni di rischio: timeout ed errori devono avere un comportamento esplicito e verificato.

## Workflow Git e collaborazione tra chat

- Usare branch dedicati; non modificare direttamente `main` senza richiesta esplicita.
- Non effettuare merge senza autorizzazione esplicita.
- Evitare di sovrascrivere modifiche altrui. Prima di aggiornare un branch remoto verificare il suo head; con API usare un controllo sullo SHA atteso.
- Preferire modifiche piccole e verificabili. Separare codice e documentazione in commit distinti.
- Documentare le decisioni durature nel repository e negli ADR. Le conversazioni non sostituiscono documentazione versionata.
- Una decisione architetturale che cambia deve avere un nuovo ADR che indica quale decisione sostituisce.
- Prima di proporre funzionalità, verificare se sono già presenti. Non ampliare lo scope senza necessità.

## Verifica

Per modifiche al codice usare i target del Makefile:
- `make test`: test con race detector.
- `make build-local` e `make build-linux`: build host e Linux.
- `make bench`: benchmark, richiesti per modifiche alla logica o ai percorsi che incidono sulle prestazioni.
- `go vet ./...`: controllo usato anche dalla CI.

Aggiornare i test pertinenti quando cambia la logica, in particolare `EvaluateRisk`, il parsing e il relay IMAP. Testare il reload in un ambiente locale controllato quando viene modificato; `make reload` invia SIGHUP al container locale.

Per modifiche esclusivamente documentali verificare link relativi, coerenza con il codice e assenza di marcatori di conflitto; non è necessario eseguire test o benchmark Go.

Non dichiarare test, commit, push o modifiche eseguiti senza verifica. Riportare eventuali controlli non eseguibili e il motivo.

## Comunicazione

Rispondere in italiano; mantenere identificatori, nuovi commenti nel codice e messaggi di commit in inglese. Spiegare risultato, verifiche e limiti concreti; distinguere ciò che è implementato da ciò che è pianificato.
