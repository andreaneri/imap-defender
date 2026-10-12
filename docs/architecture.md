# IMAP Defender — Architettura e stato

## Riferimento

Questa fotografia descrive il runtime e il pacing account-aware della PR #10 (`feat/account-response-enforcement`). [DOCUMENTAZIONE.md](DOCUMENTAZIONE.md) conserva la guida estesa; [TODO.md](../TODO.md) raccoglie il backlog.

## Implementazione attuale

Il proxy termina TLS, calcola JA4, usa GeoIP opzionale e inoltra byte IMAP invariati al backend TCP. L'osservatore passivo correla LOGIN/AUTHENTICATE e OK/NO/BAD/INDETERMINATE, estraendo username e authzid per LOGIN atom/quoted/literal e SASL PLAIN/LOGIN. Conserva fino a 64 tentativi, tag di 128 byte e identità di 1024 byte; non conserva password, token o payload completi. Ambiguità, BYE e chiusura finalizzano i pendenti come indeterminati senza alterare il relay.

`security.mode` seleziona Transparent (default), Learning o Defender. Transparent osserva e logga senza accedere a Redis né mitigare. Learning persiste asincronicamente eventi reali senza classificare o mitigare. Defender legge lo storico JA4/IP e applica il Risk Engine preesistente prima del relay, con tarpit/DROP configurabili; persiste gli stessi eventi. La PR #8 aggiunge un token bucket locale per IP (disabilitato di default), eccezioni CIDR e contatori Redis di fallimento per username/IP. La PR #10 collega al relay il pacing opt-in dei soli completamenti tagged NO/BAD con authcid nota, secondo ADR 0009.

Redis conserva l'ultima osservazione per identità/origine/metodo con TTL 7 giorni e un segnale di successo JA4/IP con TTL 24 ore. OK con identità nota crea il segnale; gli altri esiti restano distinti. Nessuna whitelist globale, nessuna lettura delle vecchie chiavi di trust. Il lookup Defender ha timeout 200 ms e fallisce aperto sull'intera decisione; le scritture non bloccano i client, possono essere perse e sono transazionali con TTL. Vedere [ADR 0005](adr/0005-mode-runtime-and-learning.md) per schema, migrazione, retention e limiti.

La modalità è fissata per sessione. SIGHUP può cambiarla per nuove connessioni, ma non può cambiare le risorse Redis o il listener. TLS usa una nuova configurazione clonata al reload. Test con race detector coprono relay TLS, coda, decisioni, timeout e cancellazione usando backend e peer RESP controllati. Il collaudo Dovecot/Redis reali rimane aperto.

## Decisione di autenticazione

[ADR 0003](adr/0003-backend-authentication-authority.md) è applicato nella rimozione del mock e nell'inoltro degli esiti reali; l’integrazione con le modalità operative è implementata nei limiti descritti sopra.

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

Le normali chiusure per errori di rete o protocollo restano distinte dalle contromisure. Il livello di ispezione e la modalità operativa sono dimensioni indipendenti. Configurazione, default, Redis e limiti sono specificati in ADR 0005. Rate limiting per IP o JA4/IP ed eccezioni CIDR sono implementati. La PR #10 aggiunge il pacing account-aware delle risposte negative; il meccanismo dei blocchi account/JA4/country resta da specificare.

## Decisioni e collaborazione

- [ADR 0001](adr/0001-shared-repository-context.md): GitHub come fonte condivisa.
- [ADR 0002](adr/0002-operating-modes.md): tre modalità operative indipendenti dal livello di ispezione.
- [ADR 0004](adr/0004-account-authentication-signals.md): identità dichiarate e segnali di autenticazione, con limiti e assenza di segreti.
- [ADR 0003](adr/0003-backend-authentication-authority.md): il backend autentica, il proxy osserva.
- [AGENTS.md](../AGENTS.md): workflow e verifica per gli assistenti.
- [Istruzioni del progetto ChatGPT](chatgpt-project-instructions.md): testo da inserire nelle impostazioni del progetto.

- [ADR 0005](adr/0005-mode-runtime-and-learning.md): modalità runtime, migrazione e apprendimento Redis.

- [ADR 0006](adr/0006-defender-ip-rate-limiting.md): rate limiting per IP e gestione della capacità.
- [ADR 0007](adr/0007-account-failure-counters.md): contatori di fallimento per username/IP.

## Pacing account-aware nel relay (PR #10)

`security.account_pacing.enabled` è false per default e agisce soltanto in Defender. La configurazione è fissata per sessione. Il gate usa le identità e il framing dell'osservatore, traccia fino a 64 tag di tutti i comandi e applica la politica solo dopo un NO/BAD autentico. LOGIN atom/quoted/literal e SASL PLAIN/LOGIN sono supportati; cancellazioni, identità sconosciute, ambiguità, COMPRESS/STARTTLS e meccanismi SASL non supportati bypassano il pacing.

Il gate inoltra immediatamente ogni prefisso e trattiene solo il LF finale che completa la risposta negativa. Il budget massimo include la lettura Redis (al più 200 ms); nessuna risposta completa è ricostruita. Nuovo traffico client/backend, pipeline pendenti, EOF, errori, scritture non concluse o capacità esaurita causano fail-open. Le altre risposte non vengono trattenute dietro un timer e l'ordine è preservato. Non si implementano blocchi, risposte sintetiche o whitelist JA4.

La lettura storica precede l'accodamento dell'evento corrente. UNKNOWN non riceve pacing; per KNOWN un'origine priva di successo storico può ricevere pacing soft, con escalation sui fallimenti globali account/JA4. Il successo della stessa origine riduce il sospetto sotto soglia, senza esentare fallimenti ripetuti o L1. I timer e le letture concorrenti condividono un limite per processo e non mantengono lock dell'osservatore.

I test con race detector includono TLS reale e peer IMAP/RESP controllati, frammentazione, literal, SASL, byte invariati, pipelining, timeout, cancellazione, half-close, short write ed errori di destinazione. Una prova ripetuta 20 volte verifica concorrenza e rilascio delle risorse. Redis/Dovecot reali e compatibilità dei client restano da collaudare. Configurazione, limiti, metriche e risultati sono in [account-response-pacing.md](account-response-pacing.md).
