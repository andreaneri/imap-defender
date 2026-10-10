# IMAP Defender — Architettura e stato

## Riferimento

Questa fotografia descrive il codice al commit `1a5d536a1ea575256ee90072d3c160e93c2ace0f` di `main`. Va aggiornata quando cambia il comportamento. [DOCUMENTAZIONE.md](DOCUMENTAZIONE.md) conserva la guida tecnica e operativa estesa; [TODO.md](../TODO.md) raccoglie il backlog. Le descrizioni progettuali nella guida estesa vanno confrontate con il codice.

## Implementazione attuale (branch di lavoro)

Il proxy termina TLS, calcola JA4, utilizza GeoIP e inoltra byte IMAP originali verso il backend TCP. Il backend genera il greeting e le risposte di autenticazione; il mock `verifyCredentialsTBD`, il LOGIN sintetico e il replay sono rimossi. Un osservatore passivo associa tag LOGIN/AUTHENTICATE alle risposte tagged OK/NO/BAD e registra solo metodo/esito con segnali di connessione. Nessuna password viene intenzionalmente persistita.

Il codice mantiene temporaneamente la valutazione del rischio per connessione basata su JA4/GeoIP, con possibili tarpit o DROP **prima del relay**. Non corrisponde ancora alla modalità Transparent: le modalità Transparent, Learning e Defender non sono implementate. Redis non riceve ancora eventi di autenticazione reali dall'osservatore; il vecchio tracker rimane per compatibilità interna, ma non viene alimentato dai risultati del backend.

L'osservatore è ancora limitato: il parsing passivo di literal e SASL multilinea richiede hardening; i test end-to-end con Dovecot e la verifica completa delle condizioni avversarie restano aperti. L'hot reload TLS e GeoIP richiede ulteriori verifiche di concorrenza.

## Decisione di autenticazione

[ADR 0003](adr/0003-backend-authentication-authority.md) è applicato nella rimozione del mock e nell'inoltro degli esiti reali; la piena osservazione protocol-aware e l'integrazione con le modalità operative rimangono attività future.

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
- [ADR 0003](adr/0003-backend-authentication-authority.md): il backend autentica, il proxy osserva.
- [AGENTS.md](../AGENTS.md): workflow e verifica per gli assistenti.
- [Istruzioni del progetto ChatGPT](chatgpt-project-instructions.md): testo da inserire nelle impostazioni del progetto.
