# IMAP Defender — Architettura e stato

## Riferimento

Questa fotografia descrive la base `8ac0809` di `main` e il successivo hardening dell’osservatore sul branch `feat/harden-passive-auth-observer`. [DOCUMENTAZIONE.md](DOCUMENTAZIONE.md) conserva la guida tecnica e operativa estesa; [TODO.md](../TODO.md) raccoglie il backlog. Le descrizioni progettuali nella guida estesa vanno confrontate con il codice.

## Implementazione attuale (branch di lavoro)

Il proxy termina TLS, calcola JA4, utilizza GeoIP e inoltra byte IMAP originali verso il backend TCP. Il backend genera il greeting e le risposte di autenticazione; il mock `verifyCredentialsTBD`, il LOGIN sintetico e il replay sono rimossi. Un osservatore passivo associa tag LOGIN/AUTHENTICATE alle risposte tagged OK/NO/BAD e estrae la username dichiarata per LOGIN, SASL PLAIN e SASL LOGIN, associandola agli esiti reali per sessione/tag. L’osservatore conserva tag (massimo 128 byte), metodo e identità limitate a 1024 byte, fino a 64 autenticazioni pendenti. Copia solo le identità: password, token, altri literal e payload SASL completi non sono conservati. L’evento strutturato riunisce timestamp UTC, IP senza porta, paese GeoIP, JA4, username, eventuale identità di autorizzazione SASL, metodo e risultato. Identità non disponibili restano esplicitamente sconosciute; non vengono normalizzate o considerate identità canoniche del backend. Non persiste eventi in Redis.

Il codice mantiene temporaneamente la valutazione del rischio per connessione basata su JA4/GeoIP, con possibili tarpit o DROP **prima del relay**. Non corrisponde ancora alla modalità Transparent: le modalità Transparent, Learning e Defender non sono implementate. Redis non riceve ancora eventi di autenticazione reali dall'osservatore; il vecchio tracker rimane per compatibilità interna, ma non viene alimentato dai risultati del backend.

L’osservatore salta literal per lunghezza in entrambe le direzioni, gestisce continuazioni e scambi SASL, distinguendo OK/NO/BAD da INDETERMINATE. Alla chiusura, BYE o ambiguità di parsing/correlazione finalizza i tentativi pendenti come indeterminati; su ambiguità sospende l’osservazione per la sessione, mantenendo il relay invariato. I test avversari coprono frammentazione, payload contraffatti, overflow e limiti; i test end-to-end con Dovecot restano aperti. L'hot reload TLS e GeoIP richiede ulteriori verifiche di concorrenza.

## Decisione di autenticazione

[ADR 0003](adr/0003-backend-authentication-authority.md) è applicato nella rimozione del mock e nell'inoltro degli esiti reali; l’integrazione con le modalità operative rimane un’attività futura.

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
- [ADR 0004](adr/0004-account-authentication-signals.md): identità dichiarate e segnali di autenticazione, con limiti e assenza di segreti.
- [ADR 0003](adr/0003-backend-authentication-authority.md): il backend autentica, il proxy osserva.
- [AGENTS.md](../AGENTS.md): workflow e verifica per gli assistenti.
- [Istruzioni del progetto ChatGPT](chatgpt-project-instructions.md): testo da inserire nelle impostazioni del progetto.
