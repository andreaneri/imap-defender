# 0004 — Identità dichiarata e segnali di autenticazione

- Data: 2026-10-10
- Stato: Accettato
- Implementazione: estrazione, log e apprendimento Redis implementati; vedere [ADR 0005](0005-mode-runtime-and-learning.md)
- Integra: [ADR 0003](0003-backend-authentication-authority.md), senza sostituirlo

## Contesto

Metodo ed esito senza account non permettono di correlare attacchi distribuiti verso la stessa mailbox o tentativi verso più account dalla stessa origine. Il requisito concordato è osservare la username, senza estrarre o conservare password e token, associandola agli altri segnali.

## Decisione

Produrre eventi con timestamp UTC, IP del peer senza porta, paese GeoIP (ZZ quando sconosciuto), fingerprint JA4, username dichiarata, metodo/meccanismo ed esito reale del backend. Per SASL conservare separatamente authcid (username di autenticazione) e authzid (identità richiesta per autorizzazione). Non equiparare automaticamente le due identità.

Estrarre l’identità per LOGIN atom/quoted/literal, SASL PLAIN e SASL LOGIN. Non normalizzare arbitrariamente username e alias: il protocollo osservato non restituisce l’identificativo canonico del backend. In assenza di estrazione certa usare username_known=false. Non trattare identità sconosciute come un account condiviso né inferire l’identità da fingerprint o IP.

Limitare ogni identità a 1024 byte, il meccanismo a 32 byte, le autenticazioni pendenti a 64 e l’osservazione di ciascuna risposta SASL a 64 KiB. Non troncare identità troppo lunghe in account apparentemente validi. Non copiare il secondo argomento LOGIN o la password PLAIN; non registrare payload Base64, challenge, token o comandi completi. I meccanismi non supportati transitano senza estrazione.

Distinguere OK, NO, BAD e INDETERMINATE. La username è una dichiarazione del client e NO non prova che la sola password fosse errata. L’esito aggiorna le informazioni disponibili dopo il tentativo; azioni precedenti al suo completamento possono basarsi solo sui segnali già disponibili e sullo storico.

## Conseguenze

I risultati vengono associati ai segnali della connessione e registrati come evento strutturato. La memoria dell’osservatore dura fino a esito, chiusura o invalidazione della sessione. La retention dei log viene configurata nella piattaforma di raccolta. Non è introdotta persistenza Redis: Learning deve definire TTL e gestione della coda prima dell’attivazione.

La classificazione e l’enforcement rimangono responsabilità distinte, secondo ADR 0002. Un successo non concede whitelist globale a username, IP o JA4. Traffico compresso e livelli di sicurezza SASL non sono decodificati; eventuale perdita di framing sospende l’osservazione, non il relay.

## Verifica

Testare estrazione atom/quoted/literal, risposte iniziali e continuazioni SASL, separazione authcid/authzid, frammentazione, correlazione per tag, limiti, input incompleti e identità sconosciute. Verificare assenza di password/token nei buffer dell’osservatore e nei log e preservazione dei byte del relay. I test con backend Dovecot restano un’attività separata nel TODO.
