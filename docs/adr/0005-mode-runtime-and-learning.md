# 0005 — Modalità runtime e apprendimento Redis

- Data: 2026-10-10
- Stato: Accettato
- Implementazione: selezione modalità, apprendimento asincrono e gating delle mitigazioni
- Integra: [ADR 0002](0002-operating-modes.md), [ADR 0003](0003-backend-authentication-authority.md) e [ADR 0004](0004-account-authentication-signals.md)

## Decisione

`security.mode` accetta `transparent`, `learning` e `defender`. In assenza del campo il default è Transparent, anche per configurazioni precedenti: migrare esplicitamente a Defender se si desiderano le mitigazioni preesistenti. Il campo obsoleto `deep_inspection_mode`, anche se false, viene rifiutato con indicazione di migrazione; non è una modalità operativa. L'osservazione passiva resta attiva in tutte le modalità.

Transparent non legge né scrive Redis e non applica valutazioni o mitigazioni di rischio. Redis può essere omesso. Learning non legge Redis per classificare o ritardare una connessione, ma accoda gli eventi autentici. Defender applica il Risk Engine preesistente prima del relay e accoda gli stessi eventi. Rate limiting, eccezioni e politiche per account restano da implementare.

L'indirizzo e la dimensione della coda Redis sono obbligatori per Learning e Defender, ma Redis non deve essere raggiungibile all'avvio. Errori e timeout di lettura in Defender sono fail-open per l'intera decisione della connessione, con warning; non sono interpretati come fingerprint sconosciuta. Il lookup ha un budget di 200 ms, senza retry; usa il context della connessione. Learning e Transparent non attendono questi lookup.

## Persistenza e limiti

La coda non blocca i client; scarta eventi quando piena, rifiuta ingressi dopo la chiusura e viene drenata con il limite di shutdown esistente. Le scritture hanno un budget complessivo di 2 secondi, timeout di rete di 200 ms e nessun retry. In caso di errore l'evento viene perso con log diagnostico: non è una coda durevole.

- `proxy:auth:observation:<sha256>`: hash dell'ultima osservazione per JA4/IP/paese/username/authzid/metodo/meccanismo, TTL 7 giorni rinnovato. Per identità sconosciuta includere il timestamp nella chiave per non creare un account comune. Campi: `ip`, `country_code`, `ja4`, `username_known`, `username`, `authorization_id`, `method`, `mechanism`, `outcome`, `timestamp` UTC RFC3339Nano. Non è uno storico completo dei tentativi e non espone contatori per rate limiting.
- `proxy:auth:success:<sha256>`: segnale di successo per coppia JA4/IP, TTL 24 ore rinnovato solo da OK con username nota. Riduce esclusivamente il peso `ja4_unknown`; non elimina il peso GeoIP e non concede whitelist. NO/BAD/INDETERMINATE non creano il segnale e non revocano successi precedenti.

Le chiavi usano SHA-256 su array JSON per evitare collisioni di delimitatori. Il digest non anonimizza i campi del valore. La raccolta limita la durata ai TTL; accessi Redis e retention dei log sono responsabilità del deployment. Non vengono conservati password, token o payload SASL. Scritture e TTL sono emessi tramite transazione Redis. Le vecchie chiavi `proxy:ja4:trusted:*` e `proxy:analytics:*` non vengono lette, migrate o cancellate automaticamente.

## Reload

Ogni connessione conserva la modalità iniziale. Cambiare modalità via SIGHUP influenza le nuove connessioni; le sessioni Learning già attive possono continuare ad accodare eventi dopo il passaggio a Transparent. Se Redis è omesso all'avvio, aggiungerlo richiede un riavvio. Modifiche a indirizzo/dimensione coda Redis o listener sono rifiutate al reload; il client e il listener non vengono ricreati. I certificati TLS vengono sostituiti clonando `tls.Config`, senza modificare l'istanza usata dalle connessioni attive.

## Verifica

Test con race detector: decisioni e persistenza per modalità, relay TLS verso backend controllato con risposta originale NO, decisioni Defender con peer RESP controllato, timeout/cancellazione, coda piena, chiusura concorrente, drain, esiti distinti e TTL, migrazione YAML e snapshot di configurazione. Collaudo con Dovecot e Redis reali resta separato; i test non certificano produzione o compatibilità completa IMAP.
