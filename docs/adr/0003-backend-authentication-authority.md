# 0003 — Backend IMAP come unica autorità di autenticazione

- Data: 2026-10-10
- Stato: Accettato
- Implementazione: parziale nel branch feat/passive-imap-auth-observer; il relay non autentica localmente, ma osservatore e modalità richiedono ancora hardening

## Contesto

Il prototipo effettua una verifica credenziali locale tramite `verifyCredentialsTBD`, sintetizza risposte IMAP e ricostruisce il comando LOGIN prima dell'inoltro. Era prevista anche un'integrazione LDAP/AD per scartare credenziali errate prima del backend. Questa impostazione duplica la responsabilità di autenticazione, non fornisce esiti attendibili e introduce rischi di incompatibilità del protocollo.

## Decisione

Il backend IMAP è l'unica autorità per l'autenticazione. IMAP Defender non verifica credenziali, non interroga LDAP/AD per decidere se un LOGIN è valido e non emette risposte di autenticazione sintetiche.

Il proxy inoltra integralmente comandi e risposte senza alterare tag, ordine, greeting, capability, literal e byte già letti. Osserva passivamente la richiesta di autenticazione e la relativa risposta tagged del backend, correlandole per sessione e tag. Il risultato è attribuito al backend, non inferito dalla password o da un mock. Gli esiti non conclusivi rimangono distinti da OK e NO.

L'osservazione è prevista già in Transparent, senza enforcement o ritardi deliberati e senza obbligo di persistenza Redis. Learning usa gli esiti autentici per l'apprendimento; Defender può usare lo storico per decisioni successive secondo politiche configurate, senza sostituirsi al backend nell'autenticazione.

Non registrare o conservare password, comandi contenenti credenziali, challenge/response SASL o altri segreti. Definire esplicitamente quali identificativi e metadati sono strettamente necessari, i TTL e la gestione degli errori di parsing. L'osservatore deve essere fail-open rispetto al relay: un evento non riconosciuto non autorizza la modifica del traffico.

## Conseguenze

Rimuovere dal codice il mock `verifyCredentialsTBD`, il ramo che risponde localmente LOGIN NO e il replay LOGIN ricostruito; eliminare dalla configurazione i pesi basati su `UserExists` e `PasswordValid` calcolati localmente. Sostituire il parser distruttivo con un osservatore bidirezionale che preservi i byte.

Rimuovere dal backlog la proposta di connettore LDAP/AD e pre-screening account. Aggiornare test, documentazione e configurazione. Testare LOGIN con quoted strings/literal, comandi preliminari, risposte tagged, più autenticazioni per connessione, disconnessioni e SASL AUTHENTICATE. Le forme non supportate devono transitare comunque correttamente.

Questa decisione integra [ADR 0002](0002-operating-modes.md), senza sostituirne le modalità operative.

## Verifica

I test devono dimostrare che solo il backend determina OK/NO, che i byte sono inoltrati invariati e che Transparent non blocca o ritarda per rischio. Le credenziali non devono comparire in log o Redis.

Vedere [architecture.md](../architecture.md) e [TODO.md](../../TODO.md).
