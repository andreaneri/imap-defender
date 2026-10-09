# IMAP Defender — Istruzioni del progetto ChatGPT

Testo da copiare nelle istruzioni del progetto ChatGPT “imap defender”. La sua presenza nel repository non modifica automaticamente le impostazioni ChatGPT.

---

Repository di riferimento: https://github.com/andreaneri/imap-defender. Branch principale: `main`. GitHub è la fonte di verità per codice, configurazione e documentazione.

All'inizio di ogni attività sul codice, consultare il repository tramite il connettore GitHub o un checkout disponibile; verificare branch, commit, struttura e file coinvolti. Non presumere che il codice letto in un'altra chat sia aggiornato. Se l'accesso non è disponibile, dichiararlo e non presentare modifiche come applicate.

Leggere e rispettare `AGENTS.md`, `docs/architecture.md` e gli ADR pertinenti in `docs/adr/`. Consultare `docs/DOCUMENTAZIONE.md` e `TODO.md` per dettagli operativi e backlog. Documentare nel repository le decisioni che devono sopravvivere alle chat.

IMAP Defender è un proxy IMAP in Go per mitigare attacchi automatizzati e proteggere i backend mantenendo la compatibilità con i client legittimi.

Le modalità concordate sono:
- Transparent: inoltro, metriche e diagnostica senza ritardi o blocchi deliberati.
- Learning: osservazione degli esiti reali e apprendimento in Redis senza contromisure basate sulle classificazioni.
- Defender: rate limiting, rallentamento e blocco configurabili, eccezioni controllate e decisioni motivabili.

Verificare sempre lo stato implementato: Light/Deep Inspection e `deep_inspection_mode` non equivalgono alle tre modalità concordate.

Preferire Go e la libreria standard, limitare dipendenze e componenti complessi. Separare proxying, osservazione, classificazione ed enforcement. Trattare fingerprint TLS, IP, paese, account ed esito come segnali distinti; una fingerprint non identifica univocamente un client. Gestire correttamente timeout, connessioni, goroutine, buffer e context. Non esporre credenziali o dati sensibili nei log.

Usare branch dedicati e modifiche piccole e verificabili. Non modificare direttamente `main` o effettuare merge senza autorizzazione esplicita. Esaminare i file prima di modificarli e verificare lo stato del branch prima delle scritture. Separare commit di codice e documentazione; messaggi di commit in inglese. Presentare le modifiche tramite commit e, quando opportuno, pull request.

Usare le verifiche previste da `AGENTS.md` in base alla modifica. Non dichiarare test, commit o modifiche senza averne verificato il risultato. Distinguere comportamento implementato, decisioni accettate e proposte future.

Rispondere in italiano, mantenendo nomi tecnici, identificatori e codice in inglese. Privilegiare discussioni concrete, rispettare le convenzioni del repository, verificare se una funzionalità esiste già e limitare le modifiche allo scope richiesto.
