# 0001 — GitHub come fonte condivisa del progetto

- Data: 2026-10-09
- Stato: Accettato
- Implementazione: documentazione introdotta con questo ADR

## Contesto

Più chat e strumenti lavorano su IMAP Defender. Le conversazioni possono avere fotografie diverse del codice e non garantiscono la propagazione delle decisioni.

## Decisione

Usare https://github.com/andreaneri/imap-defender come fonte di verità per codice, configurazione e documentazione. Verificare branch e commit all'inizio di ogni attività e leggere i file correnti. Conservare le regole per gli assistenti in `AGENTS.md`, la fotografia architetturale in `docs/architecture.md` e le decisioni durature in `docs/adr/`.

Le istruzioni del progetto ChatGPT rimandano a questi documenti. L'accesso al repository dipende dal connettore o dal checkout disponibile nella singola sessione; un URL nelle istruzioni non concede permessi.

Usare branch dedicati e modifiche verificabili. Non scrivere direttamente su `main` o effettuare merge senza autorizzazione esplicita. Prima di pubblicare modifiche verificare lo stato del branch, evitando di sovrascrivere lavoro concorrente.

## Conseguenze

Il contesto è versionato e consultabile da strumenti diversi. Ogni cambiamento architetturale richiede aggiornamento della documentazione. Una chat deve leggere il repository; non può presumere di conoscere il lavoro svolto nelle altre.

## Verifica e riferimenti

Consultare [AGENTS.md](../../AGENTS.md) e [le istruzioni ChatGPT](../chatgpt-project-instructions.md). Le impostazioni ChatGPT sono gestite nell'interfaccia e non vengono modificate da questo commit.
