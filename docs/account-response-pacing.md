# Account-aware response pacing — PR #10

Il pacing L2 è implementato sul branch `feat/account-response-enforcement` secondo ADR [0003](adr/0003-backend-authentication-authority.md), [0008](adr/0008-account-aware-response-pacing.md) e [0009](adr/0009-account-ja4-country-policy.md). È disabilitato per default e attivo esclusivamente in Defender. Il backend riceve tutti i comandi originali ed è l'unica autorità per OK/NO/BAD. Non esistono risposte sintetiche, verifica locale delle credenziali, blocchi per account o whitelist JA4.

## Configurazione

Esempio opt-in da usare soltanto dopo il collaudo dei client e del deployment:

```yaml
security:
  mode: defender
  account_pacing:
    enabled: true
    soft_failures: 3
    hard_failures: 8
    soft_delay: 250ms
    hard_delay: 1s
    max_delay: 1s
    max_concurrent: 64
```

Redis e gli altri campi obbligatori restano quelli della configurazione principale. Il token bucket L1 (`rate_limit`) e il Risk Engine prima del relay restano indipendenti.

| Campo | Default | Validazione |
| --- | --- | --- |
| `enabled` | `false` | Ignorato in Transparent e Learning |
| `soft_failures` | 3 | Positivo e minore di `hard_failures` |
| `hard_failures` | 8 | Maggiore di `soft_failures`, massimo 1.000.000 |
| `soft_delay` | 250 ms | Almeno 1 ms, non maggiore di `hard_delay` |
| `hard_delay` | 1 s | Non maggiore di `max_delay` |
| `max_delay` | 1 s | Massimo 8 s; include il lookup |
| `max_concurrent` | 64 | Da 1 a 1024, per processo |

I campi di tuning a zero usano il default; lo zero non disabilita singole soglie. Per disabilitare il pacing usare `enabled: false`. Le durate YAML usano la sintassi Go (`250ms`, `1s`). Una configurazione non valida viene rifiutata anche se disabilitata. SIGHUP applica i nuovi valori alle nuove sessioni; quelle attive mantengono lo snapshot iniziale. Il limite di capacità è condiviso fra snapshot: abbassarlo non interrompe attese già ammesse, ma impedisce nuove ammissioni finché la capacità non rientra.

## Decisione e storico

La decisione riguarda solo un completamento tagged NO/BAD relativo a LOGIN o AUTHENTICATE con authcid estratta con certezza. Nessun lookup L2 viene richiesto per OK o identità sconosciute. LOGIN atom, quoted e literal, SASL PLAIN e SASL LOGIN sono supportati; authzid resta distinta da authcid.

Lo storico Redis usa le chiavi hashate di ADR 0009 e l'identità esatta, senza normalizzazione. L'evento corrente viene accodato **dopo** la lettura storica, quindi il suo primo esito non può rendere KNOWN la propria decisione. UNKNOWN non riceve un timer di pacing. Un'altra sessione può aver già pubblicato uno storico autentico per lo stesso account: la lettura non è una transazione o una prova di esistenza dell'account.

Per un account KNOWN:

- Fallimenti globali `(account, JA4)` almeno alla soglia hard producono `hard_delay`.
- Fallimenti almeno alla soglia soft producono `soft_delay`.
- Un'origine `(account, JA4, IP)` senza successo storico produce `soft_delay`, anche sotto soglia: copre JA4/IP cambiati.
- Un'origine con successo storico sotto soglia non riceve un timer; oltre soglia il successo non esenta dai rallentamenti.

I segnali di paese non attivano blocchi. Country ZZ non viene usato per corroborazione geografica; nessun blocco viene propagato ad altri paesi. BLOCK_CANDIDATE del motore shadow rimane solo diagnostico. Nel runtime L2 i fallimenti elevati continuano a produrre pacing limitato, senza chiusure di connessioni per account.

## Confine del protocollo e fail-open

Il gate riusa il framing bidirezionale dell'osservatore e registra i tag di **tutti** i comandi, non solo quelli di autenticazione. I tag pendenti sono limitati a 64, i tag a 128 byte e le identità a 1024 byte; SASL conserva soltanto le identità, con il limite di osservazione di 64 KiB per risposta. Password, token e payload completi non sono conservati dal gate o dall'osservatore.

Ogni prefisso ricevuto viene inoltrato immediatamente. Solo il LF finale di un completamento negativo eleggibile può essere trattenuto: un client IMAP basato su CRLF riceve la risposta completa dopo il ritardo. Il prefisso negativo può essere già visibile a un client che espone letture parziali. Questa scelta evita di accumulare linee incomplete, greeting, continuazioni SASL o literal, e conserva integralmente i byte e l'ordine senza ricostruire risposte.

Un completamento viene rilasciato senza pacing se:

- Ci sono altri comandi pendenti o byte backend successivi già letti.
- Arriva nuovo traffico dal client o dal backend durante lookup/timer, oppure EOF.
- L'inoltro del comando è ancora in corso o ha fallito; una risposta immediata che corre con il commit della scrittura fallisce aperta.
- Parsing, tag duplicati, completamenti inattesi, literal o flussi SASL risultano ambigui; l'identità è sconosciuta o SASL è cancellato.
- COMPRESS/STARTTLS, meccanismi SASL non supportati o quoting nel testo server rendono insufficiente il framing disponibile: il bypass è permanente per la sessione.
- Redis restituisce errore/timeout o la capacità condivisa è esaurita.

Se una risposta successiva arriva durante l'attesa, il gate emette prima il LF trattenuto e poi quella risposta, senza attenderne il timer né invertirne l'ordine. Le continuazioni dopo literal, inclusi literal di lunghezza zero o concatenati, non possono simulare completamenti tagged. Gli incomplete stream sono inoltrati fino all'ultimo byte, anche su EOF.

Il lookup Redis ha un budget di `min(200ms, max_delay)`, cancellabile e senza retry. Il timer usa soltanto il residuo del ritardo calcolato: il tempo Redis non si aggiunge al ritardo configurato. UNKNOWN ed errori possono comunque comportare la latenza operativa del lookup, entro tale budget. Timer e letture non mantengono mutex dell'osservatore; la telemetria rimane asincrona e può perdere eventi.

La capacità globale copre letture e timer, e il relativo slot non viene liberato finché un worker di lettura cancellato non è uscito. Il reader backend usa chunk di 32 KiB e un canale di capacità uno: al massimo quattro chunk di output possono essere vivi (corrente, prelevato dall'attesa, nel canale e in lettura), oltre al normale buffer di copia client e ai metadati limitati. Nessuna coda di risposte complete cresce con la durata del timer.

La cancellazione chiude entrambi i socket e il relay attende reader, copia client e lookup. TCP half-close client viene propagato al backend, con drain limitato a 5 s tramite read deadline; l'output finale del backend resta inoltrato. EOF backend chiude il relay dopo aver scaricato i byte già letti. Gli errori di rete possono naturalmente interrompere il flusso, senza fabbricare un risultato IMAP.

## Metriche

L'endpoint esistente esporta tre metriche senza etichette account/IP/JA4:

- `imap_account_pace_delayed_total`: completamenti che entrano nel timer, anche se successivamente rilasciati da altro traffico.
- `imap_account_pace_active`: completamenti attualmente nel timer.
- `imap_account_pace_bypassed_total`: candidati bypassati per errore/timeout del lookup o capacità esaurita; non conta tutte le forme di bypass del protocollo.

## Verifica locale — 12 ottobre 2026

Ambiente Go 1.24.4, Linux amd64. Controlli superati:

- `make test`: intera suite con race detector, inclusi test unitari, TLS reale verso peer IMAP/RESP controllati, first OK/NO UNKNOWN, NO/BAD KNOWN, OK non penalizzato, modalità osservanti e opt-in disabilitato.
- `go test -race -timeout=60s -count=20 -run 'TestAccountGate|TestAccountPacingTLSRuntime|TestPacedRelay|TestAuthForwardCoordinator' .`: frammentazione, pipeline, literal, SASL, cancellazione, timeout, limiti e concorrenza ripetuti 20 volte (25,089 s).
- `make build-local` e `make build-linux`: binari statici host e Linux amd64.
- `go vet ./...` e `make bench`.
- Integrità dei byte, prefissi incompleti immediati, quote/literal injection, tag duplicati, memoria con password/literal grandi, short write, fallimenti della destinazione e TCP half-close.

Benchmark locale `BenchmarkAccountGateStreaming`: 794,3 ns/op, 720 B/op, 16 allocs/op, 67,98 MB/s per il piccolo stream di tre linee del benchmark. Include setup di observer/canale; non misura TLS, Redis, latenza di rete o capacità in produzione.

## Limiti e decisioni aperte

Le soglie sono conservative e provvisorie, non approvate per produzione. Pacing L2 è best-effort: pipelining e traffico aggiuntivo possono bypassarlo; non sostituisce L1 né garantisce prevenzione del brute force. Quoting server e meccanismi non supportati possono escludere una sessione dall'enforcement, conservando il relay.

Due client che condividono account e JA4 possono influenzare lo stesso contatore. I successi restano segnali temporanei e gli aggiornamenti asincroni possono arrivare in ritardo o andare persi. Richiedere telemetria e collaudo del deployment prima di attivare il controllo.

Il meccanismo dei blocchi `(account, JA4, country)`, soglie di attivazione e TTL fisso restano una decisione separata richiesta da ADR 0009. Questa PR non implementa blocchi, non estende TTL su tentativi negati e non introduce blocchi globali su account/JA4.

Il collaudo con Redis e Dovecot reali rimane nel TODO: nell'ambiente non sono installati i binari e il daemon Docker non ha immagini locali; l'egress configurato non consente di scaricarle. I peer controllati provano il percorso TLS/relay/Redis e le condizioni avverse, ma non certificano interoperabilità completa con server e client reali. Anche il reload tramite container resta un collaudo operativo separato; la pubblicazione della configurazione usa il percorso AtomicConfig esistente.
