package main

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

// --- 1. UNIT TEST PER IL RISK ENGINE ---
// Sfrutta la tecnica dei "Table-Driven Tests", lo standard in Go per testare molteplici scenari.
func TestEvaluateRisk(t *testing.T) {
	// Definiamo una configurazione di sicurezza fissa per il test
	secCfg := SecurityConfig{
		Thresholds: ThresholdConfig{
			TarpitSoft: 30,
			TarpitHard: 60,
			Drop:       90,
		},
		Weights: WeightConfig{
			JA4Unknown:           25,
			GeoAnomaly:           35,
			UserNotFound:         50,
			PasswordInvalid:      30,
			LoginSuccessDiscount: 20,
		},
	}

	tests := []struct {
		name          string
		ctx           ClientContext
		expectedAct   string
		expectedDelay time.Duration
	}{
		{
			name: "Utente Legittimo (Tutto OK)",
			ctx: ClientContext{
				JA4Known:      true,
				CountryCode:   "IT",
				UserExists:    true,
				PasswordValid: true,
				RemoteIP:      "127.0.0.1",
			},
			expectedAct:   "ALLOW",
			expectedDelay: 0,
		},
		{
			name: "Utente reale a casa (IT) che sbaglia la password",
			ctx: ClientContext{
				JA4Known:      true,
				CountryCode:   "IT",
				UserExists:    true,
				PasswordValid: false,
				RemoteIP:      "127.0.0.1",
			},
			expectedAct:   "TARPIT_SOFT",
			expectedDelay: 3 * time.Second,
		},
		{
			name: "Botnet estera su utente inesistente",
			ctx: ClientContext{
				JA4Known:      false, // +25
				CountryCode:   "US",   // +35
				UserExists:    false,  // +50
				PasswordValid: false,  // +30 (Totale: 140 -> Cap a 100)
				RemoteIP:      "192.0.2.1",
			},
			expectedAct:   "DROP",
			expectedDelay: 0,
		},
		{
			name: "Client sconosciuto dall'estero con credenziali corrette (Es. Utente in viaggio)",
			ctx: ClientContext{
				JA4Known:      false, // +25
				CountryCode:   "FR",   // +35
				UserExists:    true,
				PasswordValid: true,   // -20 (Totale: 40)
				RemoteIP:      "198.51.100.2",
			},
			expectedAct:   "TARPIT_SOFT",
			expectedDelay: 3 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, delay := EvaluateRisk(&tt.ctx, secCfg)
			if action != tt.expectedAct {
				t.Errorf("Variabile 'action' non coincidente: ottenuta %s, richiesta %s", action, tt.expectedAct)
			}
			if delay != tt.expectedDelay {
				t.Errorf("Variabile 'delay' non coincidente: ottenuta %v, richiesta %v", delay, tt.expectedDelay)
			}
		})
	}
}

// --- 2. INTEGRATION TEST PER IL PARSER IMAP INLINE ---
// Emula il flusso dei dati di rete inviati da un client di posta.
func TestParseIMAPLogin(t *testing.T) {
	tests := []struct {
		name             string
		clientPayload    string
		expectedFound    bool
		expectedTag      string
		expectedUsername string
		expectedPassword string
	}{
		{
			name:             "Comando LOGIN Standard senza virgolette",
			clientPayload:    "A001 LOGIN mario segreta\r\n",
			expectedFound:    true,
			expectedTag:      "A001",
			expectedUsername: "mario",
			expectedPassword: "segreta",
		},
		{
			name:             "Comando LOGIN con virgolette",
			clientPayload:    "a02 LOGIN \"mario@dominio.it\" \"pass con spazi\"\r\n",
			expectedFound:    true,
			expectedTag:      "a02",
			expectedUsername: "mario@dominio.it",
			expectedPassword: "pass con spazi",
		},
		{
			name:             "Comandi preliminari prima del LOGIN",
			clientPayload:    "TAG1 CAPABILITY\r\nTAG2 NOOP\r\nA001 LOGIN mario segreta\r\n",
			expectedFound:    true,
			expectedTag:      "A001",
			expectedUsername: "mario",
			expectedPassword: "segreta",
		},
		{
			name:          "Client disconnesso senza inviare LOGIN",
			clientPayload: "TAG1 CAPABILITY\r\n",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Usiamo strings.NewReader per simulare in memoria il socket TCP/TLS
			simulatedSocket := strings.NewReader(tt.clientPayload)
			reader := bufio.NewReader(simulatedSocket)

			auth, err := parseIMAPLogin(reader)
			if err != nil {
				t.Fatalf("Errore inatteso del parser: %v", err)
			}

			if auth.Found != tt.expectedFound {
				t.Fatalf("Stato 'Found' non coincidente: ottenuto %t, richiesto %t", auth.Found, tt.expectedFound)
			}

			if tt.expectedFound {
				if auth.Tag != tt.expectedTag {
					t.Errorf("Tag non coincidente: ottenuto %s, richiesto %s", auth.Tag, tt.expectedTag)
				}
				if auth.Username != tt.expectedUsername {
					t.Errorf("Username non coincidente: ottenuto %s, richiesto %s", auth.Username, tt.expectedUsername)
				}
				if auth.Password != tt.expectedPassword {
					t.Errorf("Password non coincidente: ottenuta %s, richiesta %s", auth.Password, tt.expectedPassword)
				}
			}
		})
	}
}

// --- 3. BENCHMARK DEL RISK ENGINE ---
// Misura l'efficienza del calcolo matematico del punteggio basato sulla config dello YAML.
func BenchmarkEvaluateRisk(b *testing.B) {
	secCfg := SecurityConfig{
		Thresholds: ThresholdConfig{TarpitSoft: 30, TarpitHard: 60, Drop: 90},
		Weights:    WeightConfig{JA4Unknown: 25, GeoAnomaly: 35, UserNotFound: 50, PasswordInvalid: 30, LoginSuccessDiscount: 20},
	}

	ctx := &ClientContext{
		JA4Known:      false,
		CountryCode:   "US",
		UserExists:    false,
		PasswordValid: false,
		RemoteIP:      "192.0.2.1",
	}

	// b.ResetTimer esclude le fasi di setup dal computo del tempo
	b.ResetTimer()

	// Il ciclo b.N viene eseguito milioni di volte da Go per stabilire una media stabile
	for i := 0; i < b.N; i++ {
		_, _ = EvaluateRisk(ctx, secCfg)
	}
}

// --- 4. BENCHMARK DEL PARSER IMAP INLINE ---
// Misura l'impatto del processing delle stringhe e dell'allocazione dei token in memoria.
func BenchmarkParseIMAPLogin(b *testing.B) {
	// Payload standard inviato da un client
	payload := "A001 LOGIN mario segreta\r\n"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Ricreiamo il lettore simulando l'arrivo sequenziale dei byte dal socket TLS
		simulatedSocket := strings.NewReader(payload)
		reader := bufio.NewReader(simulatedSocket)

		_, _ = parseIMAPLogin(reader)
	}
}
