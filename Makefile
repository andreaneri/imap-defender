# --- CONFIGURAZIONE ---
BINARY_NAME=imap-ja4-proxy
CONFIG_FILE=config.yaml
CERT_FILE=cert.pem
KEY_FILE=key.pem

# Rilevamento automatico dell'architettura del Mac (arm64 per Apple Silicon, amd64 per Intel)
LOCAL_ARCH=$(shell go env GOARCH)
LOCAL_OS=$(shell go env GOOS)

# Flag di compilazione ottimizzati per Go 1.27 (-s -w rimuovono i simboli di debug riducendo il peso)
LDFLAGS=-ldflags="-s -w"

.PHONY: all help init certs test bench build-local build-linux clean up down reload logs

all: help

help:
	@echo "Adaptive IMAP Proxy - Gestione Comandi:"
	@echo "  make init          - Inizializza i moduli Go e scarica le dipendenze"
	@echo "  make certs         - Genera certificati SSL/TLS autofirmati di test"
	@echo "  make test          - Esegue la suite di Unit e Integration Test con Race Detector"
	@echo "  make bench         - Esegue i benchmark di performance e allocazione memoria"
	@echo "  make build-local   - Compila il binario nativo per questo Mac ($(LOCAL_OS)-$(LOCAL_ARCH))"
	@echo "  make build-linux   - Cross-compila il binario statico per Linux AMD64 (Produzione)"
	@echo "  make clean         - Rimuove i binari compilati e i file temporanei"
	@echo "  make up            - Avvia l'infrastruttura multi-container (Docker/Podman Compose)"
	@echo "  make down          - Arresta e pulisce i container dell'infrastruttura"
	@echo "  make reload        - Invia il segnale SIGHUP al proxy per l'Hot Reload live"
	@echo "  make logs          - Visualizza i log JSON strutturati (slog) in tempo reale"

# --- SVILUPPO LOCALE ---

init:
	@echo "==> Inizializzazione moduli Go..."
	go mod download
	go mod tidy

certs:
	@echo "==> Generazione certificati SSL/TLS per la terminazione..."
	openssl req -x509 -newkey rsa:4096 -keyout $(KEY_FILE) -out $(CERT_FILE) -sha256 -days 365 -nodes -subj "/CN=localhost"
	@echo "==> Certificati $(CERT_FILE) e $(KEY_FILE) generati con successo."

test:
	@echo "==> Esecuzione dei test con verifica delle Race Condition..."
	go test -race -v .

bench:
	@echo "==> Esecuzione dei benchmark di performance applicativa..."
	go test -bench=. -benchmem -run=^$$ .

# --- COMPILAZIONE ---

build-local:
	@echo "==> Compilazione binario nativo per Mac ($(LOCAL_OS)-$(LOCAL_ARCH))..."
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY_NAME)-local main.go
	@echo "==> Pronto: ./$(BINARY_NAME)-local"

build-linux:
	@echo "==> Cross-compilazione binario statico per Linux AMD64 (Produzione)..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux main.go
	@echo "==> Pronto per la produzione: ./$(BINARY_NAME)-linux"

clean:
	@echo "==> Pulizia dei binari e file temporanei..."
	rm -f $(BINARY_NAME)-local $(BINARY_NAME)-linux coverage.out
	@echo "==> Pulizia completata."

# --- RUNTIME & CONTAINER ORCHESTRATION (DOCKER / PODMAN) ---
# I comandi rilevano automaticamente se usi podman o docker sul Mac

CONTAINER_CMD=$(shell which podman 2>/dev/null || which docker 2>/dev/null)
COMPOSE_CMD=$(shell which podman-compose 2>/dev/null || which docker-compose 2>/dev/null || echo "$(CONTAINER_CMD) compose")

up:
	@echo "==> Avvio infrastruttura multi-container tramite $(COMPOSE_CMD)..."
	$(COMPOSE_CMD) up -d --build

down:
	@echo "==> Arresto e rimozione dell'infrastruttura..."
	$(COMPOSE_CMD) down

reload:
	@echo "==> Invio segnale SIGHUP per Hot Reload della configurazione..."
	$(CONTAINER_CMD) kill --signal=HUP imap-proxy
	@echo "==> Segnale inviato con successo."

logs:
	@echo "==> Estrazione log JSON in corso (Premi CTRL+C per uscire)..."
	$(COMPOSE_CMD) logs -f imap-proxy
