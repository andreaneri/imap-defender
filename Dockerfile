# ==========================================
# STAGE 1: COMPILAZIONE (BUILD ENVIRONMENT)
# ==========================================
FROM golang:1.24-alpine AS builder

# Installiamo i certificati CA necessari per le connessioni in uscita (es. Redis TLS o LDAP)
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copiamo i file dei moduli per sfruttare il caching dei layer di Docker
COPY go.mod go.sum ./
RUN go mod download

# Copiamo il resto del codice sorgente
COPY . .

# Compiliamo il binario in modo statico:
# - CGO_ENABLED=0 disabilita le librerie dinamiche C
# - GOOS=linux garantisce la compatibilità con il kernel Linux del container
# - -ldflags="-s -w" rimuove la tabella dei simboli e le informazioni di debug per ridurre il peso
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o imap-ja4-proxy main.go

# ==========================================
# STAGE 2: ESECUZIONE (MINIMAL RUNTIME)
# ==========================================
FROM scratch

# Copiamo i certificati CA generati nel primo stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /

# Copiamo esclusivamente il binario compilato
COPY --from=builder /app/imap-ja4-proxy /imap-ja4-proxy

# Espone la porta standard IMAP TLS configurata nel file YAML
EXPOSE 993

# Avvia il proxy
ENTRYPOINT ["/imap-ja4-proxy"]
