package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/exaring/ja4plus"
	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
)

// --- MODULO 1: CONFIGURAZIONE & ATOMIC MANAGEMENT ---

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Redis    RedisConfig    `yaml:"redis"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
}

type ServerConfig struct {
	ListenAddr      string `yaml:"listen_addr"`
	BackendIMAPAddr string `yaml:"backend_imap_addr"`
	CertFile        string `yaml:"cert_file"`
	KeyFile         string `yaml:"key_file"`
}

type RedisConfig struct {
	Addr            string `yaml:"addr"`
	QueueBufferSize int    `yaml:"queue_buffer_size"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

type SecurityConfig struct {
	GeoIPDBPath        string          `yaml:"geoip_db_path"`
	Thresholds         ThresholdConfig `yaml:"thresholds"`
	Weights            WeightConfig    `yaml:"weights"`
}

type ThresholdConfig struct {
	TarpitSoft int `yaml:"tarpit_soft"`
	TarpitHard int `yaml:"tarpit_hard"`
	Drop       int `yaml:"drop"`
}

type WeightConfig struct {
	JA4Unknown           int `yaml:"ja4_unknown"`
	GeoAnomaly           int `yaml:"geo_anomaly"`
}

type AtomicConfig struct {
	value atomic.Value
}

func (ac *AtomicConfig) Store(cfg *Config) { ac.value.Store(cfg) }
func (ac *AtomicConfig) Load() *Config     { return ac.value.Load().(*Config) }

func LoadConfig(filename string) (*Config, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("lettura file fallita: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("parsing dello YAML fallito: %w", err)
	}
	if err := validateConfig(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func validateConfig(c *Config) error {
	if c.Server.ListenAddr == "" || c.Server.BackendIMAPAddr == "" {
		return fmt.Errorf("server.listen_addr e server.backend_imap_addr sono obbligatori")
	}
	if c.Server.CertFile == "" || c.Server.KeyFile == "" {
		return fmt.Errorf("server.cert_file e server.key_file sono obbligatori")
	}
	if err := validateTCPAddress("server.listen_addr", c.Server.ListenAddr, true); err != nil {
		return err
	}
	if err := validateTCPAddress("server.backend_imap_addr", c.Server.BackendIMAPAddr, false); err != nil {
		return err
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("redis.addr è obbligatorio")
	}
	if err := validateTCPAddress("redis.addr", c.Redis.Addr, false); err != nil {
		return err
	}
	if c.Redis.QueueBufferSize <= 0 {
		return fmt.Errorf("redis.queue_buffer_size deve essere maggiore di zero")
	}
	t := c.Security.Thresholds
	if t.TarpitSoft <= 0 || t.TarpitSoft >= t.TarpitHard || t.TarpitHard >= t.Drop || t.Drop > 100 {
		return fmt.Errorf("security.thresholds deve rispettare 0 < tarpit_soft < tarpit_hard < drop <= 100")
	}
	w := c.Security.Weights
	weights := []struct {
		name  string
		value int
	}{
		{"ja4_unknown", w.JA4Unknown},
		{"geo_anomaly", w.GeoAnomaly},
	}
	for _, weight := range weights {
		if weight.value < 0 || weight.value > 100 {
			return fmt.Errorf("security.weights.%s deve essere compreso tra 0 e 100", weight.name)
		}
	}
	if level := strings.ToLower(c.Logging.Level); level != "" && level != "debug" && level != "info" && level != "warn" && level != "error" {
		return fmt.Errorf("logging.level non valido: %q", c.Logging.Level)
	}
	return nil
}

func validateTCPAddress(name, address string, allowEmptyHost bool) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s non valido: %w", name, err)
	}
	if host == "" && !allowEmptyHost {
		return fmt.Errorf("%s deve specificare un host", name)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("%s deve avere una porta TCP compresa tra 1 e 65535", name)
	}
	return nil
}

func initLogger(levelStr string) {
	var level slog.Level
	switch strings.ToLower(levelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, opts)))
}

// --- MODULO 2: DATI & STRUTTURE COMPONENTI ---

type LoginEvent struct {
	JA4       string
	Username  string
	RemoteIP  string
	Success   bool
	Timestamp time.Time
}

type ClientContext struct {
	JA4Known      bool
	CountryCode   string
	RemoteIP      string
}

// --- MODULO 3: ASYNC REDIS TRACKER ---

type RedisTracker struct {
	client     *redis.Client
	eventQueue chan LoginEvent
	ctx        context.Context
	cancel     context.CancelFunc
	workerDone chan struct{}
	queueMu    sync.RWMutex
	closed     bool
	closeOnce  sync.Once
}

func NewRedisTracker(addr string, bufferSize int) *RedisTracker {
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	ctx, cancel := context.WithCancel(context.Background())
	tracker := &RedisTracker{
		client:     rdb,
		eventQueue: make(chan LoginEvent, bufferSize),
		ctx:        ctx,
		cancel:     cancel,
		workerDone: make(chan struct{}),
	}
	go tracker.startAsyncWorker()
	return tracker
}

func (rt *RedisTracker) IsJA4Trusted(ja4 string) bool {
	key := "proxy:ja4:trusted:" + ja4
	ctx, cancel := context.WithTimeout(rt.ctx, 200*time.Millisecond)
	defer cancel()

	exists, err := rt.client.Exists(ctx, key).Result()
	if err != nil {
		slog.Error("Redis lookup fallito", "ja4", ja4, "error", err)
		return false
	}
	return exists > 0
}

func (rt *RedisTracker) TrackEventAsync(event LoginEvent) {
	rt.queueMu.RLock()
	defer rt.queueMu.RUnlock()
	if rt.closed {
		return
	}
	select {
	case rt.eventQueue <- event:
	default:
		slog.Warn("Coda eventi Redis piena, log rimosso", "remote_ip", event.RemoteIP)
	}
}

func (rt *RedisTracker) startAsyncWorker() {
	defer close(rt.workerDone)
	slog.Info("Redis worker asincrono avviato")
	for {
		var event LoginEvent
		select {
		case <-rt.ctx.Done():
			return
		case queuedEvent, ok := <-rt.eventQueue:
			if !ok {
				return
			}
			event = queuedEvent
		}

		ctx, cancel := context.WithTimeout(rt.ctx, 2*time.Second)
		pipe := rt.client.Pipeline()

		if event.Success {
			trustedKey := "proxy:ja4:trusted:" + event.JA4
			pipe.Set(ctx, trustedKey, "1", 30*24*time.Hour)
		}

		analyticsKey := "proxy:analytics:ja4:" + event.JA4 + ":user:" + event.Username
		fields := map[string]interface{}{
			"ip":        event.RemoteIP,
			"esito":     map[bool]string{true: "OK", false: "KO"}[event.Success],
			"timestamp": event.Timestamp.Format(time.RFC3339),
		}
		pipe.HSet(ctx, analyticsKey, fields)
		pipe.Expire(ctx, analyticsKey, 7*24*time.Hour)

		_, err := pipe.Exec(ctx)
		cancel()
		if err != nil {
			slog.Error("Scrittura pipeline Redis fallita", "error", err)
		}
	}
}

func (rt *RedisTracker) Close() {
	rt.closeOnce.Do(func() {
		rt.queueMu.Lock()
		rt.closed = true
		close(rt.eventQueue)
		rt.queueMu.Unlock()

		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		select {
		case <-rt.workerDone:
		case <-timer.C:
			pending := len(rt.eventQueue)
			slog.Warn("Timeout durante lo svuotamento della coda Redis", "pending_events", pending)
			rt.cancel()
			rt.client.Close()
			<-rt.workerDone
			return
		}
		rt.cancel()
		rt.client.Close()
	})
}

// --- MODULO 4: RISK ENGINE ---

func EvaluateRisk(ctx *ClientContext, secCfg SecurityConfig) (action string, delay time.Duration) {
	score := 0

	if !ctx.JA4Known {
		score += secCfg.Weights.JA4Unknown
	}

	// Il traffico legittimo è atteso dall'Italia ("IT") o da reti locali di test ("ZZ")
	if ctx.CountryCode != "IT" && ctx.CountryCode != "ZZ" {
		score += secCfg.Weights.GeoAnomaly
	}


	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	slog.Info("Risk Engine eseguito",
		"remote_ip", ctx.RemoteIP,
		"score", score,
		"ja4_known", ctx.JA4Known,
		"country", ctx.CountryCode,
	)

	switch {
	case score >= secCfg.Thresholds.Drop:
		return "DROP", 0
	case score >= secCfg.Thresholds.TarpitHard:
		return "TARPIT_HARD", 12 * time.Second
	case score >= secCfg.Thresholds.TarpitSoft:
		return "TARPIT_SOFT", 3 * time.Second
	default:
		return "ALLOW", 0
	}
}

// --- MODULO 6: PROXY ARCHITECTURE ---

type IMAPProxy struct {
	mu           sync.RWMutex
	tlsConfig    *tls.Config
	tracker      *RedisTracker
	geoDB        *geoip2.Reader
	handshakeMap sync.Map
	activeConns  sync.Map
	atomicCfg    *AtomicConfig
}

func NewIMAPProxy(atomicCfg *AtomicConfig, tracker *RedisTracker) (*IMAPProxy, error) {
	initialCfg := atomicCfg.Load()
	cert, err := tls.LoadX509KeyPair(initialCfg.Server.CertFile, initialCfg.Server.KeyFile)
	if err != nil {
		return nil, err
	}

	// GeoIP is optional so the proxy can run without a local database.
	db, err := geoip2.Open(initialCfg.Security.GeoIPDBPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Warn("Database MaxMind GeoIP non presente; uso country code ZZ", "path", initialCfg.Security.GeoIPDBPath)
			db = nil
		} else {
			return nil, fmt.Errorf("impossibile aprire il database MaxMind GeoIP: %w", err)
		}
	}

	proxy := &IMAPProxy{
		tracker:   tracker,
		geoDB:     db,
		atomicCfg: atomicCfg,
	}

	proxy.tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		GetConfigForClient: proxy.handleGetConfigForClient,
	}

	return proxy, nil
}

func (p *IMAPProxy) handleGetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	fp := ja4plus.JA4(hello)
	remoteAddr := hello.Conn.RemoteAddr().String()
	p.handshakeMap.Store(remoteAddr, fp)

	p.mu.RLock()
	defer p.mu.RUnlock()
	return nil, nil
}

func (p *IMAPProxy) Start(ctx context.Context) error {
	cfg := p.atomicCfg.Load()
	listener, err := net.Listen("tcp", cfg.Server.ListenAddr)
	if err != nil {
		return err
	}
	stopListener := make(chan struct{})
	var connWG sync.WaitGroup
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
			p.activeConns.Range(func(key, _ interface{}) bool {
				key.(net.Conn).Close()
				return true
			})
		case <-stopListener:
		}
	}()
	defer func() {
		close(stopListener)
		listener.Close()
		p.activeConns.Range(func(key, _ interface{}) bool {
			key.(net.Conn).Close()
			return true
		})
		waitDone := make(chan struct{})
		go func() {
			connWG.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(10 * time.Second):
			slog.Warn("Timeout durante l'attesa delle connessioni attive")
		}
	}()

	slog.Info("Proxy in ascolto", "address", cfg.Server.ListenAddr, "backend", cfg.Server.BackendIMAPAddr)

	var temporaryDelay time.Duration
	for {
		rawConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				if temporaryDelay == 0 {
					temporaryDelay = 5 * time.Millisecond
				} else {
					temporaryDelay *= 2
				}
				if temporaryDelay > time.Second {
					temporaryDelay = time.Second
				}
				slog.Warn("Errore temporaneo in Accept; nuovo tentativo", "delay", temporaryDelay, "error", err)
				time.Sleep(temporaryDelay)
				continue
			}
			return fmt.Errorf("accettazione connessione TCP fallita: %w", err)
		}
		temporaryDelay = 0
		connWG.Add(1)
		p.activeConns.Store(rawConn, struct{}{})
		go func(conn net.Conn) {
			defer connWG.Done()
			defer p.activeConns.Delete(conn)
			p.handleConnection(ctx, conn)
		}(rawConn)
	}
}

// ESTRAZIONE GEOGRAFICA REALE VIA MAXMIND
func (p *IMAPProxy) getCountryCode(remoteAddr string) string {
	// Separiamo l'IP dalla porta
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "ZZ"
	}

	// Gestione di sicurezza per indirizzi IP di loopback o privati (RFC 1918)
	if ip.IsLoopback() || ip.IsPrivate() {
		return "ZZ" // Identificatore fittizio per reti locali/test
	}

	p.mu.RLock()
	if p.geoDB == nil {
		p.mu.RUnlock()
		return "ZZ"
	}
	record, err := p.geoDB.Country(ip)
	p.mu.RUnlock()
	if err != nil {
		slog.Error("Errore durante la geolocalizzazione IP", "ip", host, "error", err)
		return "ZZ"
	}

	if record.Country.IsoCode == "" {
		return "ZZ"
	}

	return record.Country.IsoCode
}

func (p *IMAPProxy) handleConnection(ctx context.Context, rawConn net.Conn) {
	remoteAddr := rawConn.RemoteAddr().String()
	defer p.handshakeMap.Delete(remoteAddr)

	currentCfg := p.atomicCfg.Load()

	p.mu.RLock()
	tlsConn := tls.Server(rawConn, p.tlsConfig)
	p.mu.RUnlock()
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		slog.Debug("Handshake TLS fallito", "remote_ip", remoteAddr, "error", err)
		return
	}

	val, ok := p.handshakeMap.Load(remoteAddr)
	if !ok {
		return
	}
	ja4Fp := val.(string)

	slog.Debug("Handshake TLS completato", "remote_ip", remoteAddr, "ja4", ja4Fp)


	// The backend is the sole authentication authority. All IMAP bytes,
	// including its greeting and tagged authentication responses, are relayed.
	country := p.getCountryCode(remoteAddr)
	ja4Known := p.tracker.IsJA4Trusted(ja4Fp)
	clientCtx := &ClientContext{JA4Known: ja4Known, CountryCode: country, RemoteIP: remoteAddr}
	action, delay := EvaluateRisk(clientCtx, currentCfg.Security)
	slog.Info("Connection risk evaluated", "remote_ip", remoteAddr, "action", action, "delay", delay)
	if action == "DROP" {
		return
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}

	backendConn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", currentCfg.Server.BackendIMAPAddr)
	if err != nil {
		slog.Error("IMAP backend connection failed", "error", err)
		return
	}
	defer backendConn.Close()

	observer := newAuthObserver(func(result authResult) {
		// Do not persist or log credentials. Learning-mode persistence is a
		// separate change; an observed success must not grant global JA4 trust.
		slog.Info("Backend IMAP authentication result",
			"remote_ip", remoteAddr, "ja4", ja4Fp,
			"method", result.Method, "outcome", result.Outcome)
	})
	if err := relayObserved(tlsConn, backendConn, observer); err != nil {
		slog.Debug("IMAP relay finished", "remote_ip", remoteAddr, "error", err)
	}
}

func relayBidirectional(client, backend net.Conn, clientToBackend io.Reader) error {
	copyErrors := make(chan error, 2)
	copyStream := func(destination, source net.Conn) {
		_, err := io.Copy(destination, source)
		if closeWriter, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		copyErrors <- err
	}

	go func() {
		_, err := io.Copy(backend, clientToBackend)
		if closeWriter, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
		copyErrors <- err
	}()
	go copyStream(client, backend)
	firstErr := <-copyErrors
	if firstErr != nil {
		_ = client.Close()
		_ = backend.Close()
	}
	secondErr := <-copyErrors
	return errors.Join(firstErr, secondErr)
}

// --- MODULO 7: SIGNAL LISTENER (HOT RELOAD POSIX) ---

func setupSignalHandler(configFile string, atomicCfg *AtomicConfig, proxy *IMAPProxy) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for {
			<-sigChan
			slog.Info("Segnale SIGHUP intercettato, ricaricamento configurazione...")

			newCfg, err := LoadConfig(configFile)
			if err != nil {
				slog.Error("Hot reload fallito: file di configurazione corrotto", "error", err)
				continue
			}

			cert, err := tls.LoadX509KeyPair(newCfg.Server.CertFile, newCfg.Server.KeyFile)
			if err != nil {
				slog.Error("Hot reload fallito: impossibile caricare i nuovi certificati", "error", err)
				continue
			}

			// Ricaricamento a caldo anche del database MaxMind GeoIP se modificato
			newGeoDB, err := geoip2.Open(newCfg.Security.GeoIPDBPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					slog.Warn("Database MaxMind GeoIP non presente dopo il reload; uso country code ZZ", "path", newCfg.Security.GeoIPDBPath)
					newGeoDB = nil
				} else {
					slog.Error("Hot reload fallito: impossibile aprire il nuovo database GeoIP", "error", err)
					continue
				}
			}

			proxy.mu.Lock()
			proxy.tlsConfig.Certificates = []tls.Certificate{cert}
			oldGeoDB := proxy.geoDB
			proxy.geoDB = newGeoDB
			proxy.mu.Unlock()

			// Chiudiamo in sicurezza il vecchio file descriptor del DB sostituito per evitare memory leak
			if oldGeoDB != nil {
				oldGeoDB.Close()
			}

			atomicCfg.Store(newCfg)
			initLogger(newCfg.Logging.Level)

			slog.Info("Configurazione e file GeoIP ricaricati con successo via SIGHUP")
		}
	}()
}

// --- MAIN RUNNER ---

func main() {
	configFile := "config.yaml"
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		if err := checkHealth(configFile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	initialCfg, err := LoadConfig(configFile)
	if err != nil {
		fmt.Printf("Impossibile avviare il server. Config error: %v\n", err)
		os.Exit(1)
	}

	initLogger(initialCfg.Logging.Level)

	atomicCfg := &AtomicConfig{}
	atomicCfg.Store(initialCfg)

	tracker := NewRedisTracker(initialCfg.Redis.Addr, initialCfg.Redis.QueueBufferSize)
	defer tracker.Close()

	proxy, err := NewIMAPProxy(atomicCfg, tracker)
	if err != nil {
		slog.Error("Inizializzazione proxy fallita", "error", err)
		os.Exit(1)
	}

	setupSignalHandler(configFile, atomicCfg, proxy)
	runtimeCtx, stopRuntime := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopRuntime()

	if err := proxy.Start(runtimeCtx); err != nil {
		slog.Error("Esecuzione interrotta per errore critico", "error", err)
		os.Exit(1)
	}
}

func checkHealth(configFile string) error {
	cfg, err := LoadConfig(configFile)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Server.ListenAddr)
	if err != nil {
		return err
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second)
	if err != nil {
		return fmt.Errorf("proxy non in ascolto: %w", err)
	}
	return conn.Close()
}
