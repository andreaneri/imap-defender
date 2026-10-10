package main

import (
	"log/slog"
	"net"
	"time"
)

// authEvent joins backend results with independent connection signals.
// Observed usernames are client claims, not canonical backend account IDs.
type authEvent struct {
	authResult
	Timestamp   time.Time
	RemoteIP    string
	CountryCode string
	JA4         string
}

func newAuthEvent(result authResult, remoteIP, countryCode, ja4 string) authEvent {
	if host, _, err := net.SplitHostPort(remoteIP); err == nil {
		remoteIP = host
	}
	return authEvent{authResult: result, Timestamp: time.Now().UTC(), RemoteIP: remoteIP, CountryCode: countryCode, JA4: ja4}
}

func logAuthEvent(logger *slog.Logger, event authEvent) {
	logger.Info("IMAP authentication observation",
		"observed_at", event.Timestamp, "remote_ip", event.RemoteIP,
		"country_code", event.CountryCode, "ja4", event.JA4,
		"username_known", event.UsernameKnown, "username", event.Username,
		"authorization_id", event.AuthorizationID,
		"method", event.Method, "mechanism", event.Mechanism, "outcome", event.Outcome)
}
