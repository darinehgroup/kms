// Package config reads the environment variables of design.md §12.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr     string   // KMS_LISTEN_ADDR — data-plane, e.g. 10.0.0.3:8443
	AdminSocket    string   // KMS_ADMIN_SOCKET — control-plane Unix socket
	DBPath         string   // KMS_DB_PATH — SQLite file
	TLSServerCert  string   // KMS_TLS_SERVER_CERT
	TLSServerKey   string   // KMS_TLS_SERVER_KEY
	TLSClientCA    string   // KMS_TLS_CLIENT_CA
	TLSClientPins  []string // KMS_TLS_CLIENT_PINS — comma-separated SHA-256 fingerprints
	UnwrapPerMin   int      // KMS_RATE_LIMIT_UNWRAP_PER_MIN — per company_id
	MlockRequested bool     // KMS_MLOCK=1 — best-effort mlockall of the process
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// FromEnv loads config with the documented defaults. Validation of the
// fields a given subcommand actually needs happens in that subcommand.
func FromEnv() (Config, error) {
	c := Config{
		ListenAddr:     os.Getenv("KMS_LISTEN_ADDR"),
		AdminSocket:    getenv("KMS_ADMIN_SOCKET", "/run/kms/admin.sock"),
		DBPath:         getenv("KMS_DB_PATH", "/var/lib/kms/kms.db"),
		TLSServerCert:  os.Getenv("KMS_TLS_SERVER_CERT"),
		TLSServerKey:   os.Getenv("KMS_TLS_SERVER_KEY"),
		TLSClientCA:    os.Getenv("KMS_TLS_CLIENT_CA"),
		UnwrapPerMin:   120,
		MlockRequested: os.Getenv("KMS_MLOCK") == "1",
	}
	if pins := os.Getenv("KMS_TLS_CLIENT_PINS"); pins != "" {
		for _, p := range strings.Split(pins, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.TLSClientPins = append(c.TLSClientPins, p)
			}
		}
	}
	if v := os.Getenv("KMS_RATE_LIMIT_UNWRAP_PER_MIN"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("config: KMS_RATE_LIMIT_UNWRAP_PER_MIN must be a positive integer, got %q", v)
		}
		c.UnwrapPerMin = n
	}
	return c, nil
}
