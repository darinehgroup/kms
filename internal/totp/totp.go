// Package totp is a minimal RFC 6238 (TOTP) / RFC 4226 (HOTP) implementation
// for the two-founder break-glass flow (design.md §9). SHA-1, 6 digits,
// 30-second steps — the parameters every common authenticator app defaults to.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	Digits   = 6
	Period   = 30 // seconds
	SeedSize = 20 // 160-bit seed, the RFC 4226 recommendation
)

// NewSeed returns a fresh random 20-byte seed.
func NewSeed() ([]byte, error) {
	s := make([]byte, SeedSize)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("totp: rand: %w", err)
	}
	return s, nil
}

func hotp(secret []byte, counter uint64, digits int) string {
	mac := hmac.New(sha1.New, secret)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// Counter returns the TOTP timestep for t.
func Counter(t time.Time) int64 {
	return t.Unix() / Period
}

// CodeAt computes the 6-digit code for time t.
func CodeAt(secret []byte, t time.Time) string {
	return hotp(secret, uint64(Counter(t)), Digits)
}

// Validate checks code against the timesteps t-skew..t+skew and returns the
// matched timestep (for anti-replay tracking) and whether it matched.
// Comparison is constant-time.
func Validate(secret []byte, code string, t time.Time, skew int) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	base := Counter(t)
	for d := -skew; d <= skew; d++ {
		c := base + int64(d)
		if c < 0 {
			continue
		}
		want := hotp(secret, uint64(c), Digits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// Base32Secret encodes the seed the way authenticator apps expect.
func Base32Secret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// ProvisioningURI renders an otpauth:// URI for QR/manual enrollment.
func ProvisioningURI(issuer, label string, secret []byte) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(issuer), url.PathEscape(label),
		Base32Secret(secret), url.QueryEscape(issuer), Digits, Period,
	)
}
