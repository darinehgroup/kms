// Package core implements the KMS business logic: seal/unseal lifecycle,
// DEK generate/unwrap, KEK rotation, passphrase rekey, TOTP enrollment and
// the two-founder break-glass flow. Every operation is audited; an operation
// whose success cannot be audited fails (fail-closed).
package core

import (
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/darinehgroup/kms/internal/audit"
	"github.com/darinehgroup/kms/internal/kcrypto"
	"github.com/darinehgroup/kms/internal/ratelimit"
	"github.com/darinehgroup/kms/internal/store"
	"github.com/darinehgroup/kms/internal/totp"
)

// Audit operation and result names (design.md §4).
const (
	OpInit       = "init"
	OpGenerate   = "generate_dek"
	OpUnwrap     = "unwrap_dek"
	OpRotate     = "rotate_kek"
	OpBreakGlass = "break_glass"
	OpSetTOTP    = "set_totp"
	OpUnseal     = "unseal"
	OpSeal       = "seal"
	OpRekey      = "rekey_passphrase"

	ResultSuccess = "success"
	ResultDenied  = "denied"
	ResultError   = "error"
)

// MinShareLen is the minimum length of each passphrase share.
const MinShareLen = 8

// maxTrackedCompanies bounds the rate-limiter map (§12 fix).
const maxTrackedCompanies = 100_000

// companyIDRe enforces the §6 fix: no '|' (AAD / audit preimage delimiter)
// can ever appear in a company_id.
var (
	companyIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	labelRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

var (
	ErrSealed             = errors.New("service is sealed")
	ErrAlreadySealed      = errors.New("service is already sealed")
	ErrAlreadyUnsealed    = errors.New("service is already unsealed")
	ErrNotInitialized     = errors.New("kms is not initialized (run 'kms init' first)")
	ErrAlreadyInitialized = errors.New("kms is already initialized")
	ErrBadPassphrase      = errors.New("invalid passphrase shares")
	ErrKEKVersionUnknown  = errors.New("unknown kek version")
	ErrUnwrapFailed       = errors.New("unwrap failed")
	ErrRateLimited        = errors.New("rate limited")
	ErrTOTPDenied         = errors.New("totp verification denied")
)

// InvalidError is a request-validation failure surfaced as INVALID_REQUEST.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalidf(format string, a ...any) error {
	return &InvalidError{Msg: fmt.Sprintf(format, a...)}
}

func nowRFC3339() string { return time.Now().UTC().Format(time.RFC3339) }

// joinShares builds the full passphrase share_A || share_B (§8). The caller
// must Zero the result.
func joinShares(a, b []byte) []byte {
	p := make([]byte, 0, len(a)+len(b))
	p = append(p, a...)
	return append(p, b...)
}

func validateShare(name string, s []byte) error {
	if len(s) < MinShareLen {
		return invalidf("%s must be at least %d characters", name, MinShareLen)
	}
	return nil
}

// Init creates KEK version 1 and the genesis audit record (design.md §5).
// It runs standalone, before the server ever serves.
func Init(st *store.Store, aud *audit.Logger, shareA, shareB []byte) error {
	if err := st.InitSchema(); err != nil {
		return err
	}
	initialized, err := st.Initialized()
	if err != nil {
		return err
	}
	if initialized {
		return ErrAlreadyInitialized
	}
	if err := validateShare("share A", shareA); err != nil {
		return err
	}
	if err := validateShare("share B", shareB); err != nil {
		return err
	}
	pass := joinShares(shareA, shareB)
	defer kcrypto.Zero(pass)
	kek, err := kcrypto.NewKey()
	if err != nil {
		return err
	}
	defer kcrypto.Zero(kek)
	material, err := kcrypto.EncryptKEK(pass, kek)
	if err != nil {
		return err
	}
	if err := st.InsertKEK(1, material, nowRFC3339()); err != nil {
		return err
	}
	return aud.Append(OpInit, "-", 1, ResultSuccess)
}

// Service is the unsealed-state keyring plus all key operations. It starts
// sealed; Unseal populates the in-memory keyring from disk.
type Service struct {
	st      *store.Store
	aud     *audit.Logger
	limiter *ratelimit.Limiter

	mu       sync.RWMutex
	keks     map[int64][]byte // version -> plaintext KEK; nil while sealed
	active   int64
	totpLast map[string]int64 // label -> last accepted timestep (anti-replay)
	now      func() time.Time
}

func New(st *store.Store, aud *audit.Logger, ratePerMinute int) *Service {
	return &Service{
		st:      st,
		aud:     aud,
		limiter: ratelimit.New(ratePerMinute, maxTrackedCompanies),
		now:     time.Now,
	}
}

// Sealed reports whether the keyring is absent.
func (s *Service) Sealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keks == nil
}

// Unseal decrypts every KEK version (active and retired — retired ones are
// still needed for unwrap) with the 2-of-2 passphrase and loads the keyring.
// Both successful and failed attempts are audited.
func (s *Service) Unseal(shareA, shareB []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keks != nil {
		return ErrAlreadyUnsealed
	}
	keks, err := s.st.AllKEKs()
	if err != nil {
		return err
	}
	if len(keks) == 0 {
		return ErrNotInitialized
	}
	pass := joinShares(shareA, shareB)
	defer kcrypto.Zero(pass)

	keyring := make(map[int64][]byte, len(keks))
	var active int64
	for _, k := range keks {
		key, derr := kcrypto.DecryptKEK(pass, k.Material)
		if derr != nil {
			zeroKeyring(keyring)
			s.aud.Append(OpUnseal, "-", k.ID, ResultError)
			return ErrBadPassphrase
		}
		keyring[k.ID] = key
		if k.Status == "active" {
			active = k.ID
		}
	}
	if active == 0 {
		zeroKeyring(keyring)
		return fmt.Errorf("core: no active kek version in database")
	}
	if err := s.aud.Append(OpUnseal, "-", active, ResultSuccess); err != nil {
		zeroKeyring(keyring)
		return fmt.Errorf("core: unseal not audited, refusing to unseal: %w", err)
	}
	s.keks = keyring
	s.active = active
	s.totpLast = make(map[string]int64)
	return nil
}

// Seal zeroizes and drops the keyring.
func (s *Service) Seal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keks == nil {
		return ErrAlreadySealed
	}
	active := s.active
	zeroKeyring(s.keks)
	s.keks = nil
	s.active = 0
	s.totpLast = nil
	return s.aud.Append(OpSeal, "-", active, ResultSuccess)
}

func zeroKeyring(m map[int64][]byte) {
	for _, k := range m {
		kcrypto.Zero(k)
	}
}

// GenerateDEK creates a fresh 256-bit DEK for a company and wraps it under
// the active KEK (design.md §6, POST /v1/dek/generate).
func (s *Service) GenerateDEK(companyID string) (wrapped []byte, kekVersion int64, dek []byte, err error) {
	if !companyIDRe.MatchString(companyID) {
		return nil, 0, nil, invalidf("company_id must match ^[A-Za-z0-9_-]{1,64}$")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.keks == nil {
		return nil, 0, nil, ErrSealed
	}
	if !s.limiter.Allow(companyID) {
		s.aud.Append(OpGenerate, companyID, s.active, ResultDenied)
		return nil, 0, nil, ErrRateLimited
	}
	dek, err = kcrypto.NewKey()
	if err != nil {
		return nil, 0, nil, err
	}
	wrapped, err = kcrypto.WrapDEK(s.keks[s.active], dek, companyID, s.active)
	if err != nil {
		kcrypto.Zero(dek)
		s.aud.Append(OpGenerate, companyID, s.active, ResultError)
		return nil, 0, nil, err
	}
	if err := s.aud.Append(OpGenerate, companyID, s.active, ResultSuccess); err != nil {
		kcrypto.Zero(dek)
		return nil, 0, nil, fmt.Errorf("core: generate not audited, refusing: %w", err)
	}
	return wrapped, s.active, dek, nil
}

// UnwrapDEK unwraps a wrapped DEK (design.md §6, POST /v1/dek/unwrap). Any
// cryptographic failure — wrong company_id, wrong version bound in the AAD,
// or a corrupted blob — surfaces as the single generic ErrUnwrapFailed to
// avoid an oracle; the distinction lives only in the audit log.
func (s *Service) UnwrapDEK(companyID string, wrapped []byte, kekVersion int64) ([]byte, error) {
	if !companyIDRe.MatchString(companyID) {
		return nil, invalidf("company_id must match ^[A-Za-z0-9_-]{1,64}$")
	}
	if kekVersion < 1 {
		return nil, invalidf("kek_version must be a positive integer")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.keks == nil {
		return nil, ErrSealed
	}
	if !s.limiter.Allow(companyID) {
		s.aud.Append(OpUnwrap, companyID, kekVersion, ResultDenied)
		return nil, ErrRateLimited
	}
	kek, ok := s.keks[kekVersion]
	if !ok {
		s.aud.Append(OpUnwrap, companyID, kekVersion, ResultError)
		return nil, ErrKEKVersionUnknown
	}
	dek, err := kcrypto.UnwrapDEK(kek, wrapped, companyID, kekVersion)
	if err != nil {
		s.aud.Append(OpUnwrap, companyID, kekVersion, ResultError)
		return nil, ErrUnwrapFailed
	}
	if err := s.aud.Append(OpUnwrap, companyID, kekVersion, ResultSuccess); err != nil {
		kcrypto.Zero(dek)
		return nil, fmt.Errorf("core: unwrap not audited, refusing: %w", err)
	}
	return dek, nil
}

// RotateKEK creates a new active KEK version and retires the old one
// (design.md §5). Both shares are required again: the server keeps only the
// decrypted KEKs after unseal — not the passphrase — and every version has
// its own Argon2id salt. TOTP seeds are re-encrypted under the new KEK in
// the same transaction.
func (s *Service) RotateKEK(shareA, shareB []byte) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keks == nil {
		return 0, ErrSealed
	}
	pass := joinShares(shareA, shareB)
	defer kcrypto.Zero(pass)

	activeRow, err := s.st.ActiveKEK()
	if err != nil {
		return 0, err
	}
	if activeRow == nil {
		return 0, fmt.Errorf("core: no active kek version in database")
	}
	verify, err := kcrypto.DecryptKEK(pass, activeRow.Material)
	if err != nil {
		s.aud.Append(OpRotate, "-", s.active, ResultDenied)
		return 0, ErrBadPassphrase
	}
	kcrypto.Zero(verify)

	newKEK, err := kcrypto.NewKey()
	if err != nil {
		return 0, err
	}
	newMaterial, err := kcrypto.EncryptKEK(pass, newKEK)
	if err != nil {
		kcrypto.Zero(newKEK)
		return 0, err
	}
	newID, err := s.st.RotateKEK(nowRFC3339(), newMaterial,
		func(newVersion int64, entries []store.TOTPEntry) (map[int64][]byte, error) {
			updates := make(map[int64][]byte, len(entries))
			for _, e := range entries {
				oldKEK, ok := s.keks[e.KEKVersion]
				if !ok {
					return nil, fmt.Errorf("core: totp seed %q encrypted under unknown kek version %d", e.Label, e.KEKVersion)
				}
				seed, err := kcrypto.Open(oldKEK, e.EncryptedSeed, kcrypto.TOTPAAD(e.Label, e.KEKVersion))
				if err != nil {
					return nil, fmt.Errorf("core: decrypt totp seed %q: %w", e.Label, err)
				}
				blob, err := kcrypto.Seal(newKEK, seed, kcrypto.TOTPAAD(e.Label, newVersion))
				kcrypto.Zero(seed)
				if err != nil {
					return nil, err
				}
				updates[e.ID] = blob
			}
			return updates, nil
		})
	if err != nil {
		kcrypto.Zero(newKEK)
		s.aud.Append(OpRotate, "-", s.active, ResultError)
		return 0, err
	}
	s.keks[newID] = newKEK
	s.active = newID
	if err := s.aud.Append(OpRotate, "-", newID, ResultSuccess); err != nil {
		return newID, fmt.Errorf("core: rotation succeeded but audit failed: %w", err)
	}
	return newID, nil
}

// RekeyPassphrase re-encrypts every retained KEK version (active and
// retired) under a new passphrase without changing any KEK (design.md §5).
// Works whether sealed or unsealed; the seal state is not changed.
func (s *Service) RekeyPassphrase(oldA, oldB, newA, newB []byte) error {
	if err := validateShare("new share A", newA); err != nil {
		return err
	}
	if err := validateShare("new share B", newB); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	keks, err := s.st.AllKEKs()
	if err != nil {
		return err
	}
	if len(keks) == 0 {
		return ErrNotInitialized
	}
	oldPass := joinShares(oldA, oldB)
	defer kcrypto.Zero(oldPass)
	newPass := joinShares(newA, newB)
	defer kcrypto.Zero(newPass)

	var activeID int64
	materials := make(map[int64][]byte, len(keks))
	for _, k := range keks {
		if k.Status == "active" {
			activeID = k.ID
		}
		key, derr := kcrypto.DecryptKEK(oldPass, k.Material)
		if derr != nil {
			s.aud.Append(OpRekey, "-", k.ID, ResultDenied)
			return ErrBadPassphrase
		}
		m, eerr := kcrypto.EncryptKEK(newPass, key)
		kcrypto.Zero(key)
		if eerr != nil {
			return eerr
		}
		materials[k.ID] = m
	}
	if err := s.st.UpdateKEKMaterials(materials); err != nil {
		s.aud.Append(OpRekey, "-", activeID, ResultError)
		return err
	}
	return s.aud.Append(OpRekey, "-", activeID, ResultSuccess)
}

// SetTOTP generates and stores a founder TOTP seed encrypted under the
// active KEK (design.md §9). The plaintext seed is returned once for
// enrollment; the caller must zeroize it.
func (s *Service) SetTOTP(label string) ([]byte, error) {
	if !labelRe.MatchString(label) {
		return nil, invalidf("label must match ^[A-Za-z0-9_-]{1,32}$")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keks == nil {
		return nil, ErrSealed
	}
	seed, err := totp.NewSeed()
	if err != nil {
		return nil, err
	}
	blob, err := kcrypto.Seal(s.keks[s.active], seed, kcrypto.TOTPAAD(label, s.active))
	if err != nil {
		kcrypto.Zero(seed)
		return nil, err
	}
	if err := s.st.UpsertTOTP(label, blob, s.active); err != nil {
		kcrypto.Zero(seed)
		return nil, err
	}
	if err := s.aud.Append(OpSetTOTP, "-", s.active, ResultSuccess); err != nil {
		kcrypto.Zero(seed)
		return nil, fmt.Errorf("core: set-totp not audited, refusing: %w", err)
	}
	return seed, nil
}

// BreakGlass performs an out-of-band unwrap requiring valid, unreplayed TOTP
// codes from both founders (design.md §9). codeA belongs to the first
// registered label, codeB to the second.
func (s *Service) BreakGlass(companyID string, wrapped []byte, kekVersion int64, codeA, codeB string) ([]byte, error) {
	if !companyIDRe.MatchString(companyID) {
		return nil, invalidf("company_id must match ^[A-Za-z0-9_-]{1,64}$")
	}
	if kekVersion < 1 {
		return nil, invalidf("kek_version must be a positive integer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keks == nil {
		return nil, ErrSealed
	}
	entries, err := s.st.TOTPEntries()
	if err != nil {
		return nil, err
	}
	if len(entries) != 2 {
		return nil, invalidf("break-glass requires exactly two registered TOTP seeds (found %d); enroll both founders with set-totp", len(entries))
	}
	now := s.now()
	codes := [2]string{codeA, codeB}
	var counters [2]int64
	for i, e := range entries {
		kek, ok := s.keks[e.KEKVersion]
		if !ok {
			return nil, fmt.Errorf("core: totp seed %q encrypted under unknown kek version %d", e.Label, e.KEKVersion)
		}
		seed, derr := kcrypto.Open(kek, e.EncryptedSeed, kcrypto.TOTPAAD(e.Label, e.KEKVersion))
		if derr != nil {
			return nil, fmt.Errorf("core: decrypt totp seed %q: %w", e.Label, derr)
		}
		counter, valid := totp.Validate(seed, codes[i], now, 1)
		kcrypto.Zero(seed)
		if !valid || counter <= s.totpLast[e.Label] {
			s.aud.Append(OpBreakGlass, companyID, kekVersion, ResultDenied)
			return nil, ErrTOTPDenied
		}
		counters[i] = counter
	}
	for i, e := range entries {
		s.totpLast[e.Label] = counters[i]
	}
	kek, ok := s.keks[kekVersion]
	if !ok {
		s.aud.Append(OpBreakGlass, companyID, kekVersion, ResultError)
		return nil, ErrKEKVersionUnknown
	}
	dek, err := kcrypto.UnwrapDEK(kek, wrapped, companyID, kekVersion)
	if err != nil {
		s.aud.Append(OpBreakGlass, companyID, kekVersion, ResultError)
		return nil, ErrUnwrapFailed
	}
	if err := s.aud.Append(OpBreakGlass, companyID, kekVersion, ResultSuccess); err != nil {
		kcrypto.Zero(dek)
		return nil, fmt.Errorf("core: break-glass not audited, refusing: %w", err)
	}
	return dek, nil
}

// Status is the control-plane status summary. No secrets.
type Status struct {
	Initialized      bool  `json:"initialized"`
	Sealed           bool  `json:"sealed"`
	ActiveKEKVersion int64 `json:"active_kek_version,omitempty"`
	KEKVersions      int   `json:"kek_versions"`
	TOTPSeeds        int   `json:"totp_seeds"`
}

func (s *Service) Status() (Status, error) {
	keks, err := s.st.AllKEKs()
	if err != nil {
		return Status{}, err
	}
	entries, err := s.st.TOTPEntries()
	if err != nil {
		return Status{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Status{
		Initialized:      len(keks) > 0,
		Sealed:           s.keks == nil,
		ActiveKEKVersion: s.active,
		KEKVersions:      len(keks),
		TOTPSeeds:        len(entries),
	}, nil
}
