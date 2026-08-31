package core

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/darinehgroup/kms/internal/audit"
	"github.com/darinehgroup/kms/internal/store"
	"github.com/darinehgroup/kms/internal/totp"
)

var (
	shareA = []byte("founder-a-share-secret")
	shareB = []byte("founder-b-share-secret")
)

func newInitializedService(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kms.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	aud := audit.New(st.DB())
	if err := Init(st, aud, shareA, shareB); err != nil {
		t.Fatal(err)
	}
	return New(st, aud, 1000), st
}

func unsealed(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	svc, st := newInitializedService(t)
	if err := svc.Unseal(shareA, shareB); err != nil {
		t.Fatal(err)
	}
	return svc, st
}

func TestInitIdempotentGuard(t *testing.T) {
	svc, st := newInitializedService(t)
	_ = svc
	if err := Init(st, audit.New(st.DB()), shareA, shareB); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: err = %v, want ErrAlreadyInitialized", err)
	}
}

func TestSealedLifecycle(t *testing.T) {
	svc, _ := newInitializedService(t)
	if !svc.Sealed() {
		t.Fatal("service should start sealed")
	}
	if _, _, _, err := svc.GenerateDEK("comp-001"); !errors.Is(err, ErrSealed) {
		t.Fatalf("generate while sealed: err = %v, want ErrSealed", err)
	}
	if _, err := svc.UnwrapDEK("comp-001", make([]byte, 61), 1); !errors.Is(err, ErrSealed) {
		t.Fatalf("unwrap while sealed: err = %v, want ErrSealed", err)
	}
	if err := svc.Unseal(shareA, []byte("wrong-share-b")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("bad unseal: err = %v, want ErrBadPassphrase", err)
	}
	if err := svc.Unseal(shareA, shareB); err != nil {
		t.Fatal(err)
	}
	if svc.Sealed() {
		t.Fatal("service should be unsealed")
	}
	if err := svc.Unseal(shareA, shareB); !errors.Is(err, ErrAlreadyUnsealed) {
		t.Fatalf("double unseal: err = %v, want ErrAlreadyUnsealed", err)
	}
	if err := svc.Seal(); err != nil {
		t.Fatal(err)
	}
	if !svc.Sealed() {
		t.Fatal("service should be sealed again")
	}
}

func TestGenerateUnwrapRoundtrip(t *testing.T) {
	svc, _ := unsealed(t)
	wrapped, version, dek, err := svc.GenerateDEK("comp-001")
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 || len(wrapped) != 61 || len(dek) != 32 {
		t.Fatalf("unexpected generate output: version=%d len(wrapped)=%d len(dek)=%d",
			version, len(wrapped), len(dek))
	}
	got, err := svc.UnwrapDEK("comp-001", wrapped, version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK differs")
	}
	// The GCM/AAD binding is the company_id check (design.md §2).
	if _, err := svc.UnwrapDEK("comp-002", wrapped, version); !errors.Is(err, ErrUnwrapFailed) {
		t.Fatalf("wrong company: err = %v, want ErrUnwrapFailed", err)
	}
	if _, err := svc.UnwrapDEK("comp-001", wrapped, 99); !errors.Is(err, ErrKEKVersionUnknown) {
		t.Fatalf("unknown version: err = %v, want ErrKEKVersionUnknown", err)
	}
}

func TestCompanyIDValidation(t *testing.T) {
	svc, _ := unsealed(t)
	for _, bad := range []string{"", "comp|001", "comp 001", "comp\x00", string(make([]byte, 65))} {
		var inv *InvalidError
		if _, _, _, err := svc.GenerateDEK(bad); !errors.As(err, &inv) {
			t.Errorf("company_id %q: err = %v, want InvalidError", bad, err)
		}
	}
}

func TestRotateKEKAndOldVersionsStillUnwrap(t *testing.T) {
	svc, _ := unsealed(t)
	wrappedOld, v1, dekOld, err := svc.GenerateDEK("comp-001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateKEK(shareA, []byte("wrong-share")); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("rotate with bad passphrase: err = %v, want ErrBadPassphrase", err)
	}
	v2, err := svc.RotateKEK(shareA, shareB)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != v1+1 {
		t.Fatalf("new version = %d, want %d", v2, v1+1)
	}
	// New DEKs wrap under the new version.
	_, gotV, _, err := svc.GenerateDEK("comp-002")
	if err != nil {
		t.Fatal(err)
	}
	if gotV != v2 {
		t.Fatalf("generate used version %d, want %d", gotV, v2)
	}
	// Retired version still unwraps (design.md §5).
	got, err := svc.UnwrapDEK("comp-001", wrappedOld, v1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dekOld) {
		t.Fatal("old-version unwrap returned wrong DEK")
	}
	// Reseal + unseal reloads all versions from disk.
	if err := svc.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := svc.Unseal(shareA, shareB); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UnwrapDEK("comp-001", wrappedOld, v1); err != nil {
		t.Fatalf("old-version unwrap after re-unseal: %v", err)
	}
}

func TestRekeyPassphrase(t *testing.T) {
	svc, _ := unsealed(t)
	if _, err := svc.RotateKEK(shareA, shareB); err != nil {
		t.Fatal(err) // two versions on disk so rekey must cover both
	}
	newA, newB := []byte("new-share-a-value"), []byte("new-share-b-value")
	if err := svc.RekeyPassphrase([]byte("wrong"), shareB, newA, newB); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("rekey with bad old passphrase: err = %v, want ErrBadPassphrase", err)
	}
	if err := svc.RekeyPassphrase(shareA, shareB, newA, newB); err != nil {
		t.Fatal(err)
	}
	if err := svc.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := svc.Unseal(shareA, shareB); !errors.Is(err, ErrBadPassphrase) {
		t.Fatalf("old passphrase after rekey: err = %v, want ErrBadPassphrase", err)
	}
	if err := svc.Unseal(newA, newB); err != nil {
		t.Fatalf("new passphrase after rekey: %v", err)
	}
}

func TestBreakGlassFlow(t *testing.T) {
	svc, st := unsealed(t)
	now := time.Unix(1_700_000_000, 0)
	svc.now = func() time.Time { return now }

	seedA, err := svc.SetTOTP("founder_a")
	if err != nil {
		t.Fatal(err)
	}
	wrapped, version, dek, err := svc.GenerateDEK("comp-001")
	if err != nil {
		t.Fatal(err)
	}
	// Only one seed enrolled: break-glass refuses.
	var inv *InvalidError
	if _, err := svc.BreakGlass("comp-001", wrapped, version,
		totp.CodeAt(seedA, now), "000000"); !errors.As(err, &inv) {
		t.Fatalf("one seed: err = %v, want InvalidError", err)
	}
	seedB, err := svc.SetTOTP("founder_b")
	if err != nil {
		t.Fatal(err)
	}

	// Wrong code from founder B: denied.
	wrong := "000000"
	if wrong == totp.CodeAt(seedB, now) {
		wrong = "000001"
	}
	if _, err := svc.BreakGlass("comp-001", wrapped, version,
		totp.CodeAt(seedA, now), wrong); !errors.Is(err, ErrTOTPDenied) {
		t.Fatalf("bad totp: err = %v, want ErrTOTPDenied", err)
	}

	got, err := svc.BreakGlass("comp-001", wrapped, version,
		totp.CodeAt(seedA, now), totp.CodeAt(seedB, now))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("break-glass returned wrong DEK")
	}

	// Replaying the same codes is denied (anti-replay fix, design.md §9).
	if _, err := svc.BreakGlass("comp-001", wrapped, version,
		totp.CodeAt(seedA, now), totp.CodeAt(seedB, now)); !errors.Is(err, ErrTOTPDenied) {
		t.Fatalf("replayed codes: err = %v, want ErrTOTPDenied", err)
	}
	// Next timestep works again.
	now = now.Add(totp.Period * time.Second)
	if _, err := svc.BreakGlass("comp-001", wrapped, version,
		totp.CodeAt(seedA, now), totp.CodeAt(seedB, now)); err != nil {
		t.Fatalf("next-step codes: %v", err)
	}

	// TOTP seeds survive KEK rotation (rewrap fix, design.md §4).
	if _, err := svc.RotateKEK(shareA, shareB); err != nil {
		t.Fatal(err)
	}
	entries, err := st.TOTPEntries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.KEKVersion != 2 {
			t.Fatalf("totp seed %q still under kek version %d after rotate", e.Label, e.KEKVersion)
		}
	}
	now = now.Add(totp.Period * time.Second)
	if _, err := svc.BreakGlass("comp-001", wrapped, version,
		totp.CodeAt(seedA, now), totp.CodeAt(seedB, now)); err != nil {
		t.Fatalf("break-glass after rotate: %v", err)
	}
}

func TestRateLimitAudited(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "kms.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	aud := audit.New(st.DB())
	if err := Init(st, aud, shareA, shareB); err != nil {
		t.Fatal(err)
	}
	svc := New(st, aud, 2) // 2 per minute
	if err := svc.Unseal(shareA, shareB); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.GenerateDEK("comp-001"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.GenerateDEK("comp-001"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.GenerateDEK("comp-001"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("third op: err = %v, want ErrRateLimited", err)
	}
	var n int
	if err := st.DB().QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE result = 'denied' AND operation = 'generate_dek'`).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("denied audit records = %d, want 1", n)
	}
}

func TestAuditChainStaysValidAcrossLifecycle(t *testing.T) {
	svc, st := unsealed(t)
	svc.GenerateDEK("comp-001")
	svc.UnwrapDEK("comp-001", make([]byte, 61), 1) // fails, audited as error
	svc.RotateKEK(shareA, shareB)
	svc.Seal()
	n, err := audit.Verify(st.DB())
	if err != nil {
		t.Fatal(err)
	}
	if n < 5 {
		t.Fatalf("expected at least 5 audit records, got %d", n)
	}
	// Operation names in the log match the §4 enum.
	rows, err := st.DB().Query(`SELECT DISTINCT operation FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var op string
		rows.Scan(&op)
		seen[op] = true
	}
	for _, want := range []string{OpInit, OpUnseal, OpGenerate, OpUnwrap, OpRotate, OpSeal} {
		if !seen[want] {
			t.Errorf("operation %q missing from audit log", want)
		}
	}
}
