package audit

import (
	"path/filepath"
	"testing"

	"github.com/darinehgroup/kms/internal/store"
)

func newTestDB(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "kms.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.InitSchema(); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestChainAppendAndVerify(t *testing.T) {
	st := newTestDB(t)
	l := New(st.DB())

	if err := l.Append("init", "-", 1, "success"); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("generate_dek", "comp-001", 1, "success"); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("unwrap_dek", "comp-001", 1, "denied"); err != nil {
		t.Fatal(err)
	}
	n, err := Verify(st.DB())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("verified %d records, want 3", n)
	}

	// Genesis record must carry the all-zero prev_hash.
	var prev string
	if err := st.DB().QueryRow(`SELECT prev_hash FROM audit_log WHERE id = 1`).Scan(&prev); err != nil {
		t.Fatal(err)
	}
	if prev != GenesisPrevHash {
		t.Fatalf("genesis prev_hash = %q", prev)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	st := newTestDB(t)
	l := New(st.DB())
	if err := l.Append("init", "-", 1, "success"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE audit_log SET result = 'denied' WHERE id = 1`); err == nil {
		t.Fatal("UPDATE on audit_log succeeded; trigger missing")
	}
	if _, err := st.DB().Exec(`DELETE FROM audit_log WHERE id = 1`); err == nil {
		t.Fatal("DELETE on audit_log succeeded; trigger missing")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	st := newTestDB(t)
	l := New(st.DB())
	for _, op := range []string{"init", "generate_dek", "unwrap_dek"} {
		if err := l.Append(op, "comp-x", 1, "success"); err != nil {
			t.Fatal(err)
		}
	}
	// Bypass the trigger the way a hostile admin would, then check that the
	// chain math still catches it.
	if _, err := st.DB().Exec(`DROP TRIGGER audit_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE audit_log SET company_id = 'comp-y' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(st.DB()); err == nil {
		t.Fatal("Verify accepted a tampered record")
	}
}

func TestVerifyDetectsDeletedTail(t *testing.T) {
	st := newTestDB(t)
	l := New(st.DB())
	for _, op := range []string{"init", "generate_dek", "unwrap_dek"} {
		if err := l.Append(op, "-", 1, "success"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DB().Exec(`DROP TRIGGER audit_no_delete`); err != nil {
		t.Fatal(err)
	}
	// Deleting a middle record leaves an id gap.
	if _, err := st.DB().Exec(`DELETE FROM audit_log WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(st.DB()); err == nil {
		t.Fatal("Verify accepted a chain with a deleted record")
	}
}

func TestRejectsPipeInCompanyID(t *testing.T) {
	st := newTestDB(t)
	l := New(st.DB())
	if err := l.Append("generate_dek", "a|b", 1, "success"); err == nil {
		t.Fatal("company_id containing '|' accepted")
	}
}
