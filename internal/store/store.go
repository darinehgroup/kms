// Package store owns the KMS SQLite database: schema (design.md §4),
// KEK version rows, encrypted TOTP seeds, and the transactional KEK
// rotation / passphrase rekey updates.
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS kek_versions (
    id                     INTEGER PRIMARY KEY,
    status                 TEXT NOT NULL CHECK (status IN ('active','retired')),
    encrypted_key_material BLOB NOT NULL,
    created_at             TEXT NOT NULL,
    retired_at             TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_kek ON kek_versions(status) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS admin_totp (
    id             INTEGER PRIMARY KEY,
    label          TEXT NOT NULL UNIQUE,
    encrypted_seed BLOB NOT NULL,
    kek_version    INTEGER NOT NULL REFERENCES kek_versions(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    operation   TEXT NOT NULL CHECK (operation IN
        ('init','generate_dek','unwrap_dek','rotate_kek','break_glass',
         'set_totp','unseal','seal','rekey_passphrase')),
    company_id  TEXT NOT NULL,
    kek_version INTEGER NOT NULL,
    result      TEXT NOT NULL CHECK (result IN ('success','denied','error')),
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
`

type Store struct {
	db *sql.DB
}

func open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// Single connection: this service is the sole writer and the load is
	// tiny; it also keeps transactions and the audit mutex trivially safe.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{db: db}, nil
}

// Open opens (creating if absent) the database read-write with the pragmas
// required by design.md §4: WAL, busy_timeout=5000, foreign_keys=ON.
func Open(path string) (*Store, error) {
	return open("file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
}

// OpenReadOnly opens the database for verification (audit chain walk) without
// the ability to write; safe to use while the server is running (WAL).
func OpenReadOnly(path string) (*Store, error) {
	return open("file:" + path + "?mode=ro&_pragma=busy_timeout(5000)")
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

// InitSchema creates all tables, indexes and triggers.
func (s *Store) InitSchema() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: schema: %w", err)
	}
	return nil
}

// Initialized reports whether any KEK version exists.
func (s *Store) Initialized() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM kek_versions`).Scan(&n); err != nil {
		return false, fmt.Errorf("store: %w", err)
	}
	return n > 0, nil
}

// KEK is one row of kek_versions.
type KEK struct {
	ID        int64
	Status    string
	Material  []byte
	CreatedAt string
	RetiredAt *string
}

// AllKEKs returns every KEK version, oldest first.
func (s *Store) AllKEKs() ([]KEK, error) {
	rows, err := s.db.Query(
		`SELECT id, status, encrypted_key_material, created_at, retired_at
		 FROM kek_versions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	var out []KEK
	for rows.Next() {
		var k KEK
		if err := rows.Scan(&k.ID, &k.Status, &k.Material, &k.CreatedAt, &k.RetiredAt); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ActiveKEK returns the single active KEK version, or nil if none exists.
func (s *Store) ActiveKEK() (*KEK, error) {
	var k KEK
	err := s.db.QueryRow(
		`SELECT id, status, encrypted_key_material, created_at, retired_at
		 FROM kek_versions WHERE status = 'active'`).
		Scan(&k.ID, &k.Status, &k.Material, &k.CreatedAt, &k.RetiredAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &k, nil
}

// InsertKEK inserts an active KEK version with an explicit id (used by init).
func (s *Store) InsertKEK(id int64, material []byte, createdAt string) error {
	_, err := s.db.Exec(
		`INSERT INTO kek_versions (id, status, encrypted_key_material, created_at)
		 VALUES (?, 'active', ?, ?)`, id, material, createdAt)
	if err != nil {
		return fmt.Errorf("store: insert kek: %w", err)
	}
	return nil
}

// TOTPEntry is one row of admin_totp.
type TOTPEntry struct {
	ID            int64
	Label         string
	EncryptedSeed []byte
	KEKVersion    int64
}

// TOTPEntries returns all registered TOTP seeds ordered by id.
func (s *Store) TOTPEntries() ([]TOTPEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, label, encrypted_seed, kek_version FROM admin_totp ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	defer rows.Close()
	var out []TOTPEntry
	for rows.Next() {
		var e TOTPEntry
		if err := rows.Scan(&e.ID, &e.Label, &e.EncryptedSeed, &e.KEKVersion); err != nil {
			return nil, fmt.Errorf("store: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// UpsertTOTP inserts or replaces the seed for a label.
func (s *Store) UpsertTOTP(label string, encryptedSeed []byte, kekVersion int64) error {
	_, err := s.db.Exec(
		`INSERT INTO admin_totp (label, encrypted_seed, kek_version) VALUES (?, ?, ?)
		 ON CONFLICT(label) DO UPDATE SET encrypted_seed = excluded.encrypted_seed,
		                                  kek_version = excluded.kek_version`,
		label, encryptedSeed, kekVersion)
	if err != nil {
		return fmt.Errorf("store: upsert totp: %w", err)
	}
	return nil
}

// RotateKEK atomically retires the active KEK, inserts newMaterial as the new
// active version, and applies the TOTP seed re-encryption produced by
// reencrypt (which receives the new version number and the current entries).
// Returns the new version id.
func (s *Store) RotateKEK(now string, newMaterial []byte,
	reencrypt func(newVersion int64, entries []TOTPEntry) (map[int64][]byte, error)) (int64, error) {

	entries, err := s.TOTPEntries()
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()

	var newID int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(id), 0) + 1 FROM kek_versions`).Scan(&newID); err != nil {
		return 0, fmt.Errorf("store: next version: %w", err)
	}
	updates, err := reencrypt(newID, entries)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(
		`UPDATE kek_versions SET status = 'retired', retired_at = ? WHERE status = 'active'`,
		now); err != nil {
		return 0, fmt.Errorf("store: retire kek: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO kek_versions (id, status, encrypted_key_material, created_at)
		 VALUES (?, 'active', ?, ?)`, newID, newMaterial, now); err != nil {
		return 0, fmt.Errorf("store: insert kek: %w", err)
	}
	for id, blob := range updates {
		if _, err := tx.Exec(
			`UPDATE admin_totp SET encrypted_seed = ?, kek_version = ? WHERE id = ?`,
			blob, newID, id); err != nil {
			return 0, fmt.Errorf("store: rewrap totp: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return newID, nil
}

// UpdateKEKMaterials atomically replaces encrypted_key_material for every
// listed version (passphrase rekey, design.md §5).
func (s *Store) UpdateKEKMaterials(materials map[int64][]byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer tx.Rollback()
	for id, m := range materials {
		res, err := tx.Exec(
			`UPDATE kek_versions SET encrypted_key_material = ? WHERE id = ?`, m, id)
		if err != nil {
			return fmt.Errorf("store: rekey update: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("store: rekey update: kek version %d not found", id)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
