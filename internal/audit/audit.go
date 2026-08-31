// Package audit implements the append-only, hash-chained audit log of
// design.md §4. Every append is serialized by a process-level mutex plus a
// database transaction so the chain can never fork (§11).
package audit

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GenesisPrevHash is the prev_hash of the first record: 64 zeros.
var GenesisPrevHash = strings.Repeat("0", 64)

// ComputeHash implements the canonical preimage of §4:
//
//	prev_hash|id|ts|operation|company_id|kek_version|result
func ComputeHash(prevHash string, id int64, ts, operation, companyID string, kekVersion int64, result string) string {
	preimage := prevHash + "|" + strconv.FormatInt(id, 10) + "|" + ts + "|" +
		operation + "|" + companyID + "|" + strconv.FormatInt(kekVersion, 10) + "|" + result
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:])
}

// Logger appends hash-chained records.
type Logger struct {
	mu  sync.Mutex
	db  *sql.DB
	now func() time.Time
}

func New(db *sql.DB) *Logger {
	return &Logger{db: db, now: time.Now}
}

// Append writes one record, linking it to the previous one. companyID may be
// "" or "-" for non-company operations; it must never contain '|'.
func (l *Logger) Append(operation, companyID string, kekVersion int64, result string) error {
	if companyID == "" {
		companyID = "-"
	}
	if strings.ContainsRune(companyID, '|') {
		return fmt.Errorf("audit: company_id must not contain '|'")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.Begin()
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer tx.Rollback()

	lastID, lastHash := int64(0), GenesisPrevHash
	err = tx.QueryRow(`SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1`).
		Scan(&lastID, &lastHash)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("audit: read tail: %w", err)
	}
	id := lastID + 1
	ts := l.now().UTC().Format(time.RFC3339Nano)
	hash := ComputeHash(lastHash, id, ts, operation, companyID, kekVersion, result)
	if _, err := tx.Exec(
		`INSERT INTO audit_log (id, ts, operation, company_id, kek_version, result, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, ts, operation, companyID, kekVersion, result, lastHash, hash); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

// Verify walks the whole chain and returns the number of valid records.
// It fails on id gaps, broken links, or any hash mismatch.
func Verify(db *sql.DB) (int64, error) {
	rows, err := db.Query(
		`SELECT id, ts, operation, company_id, kek_version, result, prev_hash, hash
		 FROM audit_log ORDER BY id`)
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()

	var count int64
	expectID, prevHash := int64(1), GenesisPrevHash
	for rows.Next() {
		var (
			id, kekVersion                          int64
			ts, op, company, result, prev, recorded string
		)
		if err := rows.Scan(&id, &ts, &op, &company, &kekVersion, &result, &prev, &recorded); err != nil {
			return count, fmt.Errorf("audit: %w", err)
		}
		if id != expectID {
			return count, fmt.Errorf("audit: id gap at record %d (expected %d)", id, expectID)
		}
		if prev != prevHash {
			return count, fmt.Errorf("audit: broken chain at record %d: prev_hash mismatch", id)
		}
		if got := ComputeHash(prev, id, ts, op, company, kekVersion, result); got != recorded {
			return count, fmt.Errorf("audit: hash mismatch at record %d (record tampered)", id)
		}
		prevHash = recorded
		expectID++
		count++
	}
	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("audit: %w", err)
	}
	if count == 0 {
		return 0, fmt.Errorf("audit: log is empty (kms not initialized?)")
	}
	return count, nil
}
