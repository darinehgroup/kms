package kcrypto

import (
	"bytes"
	"testing"
)

func TestWrapUnwrapDEKRoundtrip(t *testing.T) {
	kek, _ := NewKey()
	dek, _ := NewKey()
	wrapped, err := WrapDEK(kek, dek, "comp-001", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) != WrappedDEKSize {
		t.Fatalf("wrapped size = %d, want %d (design.md §3.2)", len(wrapped), WrappedDEKSize)
	}
	if wrapped[0] != BlobVersion1 {
		t.Fatalf("version byte = 0x%02x, want 0x01", wrapped[0])
	}
	got, err := UnwrapDEK(kek, wrapped, "comp-001", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK differs from original")
	}
}

func TestUnwrapAADBinding(t *testing.T) {
	kek, _ := NewKey()
	dek, _ := NewKey()
	wrapped, _ := WrapDEK(kek, dek, "comp-001", 3)

	if _, err := UnwrapDEK(kek, wrapped, "comp-002", 3); err != ErrOpenFailed {
		t.Fatalf("wrong company_id: err = %v, want ErrOpenFailed", err)
	}
	if _, err := UnwrapDEK(kek, wrapped, "comp-001", 4); err != ErrOpenFailed {
		t.Fatalf("wrong kek_version: err = %v, want ErrOpenFailed", err)
	}
}

func TestUnwrapTamperedBlob(t *testing.T) {
	kek, _ := NewKey()
	dek, _ := NewKey()
	wrapped, _ := WrapDEK(kek, dek, "comp-001", 1)

	tampered := append([]byte(nil), wrapped...)
	tampered[20] ^= 0xff
	if _, err := UnwrapDEK(kek, tampered, "comp-001", 1); err != ErrOpenFailed {
		t.Fatalf("tampered blob: err = %v, want ErrOpenFailed", err)
	}
	if _, err := UnwrapDEK(kek, wrapped[:len(wrapped)-1], "comp-001", 1); err != ErrBadBlob {
		t.Fatalf("truncated blob: err = %v, want ErrBadBlob", err)
	}
	badVersion := append([]byte(nil), wrapped...)
	badVersion[0] = 0x02
	if _, err := UnwrapDEK(kek, badVersion, "comp-001", 1); err != ErrBadBlob {
		t.Fatalf("unknown version byte: err = %v, want ErrBadBlob", err)
	}
}

func TestNoncesAreFresh(t *testing.T) {
	kek, _ := NewKey()
	dek, _ := NewKey()
	a, _ := WrapDEK(kek, dek, "c", 1)
	b, _ := WrapDEK(kek, dek, "c", 1)
	if bytes.Equal(a[1:1+NonceSize], b[1:1+NonceSize]) {
		t.Fatal("two wraps produced the same nonce")
	}
}

func TestEncryptDecryptKEK(t *testing.T) {
	pass := []byte("share-A-secret" + "share-B-secret")
	kek, _ := NewKey()
	blob, err := EncryptKEK(pass, kek)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != KEKBlobSize {
		t.Fatalf("blob size = %d, want %d (design.md §3.3)", len(blob), KEKBlobSize)
	}
	if blob[0] != BlobVersion1 || blob[1] != KDFArgon2idV1 {
		t.Fatalf("header = %02x %02x, want 01 01", blob[0], blob[1])
	}
	got, err := DecryptKEK(pass, blob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, kek) {
		t.Fatal("decrypted KEK differs")
	}
	if _, err := DecryptKEK([]byte("wrong-passphrase-entirely"), blob); err != ErrOpenFailed {
		t.Fatalf("wrong passphrase: err = %v, want ErrOpenFailed", err)
	}
}

func TestEncryptKEKUniqueSalts(t *testing.T) {
	pass := []byte("some-passphrase-shares")
	kek, _ := NewKey()
	a, _ := EncryptKEK(pass, kek)
	b, _ := EncryptKEK(pass, kek)
	if bytes.Equal(a[2:2+SaltSize], b[2:2+SaltSize]) {
		t.Fatal("two KEK encryptions produced the same salt")
	}
}

func TestAADStrings(t *testing.T) {
	if got := DEKAAD("comp-001", 3); got != "comp-001|3" {
		t.Fatalf("DEKAAD = %q, want %q", got, "comp-001|3")
	}
	if got := TOTPAAD("founder_a", 2); got != "totp|founder_a|2" {
		t.Fatalf("TOTPAAD = %q, want %q", got, "totp|founder_a|2")
	}
}
