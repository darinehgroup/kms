// Package kcrypto implements the byte formats and primitives specified in
// design.md §3: AES-256-GCM sealing with canonical AAD strings, and
// Argon2id-based KEK encryption at rest.
package kcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
)

const (
	KeySize   = 32 // DEK and KEK are both 256-bit (§3.1)
	NonceSize = 12
	TagSize   = 16
	SaltSize  = 16

	// BlobVersion1 is the leading version byte of every ciphertext blob.
	BlobVersion1 = 0x01
	// KDFArgon2idV1 maps to the fixed parameter set below (§3.3).
	KDFArgon2idV1 = 0x01

	// WrappedDEKSize: version(1) || nonce(12) || ciphertext(32) || tag(16) = 61 (§3.2).
	WrappedDEKSize = 1 + NonceSize + KeySize + TagSize
	// KEKBlobSize: version(1) || kdf_id(1) || salt(16) || nonce(12) || ciphertext(32) || tag(16) = 78 (§3.3).
	KEKBlobSize = 2 + SaltSize + NonceSize + KeySize + TagSize
)

// Argon2id parameter set identified by KDFArgon2idV1, sized for a 1 GiB host.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB = 64 MiB
	argonThreads = 1
)

var (
	ErrOpenFailed = errors.New("kcrypto: authenticated decryption failed")
	ErrBadBlob    = errors.New("kcrypto: malformed ciphertext blob")
)

// NewKey returns 32 bytes from crypto/rand.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("kcrypto: rand: %w", err)
	}
	return k, nil
}

// Zero overwrites b with zeros (best-effort zeroization, §11).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("kcrypto: key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// DEKAAD is the canonical AAD binding a wrapped DEK to its company and KEK
// version: company_id + "|" + kek_version (§3.2).
func DEKAAD(companyID string, kekVersion int64) string {
	return companyID + "|" + strconv.FormatInt(kekVersion, 10)
}

// TOTPAAD binds an encrypted TOTP seed to its label and KEK version (§4).
func TOTPAAD(label string, kekVersion int64) string {
	return "totp|" + label + "|" + strconv.FormatInt(kekVersion, 10)
}

// Seal encrypts plaintext under key with a fresh random nonce and returns
// version(1) || nonce(12) || ciphertext(len) || tag(16).
func Seal(key, plaintext []byte, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kcrypto: rand: %w", err)
	}
	out := make([]byte, 0, 1+NonceSize+len(plaintext)+TagSize)
	out = append(out, BlobVersion1)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, []byte(aad)), nil
}

// Open reverses Seal. Any authentication failure returns ErrOpenFailed.
func Open(key, blob []byte, aad string) ([]byte, error) {
	if len(blob) < 1+NonceSize+TagSize || blob[0] != BlobVersion1 {
		return nil, ErrBadBlob
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := blob[1 : 1+NonceSize]
	ct := blob[1+NonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return nil, ErrOpenFailed
	}
	return pt, nil
}

// WrapDEK wraps a 32-byte DEK under the KEK with the canonical AAD (§3.2).
func WrapDEK(kek, dek []byte, companyID string, kekVersion int64) ([]byte, error) {
	if len(dek) != KeySize {
		return nil, fmt.Errorf("kcrypto: dek must be %d bytes", KeySize)
	}
	return Seal(kek, dek, DEKAAD(companyID, kekVersion))
}

// UnwrapDEK unwraps a 61-byte wrapped DEK. A wrong company_id or kek_version
// makes GCM authentication fail, which is the designed binding check.
func UnwrapDEK(kek, blob []byte, companyID string, kekVersion int64) ([]byte, error) {
	if len(blob) != WrappedDEKSize {
		return nil, ErrBadBlob
	}
	return Open(kek, blob, DEKAAD(companyID, kekVersion))
}

func deriveKey(passphrase, salt []byte, kdfID byte) ([]byte, error) {
	switch kdfID {
	case KDFArgon2idV1:
		return argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, KeySize), nil
	default:
		return nil, fmt.Errorf("kcrypto: unknown kdf id 0x%02x", kdfID)
	}
}

// EncryptKEK encrypts a KEK for storage at rest with a key derived from the
// unseal passphrase, producing the self-describing blob of §3.3 with a fresh
// random salt and nonce.
func EncryptKEK(passphrase, kek []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("kcrypto: kek must be %d bytes", KeySize)
	}
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("kcrypto: rand: %w", err)
	}
	key, err := deriveKey(passphrase, salt, KDFArgon2idV1)
	if err != nil {
		return nil, err
	}
	defer Zero(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kcrypto: rand: %w", err)
	}
	out := make([]byte, 0, KEKBlobSize)
	out = append(out, BlobVersion1, KDFArgon2idV1)
	out = append(out, salt...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, kek, nil), nil
}

// DecryptKEK reverses EncryptKEK. A wrong passphrase returns ErrOpenFailed.
func DecryptKEK(passphrase, blob []byte) ([]byte, error) {
	if len(blob) != KEKBlobSize || blob[0] != BlobVersion1 {
		return nil, ErrBadBlob
	}
	kdfID := blob[1]
	salt := blob[2 : 2+SaltSize]
	nonce := blob[2+SaltSize : 2+SaltSize+NonceSize]
	ct := blob[2+SaltSize+NonceSize:]
	key, err := deriveKey(passphrase, salt, kdfID)
	if err != nil {
		return nil, err
	}
	defer Zero(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return pt, nil
}
