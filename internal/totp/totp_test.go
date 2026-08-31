package totp

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B test vectors (SHA-1, 8 digits).
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, v := range vectors {
		counter := uint64(v.unix / Period)
		if got := hotp(secret, counter, 8); got != v.want {
			t.Errorf("T=%d: got %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestValidateWindowAndReplayCounter(t *testing.T) {
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)

	code := CodeAt(seed, now)
	counter, ok := Validate(seed, code, now, 1)
	if !ok {
		t.Fatal("current code rejected")
	}
	if counter != Counter(now) {
		t.Fatalf("counter = %d, want %d", counter, Counter(now))
	}

	// Codes one step before/after are accepted with skew 1.
	prev := CodeAt(seed, now.Add(-Period*time.Second))
	if _, ok := Validate(seed, prev, now, 1); !ok {
		t.Fatal("previous-step code rejected with skew 1")
	}
	// Two steps away is rejected.
	old := CodeAt(seed, now.Add(-2*Period*time.Second))
	if _, ok := Validate(seed, old, now, 1); ok && old != code && old != prev {
		t.Fatal("two-step-old code accepted")
	}
	if _, ok := Validate(seed, "000000", now, 1); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	if _, ok := Validate(seed, "12345", now, 1); ok {
		t.Fatal("wrong-length code accepted")
	}
}
