package ratelimit

import (
	"testing"
	"time"
)

func newTestLimiter(perMinute, maxBuckets int) (*Limiter, *time.Time) {
	l := New(perMinute, maxBuckets)
	now := time.Unix(1_700_000_000, 0)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestBurstThenDeny(t *testing.T) {
	l, _ := newTestLimiter(10, 100)
	for i := 0; i < 10; i++ {
		if !l.Allow("comp-001") {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	if l.Allow("comp-001") {
		t.Fatal("request beyond burst allowed")
	}
	// Other keys are independent.
	if !l.Allow("comp-002") {
		t.Fatal("independent key denied")
	}
}

func TestRefill(t *testing.T) {
	l, now := newTestLimiter(60, 100) // 1 token/sec
	for i := 0; i < 60; i++ {
		l.Allow("c")
	}
	if l.Allow("c") {
		t.Fatal("expected deny after burst")
	}
	*now = now.Add(2 * time.Second)
	if !l.Allow("c") {
		t.Fatal("expected allow after refill")
	}
	if !l.Allow("c") {
		t.Fatal("expected second allow after 2s refill")
	}
	if l.Allow("c") {
		t.Fatal("expected deny after consuming refilled tokens")
	}
}

func TestBucketCapAndSweep(t *testing.T) {
	l, now := newTestLimiter(10, 3)
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	// Map full and nothing idle: new key denied.
	if l.Allow("d") {
		t.Fatal("new key allowed while map full of active buckets")
	}
	// After the existing buckets fully refill they are sweepable.
	*now = now.Add(2 * time.Minute)
	if !l.Allow("d") {
		t.Fatal("new key denied although idle buckets were sweepable")
	}
}
