// Package ratelimit is a bounded per-key token-bucket limiter for the
// data-plane (design.md §12). Bucket count is capped so fabricated
// company_ids cannot exhaust memory.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter allows `perMinute` operations per key with a burst of the same
// size. At most maxBuckets keys are tracked; idle (fully refilled) buckets
// are swept when the cap is hit, and brand-new keys are denied if the map is
// still full afterwards.
type Limiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	ratePerSec float64
	burst      float64
	maxBuckets int
	now        func() time.Time
}

func New(perMinute, maxBuckets int) *Limiter {
	return &Limiter{
		buckets:    make(map[string]*bucket),
		ratePerSec: float64(perMinute) / 60.0,
		burst:      float64(perMinute),
		maxBuckets: maxBuckets,
		now:        time.Now,
	}
}

// Allow reports whether one operation for key may proceed now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxBuckets {
			l.sweep(now)
			if len(l.buckets) >= l.maxBuckets {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.ratePerSec
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// sweep drops buckets that would be fully refilled by now (i.e. idle keys).
func (l *Limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.ratePerSec >= l.burst {
			delete(l.buckets, k)
		}
	}
}
