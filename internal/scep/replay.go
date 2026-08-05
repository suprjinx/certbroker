package scep

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ReplayCache rejects an already-answered transactionID/senderNonce pair: EST
// gets freshness from TLS, a SCEP message stays valid wherever replayed.
type ReplayCache struct {
	mu      sync.Mutex
	seen    map[string]time.Time
	ttl     time.Duration
	maxSize int
	now     func() time.Time
}

const (
	// DefaultReplayTTL bounds how long a request stays un-replayable. Long
	// enough to cover retries and clock skew, short enough to bound memory.
	DefaultReplayTTL = 15 * time.Minute
	// DefaultReplayMaxEntries caps the table.
	DefaultReplayMaxEntries = 100_000
)

// NewReplayCache builds a cache; non-positive arguments take the defaults.
func NewReplayCache(ttl time.Duration, maxSize int) *ReplayCache {
	if ttl <= 0 {
		ttl = DefaultReplayTTL
	}
	if maxSize <= 0 {
		maxSize = DefaultReplayMaxEntries
	}
	return &ReplayCache{
		seen:    make(map[string]time.Time),
		ttl:     ttl,
		maxSize: maxSize,
		now:     time.Now,
	}
}

// Check records the pair and reports whether it is fresh. Recorded on first
// sight, so a request that failed midway is not retryable either.
func (c *ReplayCache) Check(txID TransactionID, nonce Nonce) bool {
	key := replayKey(txID, nonce)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if expiry, ok := c.seen[key]; ok && now.Before(expiry) {
		return false
	}
	if len(c.seen) >= c.maxSize {
		c.evictLocked(now)
	}
	c.seen[key] = now.Add(c.ttl)
	return true
}

// evictLocked drops expired entries, clearing the table outright if none had
// expired. Under a flood the table is attacker traffic, so a reset is safest.
func (c *ReplayCache) evictLocked(now time.Time) {
	for k, expiry := range c.seen {
		if !now.Before(expiry) {
			delete(c.seen, k)
		}
	}
	if len(c.seen) >= c.maxSize {
		clear(c.seen)
	}
}

// Size reports the number of tracked entries.
func (c *ReplayCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// replayKey hashes the pair so the table holds fixed-size keys regardless of
// what a client sends.
func replayKey(txID TransactionID, nonce Nonce) string {
	h := sha256.New()
	h.Write([]byte(txID))
	h.Write([]byte{0}) // separator: keeps ("ab","c") distinct from ("a","bc")
	h.Write(nonce)
	return hex.EncodeToString(h.Sum(nil))
}
