package scep

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ReplayCache rejects a transactionID/senderNonce pair the broker has already
// answered.
//
// EST needs no equivalent: TLS gives each request its own freshness. A SCEP
// request is a signed blob that stays valid wherever it is replayed, so without
// this a captured PKCSReq can be resubmitted indefinitely — every replay
// consuming a single-use challenge slot or minting another certificate.
//
// Process-local, like the OTP store: it does not survive a restart and does not
// coordinate across replicas. Sized and swept so an attacker cannot grow it
// without bound.
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

// Check records the pair and reports whether it is fresh. A false return means
// the request is a replay and must be refused.
//
// Recording happens on first sight rather than after successful issuance: a
// request that failed midway must not be retryable either, since the failure
// may be exactly what the attacker is probing.
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

// evictLocked drops expired entries, and if none had expired, clears the table
// outright. Dropping live entries risks admitting a replay; refusing all new
// requests would be a denial of service. Under a flood the table is attacker
// traffic anyway, so a reset is the lesser harm — and the TTL keeps this rare.
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
