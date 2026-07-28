package authz

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

// ErrChallenge is returned when a challenge secret is missing or invalid.
var ErrChallenge = errors.New("challenge validation failed")

// ChallengeValidator validates a challenge secret (EST/SCEP challengePassword)
// for an identity. Returning nil means the secret is acceptable.
type ChallengeValidator interface {
	Validate(ctx context.Context, id Identity, provided string) error
}

// NoChallenge accepts unconditionally, even when one IS required. To disable
// challenges leave Pipeline.Challenge nil instead — see cmd wiring.
type NoChallenge struct{}

func (NoChallenge) Validate(context.Context, Identity, string) error { return nil }

// StaticSecret validates one shared secret in constant time. Weak (fleet-wide,
// replayable) but useful for bootstrapping and SCEP compatibility.
type StaticSecret struct {
	secret []byte
}

// NewStaticSecret builds a StaticSecret. An empty secret is rejected.
func NewStaticSecret(secret string) (*StaticSecret, error) {
	if secret == "" {
		return nil, errors.New("challenge: static secret must not be empty")
	}
	return &StaticSecret{secret: []byte(secret)}, nil
}

func (s *StaticSecret) Validate(_ context.Context, _ Identity, provided string) error {
	if subtle.ConstantTimeCompare([]byte(provided), s.secret) != 1 {
		return ErrChallenge
	}
	return nil
}

// MemoryStore holds single-use per-device OTPs, consumed on first success and
// expiring after a TTL. Process-local: needs a shared store for real use.
type MemoryStore struct {
	mu    sync.Mutex
	codes map[string]otp // key: match value (see Add)
	now   func() time.Time
}

type otp struct {
	secret  []byte
	expires time.Time
}

// NewMemoryStore builds an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes: make(map[string]otp),
		now:   time.Now,
	}
}

// Add registers a one-time code for the given key (typically a device CN or
// serial) valid for ttl. It overwrites any existing code for that key.
func (m *MemoryStore) Add(key, code string, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[key] = otp{secret: []byte(code), expires: m.now().Add(ttl)}
}

// Validate consumes the code registered for the identity (matched by CN, then
// serial). A correct, unexpired code succeeds exactly once.
func (m *MemoryStore) Validate(_ context.Context, id Identity, provided string) error {
	if provided == "" {
		return ErrChallenge
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, key := range m.candidateKeys(id) {
		code, ok := m.codes[key]
		if !ok {
			continue
		}
		if m.now().After(code.expires) {
			delete(m.codes, key) // expired; clean up
			return ErrChallenge
		}
		if subtle.ConstantTimeCompare([]byte(provided), code.secret) != 1 {
			return ErrChallenge
		}
		delete(m.codes, key) // single use: consume on success
		return nil
	}
	return ErrChallenge
}

func (m *MemoryStore) candidateKeys(id Identity) []string {
	var keys []string
	if id.CommonName != "" {
		keys = append(keys, id.CommonName)
	}
	if id.RequestedCN != "" && id.RequestedCN != id.CommonName {
		keys = append(keys, id.RequestedCN)
	}
	if id.Serial != "" {
		keys = append(keys, id.Serial)
	}
	return keys
}
