// Package limits bounds the unauthenticated work an enrollment request can
// force: per-client and global rate limits, plus a concurrency cap.
package limits

import (
	"log/slog"
	"math"
	"net"
	"net/http"
	"sync"
	"time"
)

// Defaults sized for an enrollment broker: devices enroll rarely, so sustained
// rates are low and bursts are what matter (a rebooting fleet retries at once).
const (
	DefaultPerClientRate  = 1.0
	DefaultPerClientBurst = 5.0
	DefaultGlobalRate     = 50.0
	DefaultGlobalBurst    = 100.0
	DefaultMaxConcurrent  = 32
	DefaultAcquireTimeout = 5 * time.Second
	DefaultMaxClients     = 65536
)

// sweepBudget keeps eviction O(1) per insert. Go randomizes map iteration, so a
// bounded scan doubles as a random sample.
const sweepBudget = 256

// retryAfterSeconds is the Retry-After sent with 429 and 503.
const retryAfterSeconds = "1"

// Config configures a Limiter. Zero-valued fields take the package defaults;
// a negative rate or burst disables that limiter entirely.
type Config struct {
	// PerClientRate/Burst bound a single source IP's request rate.
	PerClientRate  float64
	PerClientBurst float64
	// GlobalRate/Burst bound the whole listener, as a backstop against a
	// distributed flood that stays under the per-client limit.
	GlobalRate  float64
	GlobalBurst float64
	// MaxConcurrent bounds requests inside the handler at once; 0 uses the
	// default, negative disables.
	MaxConcurrent int
	// AcquireTimeout is how long a request waits for a concurrency slot before
	// being shed with 503.
	AcquireTimeout time.Duration
	// MaxClients bounds the per-client bucket table, so tracking cannot itself
	// become a memory exhaustion vector.
	MaxClients int

	Logger *slog.Logger
	// now is injectable for tests; nil uses time.Now.
	now func() time.Time
}

func (c *Config) withDefaults() {
	if c.PerClientRate == 0 {
		c.PerClientRate = DefaultPerClientRate
	}
	if c.PerClientBurst == 0 {
		c.PerClientBurst = DefaultPerClientBurst
	}
	if c.GlobalRate == 0 {
		c.GlobalRate = DefaultGlobalRate
	}
	if c.GlobalBurst == 0 {
		c.GlobalBurst = DefaultGlobalBurst
	}
	if c.MaxConcurrent == 0 {
		c.MaxConcurrent = DefaultMaxConcurrent
	}
	if c.AcquireTimeout <= 0 {
		c.AcquireTimeout = DefaultAcquireTimeout
	}
	if c.MaxClients <= 0 {
		c.MaxClients = DefaultMaxClients
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.now == nil {
		c.now = time.Now
	}
}

// bucket is a token bucket refilled lazily on access, so an idle client costs
// nothing until it returns.
type bucket struct {
	tokens float64
	last   time.Time
}

// take refills the bucket for elapsed time and consumes one token, reporting
// whether a token was available.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	b.refill(now, rate, burst)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *bucket) refill(now time.Time, rate, burst float64) {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(burst, b.tokens+elapsed*rate)
		b.last = now
	}
}

// idle reports whether the bucket has refilled to capacity, meaning it holds no
// rate-limiting state and can be dropped without giving anyone extra budget.
func (b *bucket) idle(now time.Time, rate, burst float64) bool {
	return b.tokens+math.Max(0, now.Sub(b.last).Seconds())*rate >= burst
}

// keyedLimiter holds one token bucket per key, with a bounded table.
type keyedLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64
	burst    float64
	maxKeys  int
	now      func() time.Time
	disabled bool
}

func newKeyedLimiter(rate, burst float64, maxKeys int, now func() time.Time) *keyedLimiter {
	return &keyedLimiter{
		buckets:  make(map[string]*bucket),
		rate:     rate,
		burst:    burst,
		maxKeys:  maxKeys,
		now:      now,
		disabled: rate < 0 || burst < 0,
	}
}

// allow consumes one token for key.
func (k *keyedLimiter) allow(key string) bool {
	if k.disabled {
		return true
	}
	now := k.now()

	k.mu.Lock()
	defer k.mu.Unlock()

	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= k.maxKeys {
			k.evictLocked(now)
		}
		b = &bucket{tokens: k.burst, last: now}
		k.buckets[key] = b
	}
	return b.take(now, k.rate, k.burst)
}

// evictLocked frees a slot in one bounded pass: idle buckets are dropped, and if
// the sample held none, the least-recently-used entry seen is evicted.
func (k *keyedLimiter) evictLocked(now time.Time) {
	var (
		freed     int
		oldestKey string
		oldest    time.Time
		seen      int
	)
	for key, b := range k.buckets {
		if b.idle(now, k.rate, k.burst) {
			delete(k.buckets, key)
			freed++
		} else if seen == 0 || b.last.Before(oldest) {
			oldestKey, oldest = key, b.last
		}
		seen++
		if seen >= sweepBudget {
			break
		}
	}
	if freed == 0 && oldestKey != "" {
		delete(k.buckets, oldestKey)
	}
}

// size reports the number of tracked keys (test/metrics helper).
func (k *keyedLimiter) size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}

// Limiter is the composed DoS control: per-client rate, global rate, and a
// concurrency bound. The zero value is not usable; build one with New.
type Limiter struct {
	perClient *keyedLimiter
	global    *keyedLimiter // single "" key; reuses the bucket logic

	sem            chan struct{}
	acquireTimeout time.Duration
	logger         *slog.Logger
}

// New builds a Limiter from cfg.
func New(cfg Config) *Limiter {
	cfg.withDefaults()

	l := &Limiter{
		perClient:      newKeyedLimiter(cfg.PerClientRate, cfg.PerClientBurst, cfg.MaxClients, cfg.now),
		global:         newKeyedLimiter(cfg.GlobalRate, cfg.GlobalBurst, 1, cfg.now),
		acquireTimeout: cfg.AcquireTimeout,
		logger:         cfg.Logger,
	}
	if cfg.MaxConcurrent > 0 {
		l.sem = make(chan struct{}, cfg.MaxConcurrent)
	}
	return l
}

// Middleware wraps next with the configured limits. Per-client runs before
// global so one flood is rejected against its own budget, not everyone's.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		client := ClientIP(r)

		if !l.perClient.allow(client) {
			l.reject(w, r, client, "per-client rate limit")
			return
		}
		if !l.global.allow("") {
			l.reject(w, r, client, "global rate limit")
			return
		}

		release, ok := l.acquire(r)
		if !ok {
			l.logger.Warn("request shed: no concurrency slot",
				"remote", client, "path", r.URL.Path)
			w.Header().Set("Retry-After", retryAfterSeconds)
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		defer release()

		next.ServeHTTP(w, r)
	})
}

// acquire takes a concurrency slot, waiting up to AcquireTimeout. The returned
// func releases it and is safe to call exactly once.
func (l *Limiter) acquire(r *http.Request) (func(), bool) {
	if l.sem == nil {
		return func() {}, true
	}
	// Fast path: a slot is immediately free.
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, true
	default:
	}

	timer := time.NewTimer(l.acquireTimeout)
	defer timer.Stop()
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, true
	case <-timer.C:
		return nil, false
	case <-r.Context().Done():
		return nil, false
	}
}

func (l *Limiter) reject(w http.ResponseWriter, r *http.Request, client, reason string) {
	l.logger.Warn("request rate limited", "remote", client, "path", r.URL.Path, "reason", reason)
	w.Header().Set("Retry-After", retryAfterSeconds)
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
}

// TrackedClients reports how many source addresses currently hold buckets.
func (l *Limiter) TrackedClients() int { return l.perClient.size() }

// ClientIP is the rate-limit key. Deliberately r.RemoteAddr only: forwarded
// headers are client-supplied and would let a caller rotate its own key.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
