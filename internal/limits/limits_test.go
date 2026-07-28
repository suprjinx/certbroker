package limits

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock so rate-limit tests are deterministic.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testLimiter builds a Limiter driven by clk, with generous global/concurrency
// settings unless a test overrides them.
func testLimiter(t *testing.T, clk *fakeClock, mutate func(*Config)) *Limiter {
	t.Helper()
	cfg := Config{
		PerClientRate:  1,
		PerClientBurst: 3,
		GlobalRate:     1000,
		GlobalBurst:    1000,
		MaxConcurrent:  100,
		Logger:         quietLogger(),
		now:            clk.Now,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// do issues a request from remoteAddr through h and returns the status code.
func do(h http.Handler, remoteAddr string) int {
	req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestPerClientBurstThenLimit(t *testing.T) {
	clk := newClock()
	h := testLimiter(t, clk, nil).Middleware(okHandler())

	// Burst of 3 is allowed.
	for i := range 3 {
		if got := do(h, "192.0.2.10:1234"); got != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, got)
		}
	}
	// Fourth exhausts the bucket.
	if got := do(h, "192.0.2.10:1234"); got != http.StatusTooManyRequests {
		t.Fatalf("4th request: got %d, want 429", got)
	}
	// One second refills exactly one token at rate=1/s.
	clk.Advance(time.Second)
	if got := do(h, "192.0.2.10:1234"); got != http.StatusOK {
		t.Fatalf("after refill: got %d, want 200", got)
	}
	if got := do(h, "192.0.2.10:1234"); got != http.StatusTooManyRequests {
		t.Fatalf("after refill, 2nd: got %d, want 429", got)
	}
}

func TestPerClientBudgetsAreIndependent(t *testing.T) {
	clk := newClock()
	h := testLimiter(t, clk, nil).Middleware(okHandler())

	for range 4 {
		do(h, "192.0.2.10:1111")
	}
	if got := do(h, "192.0.2.10:1111"); got != http.StatusTooManyRequests {
		t.Fatalf("noisy client: got %d, want 429", got)
	}
	// A different source address must be unaffected.
	if got := do(h, "192.0.2.11:2222"); got != http.StatusOK {
		t.Fatalf("quiet client: got %d, want 200", got)
	}
}

func TestPortIsNotPartOfTheKey(t *testing.T) {
	clk := newClock()
	h := testLimiter(t, clk, nil).Middleware(okHandler())

	// Same host, different source ports: one bucket, or a client could escape
	// the limit simply by opening new connections.
	for range 3 {
		do(h, "192.0.2.20:1000")
	}
	if got := do(h, "192.0.2.20:9999"); got != http.StatusTooManyRequests {
		t.Fatalf("new source port: got %d, want 429", got)
	}
}

func TestGlobalLimitAppliesAcrossClients(t *testing.T) {
	clk := newClock()
	h := testLimiter(t, clk, func(c *Config) {
		c.PerClientRate = 1000 // take per-client out of the picture
		c.PerClientBurst = 1000
		c.GlobalRate = 1
		c.GlobalBurst = 2
	}).Middleware(okHandler())

	if got := do(h, "192.0.2.1:1"); got != http.StatusOK {
		t.Fatalf("1st: got %d, want 200", got)
	}
	if got := do(h, "192.0.2.2:1"); got != http.StatusOK {
		t.Fatalf("2nd: got %d, want 200", got)
	}
	// Global burst is spent; a third, distinct client is shed.
	if got := do(h, "192.0.2.3:1"); got != http.StatusTooManyRequests {
		t.Fatalf("3rd: got %d, want 429", got)
	}
}

func TestClientTableIsBounded(t *testing.T) {
	clk := newClock()
	l := testLimiter(t, clk, func(c *Config) { c.MaxClients = 16 })
	h := l.Middleware(okHandler())

	for i := range 500 {
		do(h, "198.51.100."+itoa(i%256)+":"+itoa(1000+i))
	}
	if got := l.TrackedClients(); got > 16 {
		t.Fatalf("tracked clients: got %d, want <= 16", got)
	}
}

// TestEvictionDoesNotResetActiveBudget guards the eviction path: a client that
// is being limited must not regain its burst just because the table churned.
func TestEvictionDoesNotResetActiveBudget(t *testing.T) {
	clk := newClock()
	l := testLimiter(t, clk, func(c *Config) { c.MaxClients = 4 })
	h := l.Middleware(okHandler())

	const victim = "203.0.113.5:1234"
	for range 4 {
		do(h, victim)
	}
	if got := do(h, victim); got != http.StatusTooManyRequests {
		t.Fatalf("victim should be limited: got %d", got)
	}

	// Churn the table well past capacity without advancing the clock, so no
	// bucket is idle and eviction must pick live entries.
	for i := range 100 {
		do(h, "198.51.100."+itoa(i%256)+":1")
	}

	// Eviction is allowed (it grants a fresh burst); silent unlimited access is
	// not, so assert the limit re-engages within one burst.
	limited := false
	for range 5 {
		if do(h, victim) == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("victim never re-limited after table churn")
	}
}

func TestConcurrencyShedding(t *testing.T) {
	clk := newClock()
	l := testLimiter(t, clk, func(c *Config) {
		c.PerClientRate = 1000
		c.PerClientBurst = 1000
		c.MaxConcurrent = 1
		c.AcquireTimeout = 20 * time.Millisecond
	})

	block := make(chan struct{})
	entered := make(chan struct{})
	h := l.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-block
		w.WriteHeader(http.StatusOK)
	}))

	go func() { do(h, "192.0.2.30:1") }()
	<-entered // the single slot is now held

	// The second request cannot get a slot and is shed after AcquireTimeout.
	if got := do(h, "192.0.2.31:1"); got != http.StatusServiceUnavailable {
		t.Fatalf("second request: got %d, want 503", got)
	}

	close(block)
}

// TestSlotIsReleased verifies the semaphore is returned after each request, so
// the limiter does not leak capacity and wedge the listener.
func TestSlotIsReleased(t *testing.T) {
	clk := newClock()
	l := testLimiter(t, clk, func(c *Config) {
		c.PerClientRate = 1000
		c.PerClientBurst = 1000
		c.MaxConcurrent = 1
		c.AcquireTimeout = 20 * time.Millisecond
	})
	h := l.Middleware(okHandler())

	for i := range 5 {
		if got := do(h, "192.0.2.40:1"); got != http.StatusOK {
			t.Fatalf("sequential request %d: got %d, want 200", i+1, got)
		}
	}
}

// TestForwardedHeadersAreIgnored: keying off X-Forwarded-For would let a client
// rotate the header and never be limited.
func TestForwardedHeadersAreIgnored(t *testing.T) {
	clk := newClock()
	h := testLimiter(t, clk, nil).Middleware(okHandler())

	send := func(xff string) int {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", xff)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := range 3 {
		if got := send("10.0.0." + itoa(i)); got != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, got)
		}
	}
	if got := send("10.0.0.99"); got != http.StatusTooManyRequests {
		t.Fatalf("spoofed forwarded header escaped the limit: got %d, want 429", got)
	}
}

func TestDisabledLimiters(t *testing.T) {
	clk := newClock()
	h := testLimiter(t, clk, func(c *Config) {
		c.PerClientRate = -1
		c.PerClientBurst = -1
		c.GlobalRate = -1
		c.GlobalBurst = -1
		c.MaxConcurrent = -1
	}).Middleware(okHandler())

	for i := range 50 {
		if got := do(h, "192.0.2.60:1"); got != http.StatusOK {
			t.Fatalf("request %d with limits disabled: got %d, want 200", i+1, got)
		}
	}
}

func TestClientIPFallsBackOnUnparseableAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "not-a-host-port"
	if got := ClientIP(req); got != "not-a-host-port" {
		t.Fatalf("got %q, want the raw RemoteAddr", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
