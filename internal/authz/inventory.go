package authz

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Record is what an inventory backend returns for a device. It may carry
// per-device constraints that tighten the global policy.
type Record struct {
	// Found indicates whether the device is present/permitted in inventory.
	Found bool
	// AllowedDNSNames optionally restricts which SANs this device may request
	// (glob patterns). Empty means the global policy decides.
	AllowedDNSNames []string
	// RequireChallenge forces challenge-password validation for this device.
	RequireChallenge bool
	// Role optionally overrides role selection for this device.
	Role string
}

// Inventory answers "is this device permitted, and under what per-device
// constraints?". Implementations must be safe for concurrent use.
type Inventory interface {
	Lookup(ctx context.Context, id Identity) (Record, error)
}

// NoInventory permits every device. Use only when mTLS + challenge + constraint
// policy carry the whole authorization decision.
type NoInventory struct{}

func (NoInventory) Lookup(context.Context, Identity) (Record, error) {
	return Record{Found: true}, nil
}

// deviceEntry is one row of the file-backed allowlist.
type deviceEntry struct {
	// Match keys (any that are set must match; at least one is required).
	CN          string `yaml:"cn"`          // glob against authenticated CN, else requested CN
	Serial      string `yaml:"serial"`      // exact, lowercase hex
	Fingerprint string `yaml:"fingerprint"` // exact, lowercase hex (sha256 of cert DER)

	AllowedDNSNames  []string `yaml:"allowed_dns"`
	RequireChallenge bool     `yaml:"require_challenge"`
	Role             string   `yaml:"role"`
}

type inventoryFile struct {
	Devices []deviceEntry `yaml:"devices"`
}

// FileInventory is a reference allowlist backed by a YAML file. It is safe for
// concurrent reads; call Reload to pick up on-disk changes.
type FileInventory struct {
	path string

	mu      sync.RWMutex
	devices []deviceEntry
}

// NewFileInventory loads an allowlist from path.
func NewFileInventory(path string) (*FileInventory, error) {
	fi := &FileInventory{path: path}
	if err := fi.Reload(); err != nil {
		return nil, err
	}
	return fi, nil
}

// Reload re-reads the allowlist file.
func (f *FileInventory) Reload() error {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("inventory: read %s: %w", f.path, err)
	}
	var parsed inventoryFile
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("inventory: parse %s: %w", f.path, err)
	}
	for i, d := range parsed.Devices {
		if d.CN == "" && d.Serial == "" && d.Fingerprint == "" {
			return fmt.Errorf("inventory: device[%d] has no match key (cn/serial/fingerprint)", i)
		}
	}
	f.mu.Lock()
	f.devices = parsed.Devices
	f.mu.Unlock()
	return nil
}

// Lookup returns the first matching device record.
func (f *FileInventory) Lookup(_ context.Context, id Identity) (Record, error) {
	f.mu.RLock()
	devices := f.devices
	f.mu.RUnlock()

	cn := id.CommonName
	if cn == "" {
		cn = id.RequestedCN
	}

	for _, d := range devices {
		if !entryMatches(d, id, cn) {
			continue
		}
		return Record{
			Found:            true,
			AllowedDNSNames:  d.AllowedDNSNames,
			RequireChallenge: d.RequireChallenge,
			Role:             d.Role,
		}, nil
	}
	return Record{Found: false}, nil
}

// entryMatches reports whether a device entry matches the identity. Every match
// key that is set on the entry must match (AND); keys left empty are ignored.
func entryMatches(d deviceEntry, id Identity, cn string) bool {
	if d.CN != "" && !globMatch(d.CN, cn) {
		return false
	}
	if d.Serial != "" && !strings.EqualFold(d.Serial, id.Serial) {
		return false
	}
	if d.Fingerprint != "" && !strings.EqualFold(d.Fingerprint, id.Fingerprint) {
		return false
	}
	return true
}
