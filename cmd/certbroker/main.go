// Command certbroker is a certificate enrollment broker that fronts OpenBao's
// pki/issue endpoint, supporting the EST (and, later, SCEP) enrollment
// protocols with per-device authorization.
package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/gr-oss/certbroker/internal/config"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	configPath := flag.String("config", "/etc/certbroker/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}

	logger.Info("certbroker starting",
		"listen", cfg.Server.ListenAddr,
		"openbao_mount", cfg.OpenBao.Mount,
	)

	// TODO(phase1+): wire OpenBao client, EST handlers, authz pipeline, and
	// start the mTLS listener. This is the Phase 0 compiling skeleton.
	logger.Info("scaffold ready — no listener started yet")
}
