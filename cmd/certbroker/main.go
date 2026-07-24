// Command certbroker is a certificate enrollment broker that fronts OpenBao's
// pki/issue endpoint, supporting the EST (and, later, SCEP) enrollment
// protocols with per-device authorization.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gr-oss/certbroker/internal/authz"
	"github.com/gr-oss/certbroker/internal/bao"
	"github.com/gr-oss/certbroker/internal/config"
	"github.com/gr-oss/certbroker/internal/est"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	configPath := flag.String("config", "/etc/certbroker/config.yaml", "path to config file")
	devAllowAll := flag.Bool("dev-insecure-allow-all", false,
		"DEV ONLY: authorize every request via AllowAllEcho (NO authorization). Never use in production.")
	devRole := flag.String("dev-role", "", "OpenBao role for -dev-insecure-allow-all (defaults to role_map.default)")
	flag.Parse()

	if err := run(logger, *configPath, *devAllowAll, *devRole); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configPath string, devAllowAll bool, devRole string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// --- OpenBao client ---
	secretID, err := cfg.ResolveSecretID()
	if err != nil {
		return err
	}
	caCert, err := cfg.OpenBaoCACert()
	if err != nil {
		return err
	}
	baoClient, err := bao.New(bao.Config{
		Address:        cfg.OpenBao.Address,
		PKIMount:       cfg.OpenBao.Mount,
		CACertPEM:      caCert,
		AppRoleMount:   cfg.OpenBao.AppRole.MountPath,
		RoleID:         cfg.OpenBao.AppRole.RoleID,
		SecretID:       secretID,
		RenewThreshold: cfg.OpenBao.AppRole.RenewThreshold.Std(),
		MaxRetries:     cfg.OpenBao.MaxRetries,
	}, logger)
	if err != nil {
		return err
	}

	// --- trust anchors + server cert ---
	bootstrapRoots, deviceRoots, err := cfg.TrustPools()
	if err != nil {
		return err
	}
	serverCert, err := cfg.ServerTLSCertificate()
	if err != nil {
		return err
	}

	// --- authorizer ---
	authorizer, err := selectAuthorizer(logger, cfg, devAllowAll, devRole)
	if err != nil {
		return err
	}

	// --- EST handler ---
	handler, err := est.NewHandler(est.Options{
		BootstrapRoots:  bootstrapRoots,
		DeviceRoots:     deviceRoots,
		Enroller:        baoClient,
		Authorizer:      authorizer,
		AllowedKeyTypes: cfg.Policy.AllowedKeyTypes,
		MaxRequestBytes: cfg.Server.MaxRequestBytes,
		Logger:          logger,
	})
	if err != nil {
		return err
	}

	// --- servers ---
	estSrv := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		TLSConfig:    est.TLSConfig(serverCert),
		ReadTimeout:  cfg.Server.ReadTimeout.Std(),
		WriteTimeout: cfg.Server.WriteTimeout.Std(),
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	healthSrv := &http.Server{
		Addr:    cfg.Server.HealthAddr,
		Handler: healthHandler(baoClient),
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("EST listener starting", "addr", cfg.Server.ListenAddr)
		// Certs come from TLSConfig, so the file args are empty.
		if err := estSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("health listener starting", "addr", cfg.Server.HealthAddr)
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// --- wait for signal or server error ---
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = estSrv.Shutdown(shutdownCtx)
	_ = healthSrv.Shutdown(shutdownCtx)
	logger.Info("certbroker stopped")
	return nil
}

// selectAuthorizer returns the configured authorizer. The real policy pipeline
// arrives in Phase 3; until then the safe default is DenyAll, with an explicit,
// loudly-logged dev escape hatch.
func selectAuthorizer(logger *slog.Logger, cfg *config.Config, devAllowAll bool, devRole string) (authz.Authorizer, error) {
	if !devAllowAll {
		logger.Warn("no authorization pipeline configured yet (Phase 3); all enrollment requests will be DENIED")
		return authz.DenyAll{}, nil
	}
	role := devRole
	if role == "" {
		role = cfg.RoleMap.Default
	}
	if role == "" {
		return nil, errors.New("-dev-insecure-allow-all requires -dev-role or role_map.default")
	}
	logger.Warn("SECURITY: -dev-insecure-allow-all is set; every request is authorized WITHOUT checks",
		"role", role)
	return authz.AllowAllEcho{Role: role}, nil
}

// healthHandler serves liveness and readiness. Readiness probes OpenBao by
// fetching the CA chain, which also exercises AppRole auth.
func healthHandler(baoClient *bao.Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, err := baoClient.CAChain(ctx); err != nil {
			http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})
	return mux
}
