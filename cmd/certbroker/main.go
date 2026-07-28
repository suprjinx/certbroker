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
	"github.com/gr-oss/certbroker/internal/limits"
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
		BootstrapRoots:      bootstrapRoots,
		DeviceRoots:         deviceRoots,
		Enroller:            baoClient,
		Authorizer:          authorizer,
		AllowedKeyTypes:     cfg.Policy.AllowedKeyTypes,
		MaxRequestBytes:     cfg.Server.MaxRequestBytes,
		MinRSABits:          cfg.Policy.MinRSABits,
		MaxRSABits:          cfg.Policy.MaxRSABits,
		ServerKeyGenKeyType: cfg.Policy.ServerKeyGenKeyType,
		ServerKeyGenKeyBits: cfg.Policy.ServerKeyGenKeyBits,
		UpstreamTimeout:     cfg.Limits.UpstreamTimeout.Std(),
		Logger:              logger,
	})
	if err != nil {
		return err
	}

	// --- DoS controls ---
	// Wrapped outside the EST handler so rate limiting happens before any CSR
	// parsing or signature verification, which is the work being protected.
	limiter := limits.New(limits.Config{
		PerClientRate:  cfg.Limits.PerClientRate,
		PerClientBurst: cfg.Limits.PerClientBurst,
		GlobalRate:     cfg.Limits.GlobalRate,
		GlobalBurst:    cfg.Limits.GlobalBurst,
		MaxConcurrent:  cfg.Limits.MaxConcurrent,
		AcquireTimeout: cfg.Limits.AcquireTimeout.Std(),
		MaxClients:     cfg.Limits.MaxTrackedClients,
		Logger:         logger,
	})
	logger.Info("request limits configured",
		"per_client_rate", cfg.Limits.PerClientRate,
		"per_client_burst", cfg.Limits.PerClientBurst,
		"global_rate", cfg.Limits.GlobalRate,
		"global_burst", cfg.Limits.GlobalBurst,
		"max_concurrent", cfg.Limits.MaxConcurrent,
		"max_request_bytes", cfg.Server.MaxRequestBytes,
	)

	// --- servers ---
	estSrv := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           limiter.Middleware(handler),
		TLSConfig:         est.TLSConfig(serverCert),
		ReadTimeout:       cfg.Server.ReadTimeout.Std(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Std(),
		WriteTimeout:      cfg.Server.WriteTimeout.Std(),
		IdleTimeout:       cfg.Server.IdleTimeout.Std(),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	// The health listener is unauthenticated, so it gets the same connection
	// timeouts. It is not rate limited: probes must not be shed, and it should
	// be bound to a management interface rather than exposed.
	healthSrv := &http.Server{
		Addr:              cfg.Server.HealthAddr,
		Handler:           healthHandler(baoClient),
		ReadTimeout:       cfg.Server.ReadTimeout.Std(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Std(),
		WriteTimeout:      cfg.Server.WriteTimeout.Std(),
		IdleTimeout:       cfg.Server.IdleTimeout.Std(),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
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

	shutdownTimeout := cfg.Server.ShutdownTimeout.Std()
	if shutdownTimeout <= 0 {
		shutdownTimeout = 10 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = estSrv.Shutdown(shutdownCtx)
	_ = healthSrv.Shutdown(shutdownCtx)
	logger.Info("certbroker stopped")
	return nil
}

// selectAuthorizer builds the authorization pipeline from config. The
// -dev-insecure-allow-all flag replaces it with AllowAllEcho (no checks) for
// local development only.
func selectAuthorizer(logger *slog.Logger, cfg *config.Config, devAllowAll bool, devRole string) (authz.Authorizer, error) {
	if devAllowAll {
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

	inv, err := buildInventory(cfg)
	if err != nil {
		return nil, err
	}
	ch, err := buildChallenge(cfg)
	if err != nil {
		return nil, err
	}

	rules := make([]authz.Rule, len(cfg.RoleMap.Rules))
	for i, r := range cfg.RoleMap.Rules {
		rules[i] = authz.Rule{Match: r.Match, Role: r.Role}
	}

	logger.Info("authorization pipeline configured",
		"inventory", cfg.Inventory.Backend,
		"challenge", cfg.Challenge.Backend,
		"require_challenge", cfg.Policy.RequireCPP,
		"san_mode", cfg.Policy.SANConstraint,
	)
	return &authz.Pipeline{
		Inventory:        inv,
		Challenge:        ch,
		Roles:            authz.NewRuleSelector(rules, cfg.RoleMap.Default),
		Constraints:      authz.NewStandardConstraints(cfg.Policy.SANConstraint, cfg.Policy.MaxValidity.Std()),
		RequireChallenge: cfg.Policy.RequireCPP,
		Logger:           logger,
	}, nil
}

func buildInventory(cfg *config.Config) (authz.Inventory, error) {
	switch cfg.Inventory.Backend {
	case "", "none":
		return authz.NoInventory{}, nil
	case "file":
		if cfg.Inventory.Path == "" {
			return nil, errors.New("inventory.path is required for the file backend")
		}
		return authz.NewFileInventory(cfg.Inventory.Path)
	default:
		return nil, errors.New("unsupported inventory backend: " + cfg.Inventory.Backend)
	}
}

func buildChallenge(cfg *config.Config) (authz.ChallengeValidator, error) {
	switch cfg.Challenge.Backend {
	case "", "none":
		// nil, NOT authz.NoChallenge{}. The pipeline treats a nil validator as
		// "a required challenge cannot be satisfied" and denies, which is the
		// fail-closed behavior we want. NoChallenge accepts unconditionally, so
		// returning it here would make an inventory record's require_challenge
		// silently pass with no secret supplied at all.
		return nil, nil
	case "static":
		if cfg.Challenge.StaticSecretEnv == "" {
			return nil, errors.New("challenge.static_secret_env is required for the static backend")
		}
		return authz.NewStaticSecret(os.Getenv(cfg.Challenge.StaticSecretEnv))
	default:
		return nil, errors.New("unsupported challenge backend: " + cfg.Challenge.Backend)
	}
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
