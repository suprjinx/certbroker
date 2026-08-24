// Command certbroker brokers EST and SCEP enrollment onto OpenBao's PKI,
// authorizing each device before it issues.
package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
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
	"github.com/gr-oss/certbroker/internal/cms"
	"github.com/gr-oss/certbroker/internal/config"
	"github.com/gr-oss/certbroker/internal/est"
	"github.com/gr-oss/certbroker/internal/limits"
	"github.com/gr-oss/certbroker/internal/scep"
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
	// Outside the handler, so limits apply before any CSR parsing or PoP check.
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
	// Unauthenticated, so it gets the same timeouts. Not rate limited: probes
	// must not be shed, and it belongs on a management interface.
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

	// --- optional SCEP listener ---
	var scepSrv *http.Server
	if cfg.SCEP.Enabled {
		scepSrv, err = buildSCEPServer(logger, cfg, baoClient, authorizer, deviceRoots, limiter)
		if err != nil {
			return err
		}
	}

	errCh := make(chan error, 3)
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

	if scepSrv != nil {
		go func() {
			logger.Info("SCEP listener starting", "addr", cfg.SCEP.ListenAddr)
			if err := scepSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

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
	if scepSrv != nil {
		_ = scepSrv.Shutdown(shutdownCtx)
	}
	logger.Info("certbroker stopped")
	return nil
}

// buildSCEPServer assembles the SCEP listener. It shares the authorization
// pipeline, issuer, and rate limiter with EST — only the protocol differs.
func buildSCEPServer(logger *slog.Logger, cfg *config.Config, baoClient *bao.Client,
	authorizer authz.Authorizer, deviceRoots *x509.CertPool, limiter *limits.Limiter) (*http.Server, error) {

	raCert, raKey, err := cfg.SCEPRAIdentity()
	if err != nil {
		return nil, err
	}

	digests := cms.DefaultDigests
	if cfg.SCEP.AllowSHA1 {
		digests = append([]asn1.ObjectIdentifier{cms.SHA1}, digests...)
		logger.Warn("SECURITY: scep.allow_sha1 is set; SHA-1 is collision-broken and accepted only for legacy clients")
	}

	handler, err := scep.NewHandler(scep.Options{
		RACert:      raCert,
		RAKey:       raKey,
		DeviceRoots: deviceRoots,
		Enroller:    baoClient,
		Authorizer:  authorizer,
		ParseCSR: func(der []byte) (*x509.CertificateRequest, error) {
			return est.ParseCSRLimited(der, cfg.Policy.MinRSABits, cfg.Policy.MaxRSABits)
		},
		ChallengePassword: est.ChallengePassword,
		VerifyIssued:      authz.VerifyIssued,
		Digests:           digests,
		ReplayCache: scep.NewReplayCache(
			cfg.SCEP.ReplayTTL.Std(), cfg.SCEP.ReplayMaxEntries),
		MaxRequestBytes: cfg.SCEP.MaxRequestBytes,
		UpstreamTimeout: cfg.Limits.UpstreamTimeout.Std(),
		Logger:          logger,
	})
	if err != nil {
		return nil, err
	}

	logger.Info("SCEP enabled",
		"addr", cfg.SCEP.ListenAddr,
		"ra_subject", raCert.Subject.CommonName,
		"allow_sha1", cfg.SCEP.AllowSHA1,
	)
	// Plain HTTP by design: SCEP carries its own signing and encryption. Bind it
	// to a trusted network — there is no transport authentication here.
	logger.Warn("SCEP listener is plain HTTP; bind it to a trusted network")

	return &http.Server{
		Addr: cfg.SCEP.ListenAddr,
		// Same limiter as EST: SCEP's unauthenticated RSA decrypt is strictly
		// more expensive than EST's proof-of-possession check.
		Handler:           limiter.Middleware(handler),
		ReadTimeout:       cfg.Server.ReadTimeout.Std(),
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Std(),
		WriteTimeout:      cfg.Server.WriteTimeout.Std(),
		IdleTimeout:       cfg.Server.IdleTimeout.Std(),
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}, nil
}

// selectAuthorizer builds the pipeline from config; -dev-insecure-allow-all
// swaps in AllowAllEcho (no checks) for local development only.
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
		"allow_unauthenticated", cfg.Policy.AllowUnauthenticatedEnrollment,
	)
	if cfg.Policy.AllowUnauthenticatedEnrollment {
		// Supported, but it means anyone who can reach the listener may enroll any
		// name the inventory and role permit. Say so once, loudly, at startup.
		logger.Warn("SECURITY: allow_unauthenticated_enrollment is set; enrollment does not require a client certificate or a challenge",
			"inventory", cfg.Inventory.Backend)
	}
	return &authz.Pipeline{
		Inventory:            inv,
		Challenge:            ch,
		Roles:                authz.NewRuleSelector(rules, cfg.RoleMap.Default),
		Constraints:          authz.NewStandardConstraints(cfg.Policy.SANConstraint, cfg.Policy.MaxValidity.Std()),
		RequireChallenge:     cfg.Policy.RequireCPP,
		AllowUnauthenticated: cfg.Policy.AllowUnauthenticatedEnrollment,
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
		// nil, NOT NoChallenge{}: the pipeline denies a required challenge when the
		// validator is nil, whereas NoChallenge would silently satisfy it.
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

// healthHandler serves liveness and readiness; readiness probes OpenBao, which
// also exercises AppRole auth.
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
