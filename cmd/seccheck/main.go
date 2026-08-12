package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hkjang/SecCheck/internal/app"
	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/notify"
	"github.com/hkjang/SecCheck/internal/store"
	api "github.com/hkjang/SecCheck/internal/web"
	"golang.org/x/crypto/bcrypt"
)

var version = "dev"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		res, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://127.0.0.1:8080/health")
		if err != nil || res.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = res.Body.Close()
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cfg, err := app.LoadConfig()
	if err != nil {
		fatal(err)
	}
	cfg.Version = version
	if err = os.MkdirAll(cfg.DataDir, 0700); err != nil {
		fatal(err)
	}
	db, err := store.Open(ctx, cfg.PostgresDSN)
	if err != nil {
		fatal(fmt.Errorf("connect database: %w", err))
	}
	defer db.Close()
	if err = db.Migrate(ctx); err != nil {
		fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.BootstrapAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		fatal(err)
	}
	if err = db.UpsertBootstrap(ctx, store.NewID(), cfg.BootstrapAdmin, string(hash)); err != nil {
		fatal(err)
	}
	bootstrap, err := db.GetUserByUsername(ctx, cfg.BootstrapAdmin)
	if err != nil {
		fatal(err)
	}
	if seeded, seedErr := db.SeedDefaults(ctx, bootstrap.ID); seedErr != nil {
		fatal(seedErr)
	} else if seeded > 0 {
		slog.Info("baseline workbook seeded", "items", seeded)
	}
	box, err := cryptox.New(cfg.EncryptionKey)
	if err != nil {
		fatal(err)
	}
	if err = ensureBootstrapKey(ctx, db, box, cfg.BootstrapAdmin); err != nil {
		fatal(err)
	}
	authService := auth.New(db, box)
	go notify.New(db, box).Run(ctx)
	handler := api.NewServer(api.Options{Store: db, Auth: authService, Box: box, Version: version, WebDir: cfg.WebDir, DataDir: cfg.DataDir})
	srv := &http.Server{Addr: cfg.ListenAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		shutdownCtx, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		_ = srv.Shutdown(shutdownCtx)
	}()
	slog.Info("SecCheck started", "version", version, "address", cfg.ListenAddr)
	err = srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

func ensureBootstrapKey(ctx context.Context, s *store.Store, box *cryptox.Box, username string) error {
	u, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return err
	}
	var n int
	if err = s.Pool.QueryRow(ctx, `SELECT count(*) FROM user_data_keys WHERE user_id=$1`, u.ID).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	key, err := cryptox.RandomBytes(32)
	if err != nil {
		return err
	}
	encrypted, err := box.Encrypt(key, []byte("user-key:"+u.ID+":1"))
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO user_data_keys(user_id,version,encrypted_key) VALUES($1,1,$2)`, u.ID, encrypted)
	return err
}

func fatal(err error) { slog.Error("SecCheck failed", "error", err); os.Exit(1) }

func init() {
	// Container paths are fixed; only the four documented secrets/configuration inputs are environment variables.
	if filepath.Separator == '\\' {
		slog.Debug("running on windows")
	}
}
