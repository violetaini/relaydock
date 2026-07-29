package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/violetaini/relaydock/internal/expiryguard"
)

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func main() {
	listen := flag.String("listen", envOr("ARCWAY_GUARD_LISTEN", "0.0.0.0:23890"), "HTTP listen address")
	agentURL := flag.String("agent-url", envOr("ARCWAY_AGENT_URL", "http://127.0.0.1:23889"), "local Agent URL")
	statePath := flag.String("state", envOr("ARCWAY_GUARD_STATE", "/var/lib/arcway-expiry-guard/state.json"), "durable schedule path")
	secret := flag.String("secret", envOr("ARCWAY_GUARD_SECRET", ""), "stable guard authentication secret")
	agentToken := flag.String("agent-token", envOr("ARCWAY_AGENT_TOKEN", ""), "current local Agent token")
	flag.Parse()

	guard, err := expiryguard.New(*statePath, *secret, *agentToken, *agentURL, nil)
	if err != nil {
		log.Fatalf("initialize expiry guard: %v", err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	startupCtx, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	if err := guard.InitializeTunnelSafety(startupCtx); err != nil {
		log.Printf("Tunnel safety initialization: %v", err)
	}
	startupCancel()
	go guard.Run(ctx)

	server := &http.Server{
		Addr:              *listen,
		Handler:           guard.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("Arcway expiry guard listening on %s", *listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("expiry guard server: %v", err)
	}
}
