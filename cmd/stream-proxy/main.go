package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"go-radioproxy/internal/auth"
	"go-radioproxy/internal/config"
	"go-radioproxy/internal/logger"
	"go-radioproxy/internal/metrics"
	"go-radioproxy/internal/proxy"
	"go-radioproxy/internal/security"
	"go-radioproxy/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("service failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := logger.New(cfg.LogLevel)
	slog.SetDefault(log)

	authenticator, err := auth.LoadFromFile(cfg.UsersFile)
	if err != nil {
		return fmt.Errorf("load users: %w", err)
	}

	metricsStore := metrics.New()
	validator := security.NewURLValidator(cfg.MaxURLLength, cfg.AllowedHosts, cfg.DeniedHosts)
	limiter := proxy.NewStreamLimiter(cfg.MaxConcurrentStreams, cfg.MaxStreamsPerIP, cfg.MaxStreamsPerUser)
	streamer := proxy.NewStreamer(proxy.ClientConfig{
		ConnectTimeout:        cfg.ConnectTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		MaxRedirects:          cfg.MaxRedirects,
		UserAgent:             cfg.UserAgent,
	}, validator)

	handler := server.NewHandler(
		log,
		metricsStore,
		validator,
		streamer,
		limiter,
		auth.Middleware(authenticator, log),
	)

	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ConnectTimeout,
	}

	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("http server started", slog.String("addr", httpServer.Addr))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-shutdownCtx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server error: %w", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	streamer.CloseIdleConnections()
	log.Info("http server stopped")
	return nil
}
