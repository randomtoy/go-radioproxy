package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"go-radioproxy/internal/auth"
	"go-radioproxy/internal/config"
	"go-radioproxy/internal/logger"
	"go-radioproxy/internal/metrics"
	"go-radioproxy/internal/proxy"
	"go-radioproxy/internal/security"
	"go-radioproxy/internal/server"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	if err := runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return runServer()
	}

	switch args[0] {
	case "serve":
		if len(args) > 1 {
			return fmt.Errorf("usage: stream-proxy serve")
		}
		return runServer()
	case "hash-password":
		return runHashPassword(args[1:], stdin, stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runHashPassword(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hash-password", flag.ContinueOnError)
	fs.SetOutput(stderr)

	password := fs.String("password", "", "Plaintext password (unsafe in shell history)")
	fromStdin := fs.Bool("stdin", false, "Read plaintext password from stdin")
	cost := fs.Int("cost", bcrypt.DefaultCost, "Bcrypt cost (4-31)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	hasPasswordFlag := strings.TrimSpace(*password) != ""
	if hasPasswordFlag == *fromStdin {
		return errors.New("use exactly one of --password or --stdin")
	}
	if *cost < bcrypt.MinCost || *cost > bcrypt.MaxCost {
		return fmt.Errorf("cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	plain := *password
	if *fromStdin {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("read stdin password: %w", err)
		}
		plain = strings.TrimRight(string(data), "\r\n")
	}
	if plain == "" {
		return errors.New("password must not be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plain), *cost)
	if err != nil {
		return fmt.Errorf("generate bcrypt hash: %w", err)
	}

	_, err = fmt.Fprintln(stdout, string(hash))
	return err
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  stream-proxy [serve]")
	_, _ = fmt.Fprintln(w, "  stream-proxy hash-password --stdin [--cost 10]")
	_, _ = fmt.Fprintln(w, "  stream-proxy hash-password --password <plaintext> [--cost 10]")
}

func runServer() error {
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
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	defer signal.Stop(reloadCh)

	errCh := make(chan error, 1)
	go func() {
		log.Info("http server started", slog.String("addr", httpServer.Addr))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	for {
		select {
		case <-shutdownCtx.Done():
			log.Info("shutdown signal received")
			goto shutdown
		case <-reloadCh:
			if err := authenticator.Reload(); err != nil {
				log.Error("users config reload failed", slog.String("path", cfg.UsersFile), slog.Any("error", err))
				continue
			}
			log.Info("users config reloaded", slog.String("path", cfg.UsersFile))
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("http server error: %w", err)
			}
			return nil
		}
	}

shutdown:
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	streamer.CloseIdleConnections()
	log.Info("http server stopped")
	return nil
}
