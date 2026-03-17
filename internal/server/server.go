package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"go-radioproxy/internal/auth"
	"go-radioproxy/internal/metrics"
	"go-radioproxy/internal/proxy"
	"go-radioproxy/internal/security"
)

type App struct {
	logger    *slog.Logger
	metrics   *metrics.Store
	validator *security.URLValidator
	streamer  *proxy.Streamer
	limiter   *proxy.StreamLimiter
}

func NewHandler(
	logger *slog.Logger,
	metricsStore *metrics.Store,
	validator *security.URLValidator,
	streamer *proxy.Streamer,
	limiter *proxy.StreamLimiter,
	authMiddleware func(http.Handler) http.Handler,
) http.Handler {
	app := &App{
		logger:    logger,
		metrics:   metricsStore,
		validator: validator,
		streamer:  streamer,
		limiter:   limiter,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/metrics", app.handleMetrics)
	mux.HandleFunc("/stream", app.handleStream)

	protected := authMiddleware(mux)
	withAuth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			mux.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})

	return app.loggingMiddleware(withAuth)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	snap := a.metrics.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(snap); err != nil {
		a.logger.Error("failed to write metrics response", slog.Any("error", err))
	}
}

func (a *App) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}

	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	clientIP := extractClientIP(r)
	rawURL := strings.TrimSpace(r.URL.Query().Get("url"))
	if rawURL == "" {
		http.Error(w, "missing url query parameter", http.StatusBadRequest)
		return
	}

	upstreamURL, err := a.validator.Validate(r.Context(), rawURL)
	if err != nil {
		status, message := mapValidationError(err)
		a.metrics.IncFailedStreams()
		a.logger.Warn("stream request rejected",
			slog.String("username", user.Username),
			slog.String("client_ip", clientIP),
			slog.String("requested_url", rawURL),
			slog.Int("status", status),
			slog.Any("error", err),
		)
		http.Error(w, message, status)
		return
	}

	release, err := a.limiter.Acquire(clientIP, user.Username, user.MaxStreams)
	if err != nil {
		a.metrics.IncFailedStreams()
		a.logger.Warn("stream limit exceeded",
			slog.String("username", user.Username),
			slog.String("client_ip", clientIP),
			slog.String("upstream_host", upstreamURL.Hostname()),
			slog.Any("error", err),
		)
		http.Error(w, "too many active streams", http.StatusTooManyRequests)
		return
	}
	defer release()

	a.metrics.IncActiveStreams()
	defer a.metrics.DecActiveStreams()

	start := time.Now()
	a.logger.Info("stream start",
		slog.String("username", user.Username),
		slog.String("client_ip", clientIP),
		slog.String("upstream_host", upstreamURL.Hostname()),
	)

	tracked := &trackingResponseWriter{ResponseWriter: w, status: http.StatusOK}
	bytesTransferred, err := a.streamer.Stream(tracked, r, upstreamURL)
	a.metrics.AddBytes(bytesTransferred)
	duration := time.Since(start)

	if err != nil {
		if errors.Is(err, proxy.ErrClientDisconnected) {
			a.logger.Info("stream end",
				slog.String("username", user.Username),
				slog.String("client_ip", clientIP),
				slog.String("upstream_host", upstreamURL.Hostname()),
				slog.String("reason", "client_disconnected"),
				slog.Duration("duration", duration),
				slog.Int64("bytes_transferred", bytesTransferred),
			)
			return
		}

		a.metrics.IncFailedStreams()
		if !tracked.wroteHeader {
			status, message := mapStreamError(err)
			http.Error(w, message, status)
			tracked.status = status
		}

		a.logger.Error("stream error",
			slog.String("username", user.Username),
			slog.String("client_ip", clientIP),
			slog.String("upstream_host", upstreamURL.Hostname()),
			slog.Duration("duration", duration),
			slog.Int64("bytes_transferred", bytesTransferred),
			slog.Any("error", err),
		)
		return
	}

	a.logger.Info("stream end",
		slog.String("username", user.Username),
		slog.String("client_ip", clientIP),
		slog.String("upstream_host", upstreamURL.Hostname()),
		slog.Duration("duration", duration),
		slog.Int64("bytes_transferred", bytesTransferred),
	)
}

func (a *App) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.metrics.IncRequests()

		start := time.Now()
		clientIP := extractClientIP(r)
		username, _, hasBasic := r.BasicAuth()
		if !hasBasic {
			username = ""
		}

		a.logger.Info("request start",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("username", username),
			slog.String("client_ip", clientIP),
		)

		rec := &trackingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		a.logger.Info("request end",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("username", username),
			slog.String("client_ip", clientIP),
			slog.Int("status", rec.status),
			slog.Int64("bytes", rec.bytes),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

func mapValidationError(err error) (int, string) {
	switch {
	case errors.Is(err, security.ErrEmptyURL):
		return http.StatusBadRequest, "missing url query parameter"
	case errors.Is(err, security.ErrURLTooLong), errors.Is(err, security.ErrInvalidURL), errors.Is(err, security.ErrInvalidScheme), errors.Is(err, security.ErrBlockedHost):
		return http.StatusBadRequest, "invalid or blocked url"
	case errors.Is(err, security.ErrDNSResolveFailed):
		return http.StatusBadGateway, "upstream host resolution failed"
	default:
		return http.StatusBadRequest, "invalid url"
	}
}

func mapStreamError(err error) (int, string) {
	var upstreamStatus proxy.UpstreamStatusError
	switch {
	case errors.As(err, &upstreamStatus):
		return http.StatusBadGateway, fmt.Sprintf("upstream returned status %d", upstreamStatus.StatusCode)
	case errors.Is(err, proxy.ErrUpstreamUnavailable):
		return http.StatusBadGateway, "upstream unavailable"
	default:
		return http.StatusBadGateway, "streaming failed"
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func extractClientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

type trackingResponseWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (tw *trackingResponseWriter) WriteHeader(statusCode int) {
	tw.status = statusCode
	tw.wroteHeader = true
	tw.ResponseWriter.WriteHeader(statusCode)
}

func (tw *trackingResponseWriter) Write(b []byte) (int, error) {
	if !tw.wroteHeader {
		tw.WriteHeader(tw.status)
	}
	n, err := tw.ResponseWriter.Write(b)
	tw.bytes += int64(n)
	return n, err
}

func (tw *trackingResponseWriter) Flush() {
	if flusher, ok := tw.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
