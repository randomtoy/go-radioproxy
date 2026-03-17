package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"go-radioproxy/internal/security"
)

var (
	ErrUpstreamUnavailable = errors.New("upstream unavailable")
	ErrClientDisconnected  = errors.New("client disconnected")
)

type UpstreamStatusError struct {
	StatusCode int
	Status     string
}

func (e UpstreamStatusError) Error() string {
	return fmt.Sprintf("upstream returned status %d", e.StatusCode)
}

type ClientConfig struct {
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	MaxRedirects          int
	UserAgent             string
}

type Streamer struct {
	client    *http.Client
	userAgent string
}

func NewStreamer(cfg ClientConfig, validator *security.URLValidator) *Streamer {
	dialer := &net.Dialer{
		Timeout:   cfg.ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           validator.SafeDialContext(dialer.DialContext),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.ConnectTimeout,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			if _, err := validator.Validate(req.Context(), req.URL.String()); err != nil {
				return fmt.Errorf("unsafe redirect: %w", err)
			}
			return nil
		},
	}

	return &Streamer{
		client:    client,
		userAgent: cfg.UserAgent,
	}
}

func (s *Streamer) Stream(w http.ResponseWriter, incoming *http.Request, upstreamURL *url.URL) (int64, error) {
	upstreamReq, err := http.NewRequestWithContext(incoming.Context(), http.MethodGet, upstreamURL.String(), nil)
	if err != nil {
		return 0, err
	}

	copySafeRequestHeaders(upstreamReq.Header, incoming.Header)
	upstreamReq.Header.Set("User-Agent", s.userAgent)

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		if incoming.Context().Err() != nil {
			return 0, ErrClientDisconnected
		}
		return 0, fmt.Errorf("%w: %v", ErrUpstreamUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return 0, UpstreamStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
	}

	copySafeResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-incoming.Context().Done():
			_ = resp.Body.Close()
		case <-done:
		}
	}()
	defer close(done)

	writer := io.Writer(w)
	if flusher, ok := w.(http.Flusher); ok {
		writer = &flushWriter{w: w, f: flusher}
	}

	buf := make([]byte, 32*1024)
	written, err := io.CopyBuffer(writer, resp.Body, buf)
	if err != nil {
		if incoming.Context().Err() != nil || isDisconnectError(err) {
			return written, ErrClientDisconnected
		}
		return written, err
	}

	return written, nil
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if err == nil {
		fw.f.Flush()
	}
	return n, err
}

func copySafeRequestHeaders(dst, src http.Header) {
	for _, key := range []string{
		"Accept",
		"Accept-Language",
		"Range",
		"Icy-MetaData",
		"Cache-Control",
		"Pragma",
	} {
		values := src.Values(key)
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

func copySafeResponseHeaders(dst, src http.Header) {
	hopByHop := buildHopByHopHeaderSet(src)

	for key, values := range src {
		if _, blocked := hopByHop[strings.ToLower(key)]; blocked {
			continue
		}
		if !isSafeResponseHeader(key) {
			continue
		}
		for _, v := range values {
			dst.Add(key, v)
		}
	}
}

func isSafeResponseHeader(key string) bool {
	k := strings.ToLower(key)
	if strings.HasPrefix(k, "icy-") || strings.HasPrefix(k, "ice-") {
		return true
	}

	switch k {
	case "content-type", "content-length", "cache-control", "pragma", "expires", "last-modified", "etag", "accept-ranges", "content-disposition":
		return true
	default:
		return false
	}
}

func buildHopByHopHeaderSet(headers http.Header) map[string]struct{} {
	hop := map[string]struct{}{
		"connection":          {},
		"keep-alive":          {},
		"proxy-authenticate":  {},
		"proxy-authorization": {},
		"te":                  {},
		"trailer":             {},
		"transfer-encoding":   {},
		"upgrade":             {},
	}

	for _, h := range headers.Values("Connection") {
		for _, token := range strings.Split(h, ",") {
			name := strings.ToLower(strings.TrimSpace(token))
			if name != "" {
				hop[name] = struct{}{}
			}
		}
	}

	return hop
}

func isDisconnectError(err error) bool {
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer")
}

func (s *Streamer) CloseIdleConnections() {
	if transport, ok := s.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
