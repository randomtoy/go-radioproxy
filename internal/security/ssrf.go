package security

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrEmptyURL         = errors.New("url is required")
	ErrURLTooLong       = errors.New("url is too long")
	ErrInvalidURL       = errors.New("invalid url")
	ErrInvalidScheme    = errors.New("unsupported url scheme")
	ErrBlockedHost      = errors.New("blocked host")
	ErrDNSResolveFailed = errors.New("failed to resolve host")
)

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

type URLValidator struct {
	resolver     *net.Resolver
	maxURLLength int
	allowedHosts map[string]struct{}
	deniedHosts  map[string]struct{}
}

func NewURLValidator(maxURLLength int, allowedHosts, deniedHosts map[string]struct{}) *URLValidator {
	return &URLValidator{
		resolver:     net.DefaultResolver,
		maxURLLength: maxURLLength,
		allowedHosts: copySet(allowedHosts),
		deniedHosts:  copySet(deniedHosts),
	}
}

func (v *URLValidator) Validate(ctx context.Context, rawURL string) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, ErrEmptyURL
	}
	if len(rawURL) > v.maxURLLength {
		return nil, ErrURLTooLong
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	if parsed.Scheme == "" {
		return nil, ErrInvalidURL
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, ErrInvalidScheme
	}
	if parsed.Host == "" {
		return nil, ErrInvalidURL
	}

	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return nil, ErrInvalidURL
	}
	if err := v.checkHostRules(host); err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, fmt.Errorf("%w: ip %s", ErrBlockedHost, ip.String())
		}
		return parsed, nil
	}

	ips, err := v.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDNSResolveFailed, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses", ErrDNSResolveFailed)
	}

	for _, ipAddr := range ips {
		if isBlockedIP(ipAddr.IP) {
			return nil, fmt.Errorf("%w: resolved ip %s", ErrBlockedHost, ipAddr.IP.String())
		}
	}

	return parsed, nil
}

func (v *URLValidator) SafeDialContext(next DialContextFunc) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}

		host = normalizeHost(host)
		if host == "" {
			return nil, fmt.Errorf("%w: empty host", ErrBlockedHost)
		}
		if err := v.checkHostRules(host); err != nil {
			return nil, err
		}

		if ip := net.ParseIP(host); ip != nil {
			if isBlockedIP(ip) {
				return nil, fmt.Errorf("%w: ip %s", ErrBlockedHost, ip.String())
			}
			return next(ctx, network, net.JoinHostPort(ip.String(), port))
		}

		ips, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDNSResolveFailed, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%w: no addresses", ErrDNSResolveFailed)
		}

		safeIPs := make([]net.IP, 0, len(ips))
		for _, ipAddr := range ips {
			if isBlockedIP(ipAddr.IP) {
				return nil, fmt.Errorf("%w: resolved ip %s", ErrBlockedHost, ipAddr.IP.String())
			}
			safeIPs = append(safeIPs, ipAddr.IP)
		}
		if len(safeIPs) == 0 {
			return nil, fmt.Errorf("%w: no safe ip", ErrBlockedHost)
		}

		selected := safeIPs[0]
		target := net.JoinHostPort(selected.String(), port)
		return next(ctx, network, target)
	}
}

func (v *URLValidator) checkHostRules(host string) error {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("%w: localhost", ErrBlockedHost)
	}

	if matchHostSet(host, v.deniedHosts) {
		return fmt.Errorf("%w: host is denied", ErrBlockedHost)
	}

	if len(v.allowedHosts) > 0 && !matchHostSet(host, v.allowedHosts) {
		return fmt.Errorf("%w: host is not in allowed list", ErrBlockedHost)
	}

	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip.IsUnspecified() {
		return true
	}
	return false
}

func matchHostSet(host string, set map[string]struct{}) bool {
	if len(set) == 0 {
		return false
	}
	for pattern := range set {
		if hostMatchesPattern(host, pattern) {
			return true
		}
	}
	return false
}

func hostMatchesPattern(host, pattern string) bool {
	pattern = normalizeHost(pattern)
	if pattern == "" {
		return false
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix)
	}

	if host == pattern {
		return true
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if _, convErr := strconv.Atoi(p); convErr == nil {
			host = h
		}
	}
	return host
}

func copySet(in map[string]struct{}) map[string]struct{} {
	if len(in) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(in))
	for key := range in {
		out[normalizeHost(key)] = struct{}{}
	}
	return out
}
