package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort                         = "8080"
	defaultUserAgent                    = "UniversalStreamProxy/1.0"
	defaultConnectTimeoutSeconds        = 10
	defaultResponseHeaderTimeoutSeconds = 15
	defaultMaxRedirects                 = 5
	defaultMaxConcurrentStreams         = 100
	defaultMaxStreamsPerIP              = 5
	defaultMaxStreamsPerUser            = 0
	defaultUsersFile                    = "./users.yaml"
	defaultLogLevel                     = "info"
	defaultMaxURLLength                 = 2048
)

type Config struct {
	Port                  string
	UserAgent             string
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	MaxRedirects          int
	MaxConcurrentStreams  int
	MaxStreamsPerIP       int
	MaxStreamsPerUser     int
	UsersFile             string
	AllowedHosts          map[string]struct{}
	DeniedHosts           map[string]struct{}
	LogLevel              slog.Level
	MaxURLLength          int
	ShutdownTimeout       time.Duration
}

func Load() (Config, error) {
	connectTimeoutSec, err := intFromEnv("CONNECT_TIMEOUT_SECONDS", defaultConnectTimeoutSeconds)
	if err != nil {
		return Config{}, err
	}

	headerTimeoutSec, err := intFromEnv("RESPONSE_HEADER_TIMEOUT_SECONDS", defaultResponseHeaderTimeoutSeconds)
	if err != nil {
		return Config{}, err
	}

	maxRedirects, err := intFromEnv("MAX_REDIRECTS", defaultMaxRedirects)
	if err != nil {
		return Config{}, err
	}

	maxConcurrentStreams, err := intFromEnv("MAX_CONCURRENT_STREAMS", defaultMaxConcurrentStreams)
	if err != nil {
		return Config{}, err
	}

	maxStreamsPerIP, err := intFromEnv("MAX_STREAMS_PER_IP", defaultMaxStreamsPerIP)
	if err != nil {
		return Config{}, err
	}

	maxStreamsPerUser, err := intFromEnv("MAX_STREAMS_PER_USER", defaultMaxStreamsPerUser)
	if err != nil {
		return Config{}, err
	}

	maxURLLength, err := intFromEnv("MAX_URL_LENGTH", defaultMaxURLLength)
	if err != nil {
		return Config{}, err
	}

	level, err := parseLogLevel(envOrDefault("LOG_LEVEL", defaultLogLevel))
	if err != nil {
		return Config{}, err
	}

	port := strings.TrimSpace(envOrDefault("PORT", defaultPort))
	if port == "" {
		return Config{}, fmt.Errorf("PORT must not be empty")
	}

	cfg := Config{
		Port:                  port,
		UserAgent:             strings.TrimSpace(envOrDefault("USER_AGENT", defaultUserAgent)),
		ConnectTimeout:        time.Duration(connectTimeoutSec) * time.Second,
		ResponseHeaderTimeout: time.Duration(headerTimeoutSec) * time.Second,
		MaxRedirects:          maxRedirects,
		MaxConcurrentStreams:  maxConcurrentStreams,
		MaxStreamsPerIP:       maxStreamsPerIP,
		MaxStreamsPerUser:     maxStreamsPerUser,
		UsersFile:             strings.TrimSpace(envOrDefault("USERS_FILE", defaultUsersFile)),
		AllowedHosts:          listToSet(envOrDefault("ALLOWED_HOSTS", "")),
		DeniedHosts:           listToSet(envOrDefault("DENIED_HOSTS", "")),
		LogLevel:              level,
		MaxURLLength:          maxURLLength,
		ShutdownTimeout:       10 * time.Second,
	}

	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if cfg.UsersFile == "" {
		cfg.UsersFile = defaultUsersFile
	}
	if cfg.MaxConcurrentStreams <= 0 {
		return Config{}, fmt.Errorf("MAX_CONCURRENT_STREAMS must be > 0")
	}
	if cfg.MaxStreamsPerIP <= 0 {
		return Config{}, fmt.Errorf("MAX_STREAMS_PER_IP must be > 0")
	}
	if cfg.MaxStreamsPerUser < 0 {
		return Config{}, fmt.Errorf("MAX_STREAMS_PER_USER must be >= 0")
	}
	if cfg.MaxRedirects < 0 {
		return Config{}, fmt.Errorf("MAX_REDIRECTS must be >= 0")
	}
	if cfg.MaxURLLength <= 0 {
		return Config{}, fmt.Errorf("MAX_URL_LENGTH must be > 0")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	return value
}

func intFromEnv(key string, fallback int) (int, error) {
	value := strings.TrimSpace(envOrDefault(key, strconv.Itoa(fallback)))
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return parsed, nil
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid LOG_LEVEL: %q", raw)
	}
}

func listToSet(raw string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		value := strings.ToLower(strings.TrimSpace(part))
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	return set
}
