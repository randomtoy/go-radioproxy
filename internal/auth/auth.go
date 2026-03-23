package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserDisabled       = errors.New("user disabled")
)

type ctxKey string

const userContextKey ctxKey = "auth_user"

type User struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	Enabled      bool   `yaml:"enabled"`
	MaxStreams   int    `yaml:"max_streams"`
}

type usersFile struct {
	Users []User `yaml:"users"`
}

type Authenticator struct {
	mu            sync.RWMutex
	users         map[string]User
	usersFilePath string
}

func LoadFromFile(path string) (*Authenticator, error) {
	users, err := loadUsers(path)
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		users:         users,
		usersFilePath: path,
	}, nil
}

func loadUsers(path string) (map[string]User, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}
	return parseUsers(data)
}

func parseUsers(data []byte) (map[string]User, error) {
	var cfg usersFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse users file: %w", err)
	}

	if len(cfg.Users) == 0 {
		return nil, errors.New("users file has no users")
	}

	users := make(map[string]User, len(cfg.Users))
	for _, u := range cfg.Users {
		u.Username = strings.TrimSpace(u.Username)
		u.PasswordHash = strings.TrimSpace(u.PasswordHash)
		if u.Username == "" {
			return nil, errors.New("user username must not be empty")
		}
		if u.PasswordHash == "" {
			return nil, fmt.Errorf("user %q has empty password_hash", u.Username)
		}
		if _, exists := users[u.Username]; exists {
			return nil, fmt.Errorf("duplicate user %q", u.Username)
		}
		if u.Enabled && u.MaxStreams <= 0 {
			return nil, fmt.Errorf("user %q max_streams must be > 0", u.Username)
		}
		users[u.Username] = u
	}

	return users, nil
}

func (a *Authenticator) Reload() error {
	users, err := loadUsers(a.usersFilePath)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.users = users
	a.mu.Unlock()
	return nil
}

func (a *Authenticator) Authenticate(username, password string) (User, error) {
	a.mu.RLock()
	user, ok := a.users[username]
	a.mu.RUnlock()
	if !ok {
		return User{}, ErrInvalidCredentials
	}
	if !user.Enabled {
		return User{}, ErrUserDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return User{}, ErrInvalidCredentials
	}
	return user, nil
}

func Middleware(authenticator *Authenticator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			username, password, ok := r.BasicAuth()
			if !ok {
				writeUnauthorized(w)
				return
			}

			user, err := authenticator.Authenticate(username, password)
			if err != nil {
				switch {
				case errors.Is(err, ErrUserDisabled):
					logger.Warn("auth denied for disabled user", slog.String("username", username), slog.String("client_ip", clientIP(r)))
					http.Error(w, "forbidden", http.StatusForbidden)
				case errors.Is(err, ErrInvalidCredentials):
					logger.Warn("auth failed", slog.String("username", username), slog.String("client_ip", clientIP(r)))
					writeUnauthorized(w)
				default:
					logger.Error("auth error", slog.String("username", username), slog.Any("error", err))
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserFromContext(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(userContextKey).(User)
	return user, ok
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="stream-proxy"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	hostPort := strings.TrimSpace(r.RemoteAddr)
	if hostPort == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}
