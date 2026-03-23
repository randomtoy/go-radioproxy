package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthenticatorReloadAppliesNewUsers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users.yaml")

	hashOne := mustHash(t, "password1")
	hashTwo := mustHash(t, "password2")

	writeUsersFile(t, usersPath, fmt.Sprintf(`users:
  - username: user1
    password_hash: %q
    enabled: true
    max_streams: 2
`, hashOne))

	authenticator, err := LoadFromFile(usersPath)
	if err != nil {
		t.Fatalf("load auth: %v", err)
	}

	if _, err := authenticator.Authenticate("user1", "password1"); err != nil {
		t.Fatalf("authenticate user1 before reload: %v", err)
	}
	if _, err := authenticator.Authenticate("user2", "password2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials before reload, got %v", err)
	}

	writeUsersFile(t, usersPath, fmt.Sprintf(`users:
  - username: user1
    password_hash: %q
    enabled: false
    max_streams: 0
  - username: user2
    password_hash: %q
    enabled: true
    max_streams: 1
`, hashOne, hashTwo))

	if err := authenticator.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, err := authenticator.Authenticate("user1", "password1"); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("expected ErrUserDisabled after reload, got %v", err)
	}
	if _, err := authenticator.Authenticate("user2", "password2"); err != nil {
		t.Fatalf("authenticate user2 after reload: %v", err)
	}
}

func TestAuthenticatorReloadKeepsCurrentUsersOnInvalidConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	usersPath := filepath.Join(dir, "users.yaml")
	hash := mustHash(t, "password1")

	writeUsersFile(t, usersPath, fmt.Sprintf(`users:
  - username: user1
    password_hash: %q
    enabled: true
    max_streams: 1
`, hash))

	authenticator, err := LoadFromFile(usersPath)
	if err != nil {
		t.Fatalf("load auth: %v", err)
	}

	writeUsersFile(t, usersPath, "users: []\n")
	if err := authenticator.Reload(); err == nil {
		t.Fatalf("expected reload error for invalid config")
	}

	if _, err := authenticator.Authenticate("user1", "password1"); err != nil {
		t.Fatalf("existing user should still authenticate after failed reload, got %v", err)
	}
}

func writeUsersFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("generate bcrypt hash: %v", err)
	}
	return string(hash)
}
