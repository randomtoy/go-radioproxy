package security

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateRejectsEmptyURL(t *testing.T) {
	v := NewURLValidator(128, nil, nil)
	if _, err := v.Validate(context.Background(), ""); !errors.Is(err, ErrEmptyURL) {
		t.Fatalf("expected ErrEmptyURL, got %v", err)
	}
}

func TestValidateRejectsInvalidScheme(t *testing.T) {
	v := NewURLValidator(128, nil, nil)
	if _, err := v.Validate(context.Background(), "file:///tmp/a.mp3"); !errors.Is(err, ErrInvalidScheme) {
		t.Fatalf("expected ErrInvalidScheme, got %v", err)
	}
}

func TestValidateRejectsLocalhostAndPrivateIP(t *testing.T) {
	v := NewURLValidator(256, nil, nil)

	if _, err := v.Validate(context.Background(), "http://127.0.0.1/live.mp3"); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("expected ErrBlockedHost for loopback, got %v", err)
	}

	if _, err := v.Validate(context.Background(), "http://10.0.0.5/live.mp3"); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("expected ErrBlockedHost for private ip, got %v", err)
	}

	if _, err := v.Validate(context.Background(), "http://localhost/live.mp3"); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("expected ErrBlockedHost for localhost, got %v", err)
	}
}

func TestValidateRejectsTooLongURL(t *testing.T) {
	v := NewURLValidator(20, nil, nil)
	tooLong := "http://example.com/" + strings.Repeat("a", 64)
	if _, err := v.Validate(context.Background(), tooLong); !errors.Is(err, ErrURLTooLong) {
		t.Fatalf("expected ErrURLTooLong, got %v", err)
	}
}

func TestValidateRespectsAllowDenyLists(t *testing.T) {
	v := NewURLValidator(256, map[string]struct{}{"allowed.example": {}}, nil)
	if _, err := v.Validate(context.Background(), "http://not-allowed.example/live.mp3"); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("expected ErrBlockedHost for non-allowed host, got %v", err)
	}

	v = NewURLValidator(256, nil, map[string]struct{}{"denied.example": {}})
	if _, err := v.Validate(context.Background(), "http://denied.example/live.mp3"); !errors.Is(err, ErrBlockedHost) {
		t.Fatalf("expected ErrBlockedHost for denied host, got %v", err)
	}
}

func TestValidateAllowsPublicIP(t *testing.T) {
	v := NewURLValidator(256, nil, nil)
	if _, err := v.Validate(context.Background(), "http://8.8.8.8/live.mp3"); err != nil {
		t.Fatalf("expected public ip to be allowed, got %v", err)
	}
}
