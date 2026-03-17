package proxy

import "testing"

func TestStreamLimiterLimitsAndRelease(t *testing.T) {
	limiter := NewStreamLimiter(2, 1, 3)

	releaseA, err := limiter.Acquire("1.1.1.1", "user1", 2)
	if err != nil {
		t.Fatalf("expected first acquire to succeed, got %v", err)
	}

	if _, err := limiter.Acquire("1.1.1.1", "user2", 2); err != ErrIPLimitExceeded {
		t.Fatalf("expected per-ip limit error, got %v", err)
	}

	releaseB, err := limiter.Acquire("2.2.2.2", "user1", 2)
	if err != nil {
		t.Fatalf("expected second acquire to succeed, got %v", err)
	}

	if _, err := limiter.Acquire("3.3.3.3", "user3", 2); err != ErrGlobalLimitExceeded {
		t.Fatalf("expected global limit error, got %v", err)
	}

	releaseA()

	if _, err := limiter.Acquire("4.4.4.4", "user1", 1); err != ErrUserLimitExceeded {
		t.Fatalf("expected user limit error, got %v", err)
	}

	releaseB()

	if _, err := limiter.Acquire("4.4.4.4", "user1", 2); err != nil {
		t.Fatalf("expected acquire after release to succeed, got %v", err)
	}
}

func TestStreamLimiterGlobalPerUserCap(t *testing.T) {
	limiter := NewStreamLimiter(5, 5, 1)

	release, err := limiter.Acquire("1.1.1.1", "user1", 10)
	if err != nil {
		t.Fatalf("expected first acquire to succeed, got %v", err)
	}
	defer release()

	if _, err := limiter.Acquire("2.2.2.2", "user1", 10); err != ErrUserLimitExceeded {
		t.Fatalf("expected global per-user cap error, got %v", err)
	}
}
