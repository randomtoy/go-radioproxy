package proxy

import (
	"errors"
	"sync"
)

var (
	ErrGlobalLimitExceeded = errors.New("global stream limit exceeded")
	ErrIPLimitExceeded     = errors.New("per-ip stream limit exceeded")
	ErrUserLimitExceeded   = errors.New("per-user stream limit exceeded")
)

type StreamLimiter struct {
	mu           sync.Mutex
	globalLimit  int
	perIPLimit   int
	perUserLimit int
	total        int
	byIP         map[string]int
	byUser       map[string]int
}

func NewStreamLimiter(globalLimit, perIPLimit, perUserLimit int) *StreamLimiter {
	return &StreamLimiter{
		globalLimit:  globalLimit,
		perIPLimit:   perIPLimit,
		perUserLimit: perUserLimit,
		byIP:         make(map[string]int),
		byUser:       make(map[string]int),
	}
}

func (l *StreamLimiter) Acquire(ip, username string, userLimit int) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.total >= l.globalLimit {
		return nil, ErrGlobalLimitExceeded
	}
	if l.byIP[ip] >= l.perIPLimit {
		return nil, ErrIPLimitExceeded
	}
	effectiveUserLimit := userLimit
	if l.perUserLimit > 0 && (effectiveUserLimit == 0 || l.perUserLimit < effectiveUserLimit) {
		effectiveUserLimit = l.perUserLimit
	}
	if effectiveUserLimit > 0 && l.byUser[username] >= effectiveUserLimit {
		return nil, ErrUserLimitExceeded
	}

	l.total++
	l.byIP[ip]++
	l.byUser[username]++

	released := false
	release := func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true

		l.total--
		l.byIP[ip]--
		if l.byIP[ip] <= 0 {
			delete(l.byIP, ip)
		}
		l.byUser[username]--
		if l.byUser[username] <= 0 {
			delete(l.byUser, username)
		}
	}

	return release, nil
}
