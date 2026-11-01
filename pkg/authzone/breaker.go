package authzone

import (
	"sync"
	"time"
)

type breaker struct {
	threshold int
	openFor   time.Duration
	now       func() time.Time

	mu       sync.Mutex
	failures int
	openedAt time.Time
	open     bool
	trial    bool
}

func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.open {
		return true
	}

	if b.now().Sub(b.openedAt) < b.openFor {
		return false
	}

	if b.trial {
		return false
	}

	b.trial = true

	return true
}

func (b *breaker) succeed() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures = 0
	b.open = false
	b.trial = false
}

func (b *breaker) fail() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.trial = false
	b.failures++

	if b.open || b.failures >= b.threshold {
		b.open = true
		b.openedAt = b.now()
	}
}
