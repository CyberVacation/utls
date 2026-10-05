package tls

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

const (
	realityInspecting = iota
	realityForwarding
	realityLocalHandshake
	realityStopped
)

// The mode lock orders a handshake deadline against the first locally
// generated server flight. The parsing lock must not be used here: it can be
// held while a handshake is blocked on network I/O.
type realityConnLifetime struct {
	mu         sync.Mutex
	mode       int
	ctx        context.Context
	client     net.Conn
	target     net.Conn
	done       chan struct{}
	joined     chan struct{}
	wakeTarget bool
}

func newRealityConnLifetime(ctx, fallbackCtx context.Context, client, target net.Conn) *realityConnLifetime {
	if fallbackCtx == nil {
		fallbackCtx = ctx
	}
	l := &realityConnLifetime{
		ctx:    ctx,
		client: client,
		target: target,
		done:   make(chan struct{}),
		joined: make(chan struct{}),
	}
	go func() {
		defer close(l.joined)
		handshakeDone := ctx.Done()
		for {
			select {
			case <-l.done:
				return
			case <-fallbackCtx.Done():
				client.Close()
				target.Close()
				return
			case <-handshakeDone:
				l.mu.Lock()
				abort := false
				if l.mode != realityStopped {
					if ctx.Err() == context.DeadlineExceeded && l.mode == realityInspecting {
						l.deadlineFallbackLocked()
					} else if l.mode != realityForwarding || ctx.Err() != context.DeadlineExceeded {
						abort = true
					}
				}
				l.mu.Unlock()
				if abort {
					client.Close()
					target.Close()
					return
				}
				handshakeDone = nil
			}
		}
	}()
	return l
}

func (l *realityConnLifetime) isFallback() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.mode == realityInspecting && l.ctx.Err() == context.DeadlineExceeded {
		l.deadlineFallbackLocked()
	}
	return l.mode == realityForwarding
}

// Wake the target reader so it can forward any response bytes already held
// for handshake imitation, even if the target is waiting for the client.
func (l *realityConnLifetime) deadlineFallbackLocked() {
	l.mode = realityForwarding
	l.wakeTarget = true
	l.target.SetReadDeadline(time.Now())
}

func (l *realityConnLifetime) targetReadError(err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.wakeTarget {
		l.wakeTarget = false
		l.target.SetReadDeadline(time.Time{})
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			return nil
		}
	}
	return err
}

func (l *realityConnLifetime) fallback() {
	l.mu.Lock()
	if l.mode == realityInspecting {
		l.mode = realityForwarding
	}
	l.mu.Unlock()
}

func (l *realityConnLifetime) commit() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.mode != realityInspecting {
		return false
	}
	if l.ctx.Err() != nil {
		l.mode = realityForwarding
		return false
	}
	l.mode = realityLocalHandshake
	return true
}

func (l *realityConnLifetime) stop() {
	l.mu.Lock()
	l.mode = realityStopped
	l.mu.Unlock()
	close(l.done)
	<-l.joined
}

// Only a clean EOF permits a half-close. A reset, a failed write, or a failed
// half-close must wake the other copy as well.
func realityFinishCopy(dst, src net.Conn, err error) {
	if err == nil || err == io.EOF {
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			err = c.CloseWrite()
		} else {
			err = dst.Close()
		}
	}
	if err != nil {
		dst.Close()
		src.Close()
	}
}
