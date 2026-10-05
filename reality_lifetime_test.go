package tls

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func realityTestTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Accept()
	if err != nil {
		a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	return a.(*net.TCPConn), b.(*net.TCPConn)
}

func TestRealityStreamingFallback(t *testing.T) {
	for _, afterDeadline := range []bool{false, true} {
		name := "early-target-response"
		if afterDeadline {
			name = "handshake-deadline"
		}
		t.Run(name, func(t *testing.T) {
			client, server := realityTestTCPPair(t)
			target, peer := realityTestTCPPair(t)
			lifecycle, cancel := context.WithCancel(context.Background())
			defer cancel()
			handshakeCtx, stop := context.WithTimeout(lifecycle, 50*time.Millisecond)
			defer stop()
			done := make(chan error, 1)
			go func() {
				_, err := RealityServer(handshakeCtx, server, &RealityConfig{
					DialContext:     func(context.Context, string, string) (net.Conn, error) { return target, nil },
					FallbackContext: lifecycle,
				})
				done <- err
			}()
			prefix := []byte{22, 3, 3, 0, 100, 1, 0}
			if _, err := client.Write(prefix); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(prefix))
			if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, prefix) {
				t.Fatalf("partial hello was not streamed: %x, %v", got, err)
			}
			if afterDeadline {
				<-handshakeCtx.Done()
				if _, err := client.Write([]byte{2}); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(peer, got[:1]); err != nil || got[0] != 2 {
					t.Fatalf("handshake deadline interrupted fallback: %v", err)
				}
			}
			reply := []byte("target response before complete ClientHello")
			if _, err := peer.Write(reply); err != nil {
				t.Fatal(err)
			}
			got = make([]byte, len(reply))
			if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, reply) {
				t.Fatalf("target response was not forwarded: %q, %v", got, err)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("lifecycle cancellation did not stop fallback")
			}
		})
	}
}

func TestRealityPartialHelloHalfClose(t *testing.T) {
	client, server := realityTestTCPPair(t)
	target, peer := realityTestTCPPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := RealityServer(ctx, server, &RealityConfig{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return target, nil },
		})
		done <- err
	}()
	prefix := []byte{22, 3, 3, 0, 100, 1, 0}
	client.Write(prefix)
	client.CloseWrite()
	got, err := io.ReadAll(peer)
	if err != nil || !bytes.Equal(got, prefix) {
		t.Fatalf("target did not receive partial hello and EOF: %x, %v", got, err)
	}
	peer.Write([]byte("after EOF"))
	peer.CloseWrite()
	got, err = io.ReadAll(client)
	if err != nil || string(got) != "after EOF" {
		t.Fatalf("half-close lost target response: %q, %v", got, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fallback did not finish after both half-closes")
	}
}

func TestRealityCommittedHandshakeDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	target, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	lifetime := newRealityConnLifetime(ctx, context.Background(), server, target)
	defer lifetime.stop()
	if !lifetime.commit() {
		t.Fatal("could not commit local handshake")
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("committed handshake did not close on deadline: %v", err)
	}
}

func TestRealityPartialHelloReset(t *testing.T) {
	client, server := realityTestTCPPair(t)
	target, peer := realityTestTCPPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := RealityServer(ctx, server, &RealityConfig{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return target, nil },
		})
		done <- err
	}()
	prefix := []byte{22, 3, 3, 0, 100, 1, 0}
	client.Write(prefix)
	got := make([]byte, len(prefix))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	client.SetLinger(0)
	client.Close()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err := peer.Read(got)
	if err == nil {
		t.Fatal("target remained readable after client reset")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("target was left open after client reset")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reset left a copy blocked")
	}
}
