package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"
)

func realityAuthenticatedTestHello(t *testing.T, private *ecdh.PrivateKey) []byte {
	t.Helper()
	c := UClient(nil, &Config{ServerName: "example.com"}, HelloChrome_Auto)
	if err := c.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	hello := c.HandshakeState.Hello
	raw := append([]byte(nil), hello.Raw...)
	for i := 39; i < 71; i++ {
		raw[i] = 0
	}
	keys := c.HandshakeState.State13.KeyShareKeys
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	auth, err := ecdhe.ECDH(private.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(hkdf.New(sha256.New, auth, hello.Random[:20], []byte("REALITY")), auth); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(auth)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 16)
	plain[0] = 1
	binary.BigEndian.PutUint32(plain[4:], uint32(time.Now().Unix()))
	session := gcm.Seal(nil, hello.Random[20:], plain, raw)
	copy(raw[39:71], session)
	return append([]byte{22, 3, 1, byte(len(raw) >> 8), byte(len(raw))}, raw...)
}

func TestRealityAuthenticationHook(t *testing.T) {
	for _, altered := range []bool{false, true} {
		name := "authenticated-rejected-by-hook"
		if altered {
			name = "invalid-authentication"
		}
		t.Run(name, func(t *testing.T) {
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			wire := realityAuthenticatedTestHello(t, private)
			if altered {
				wire[44] ^= 1
			}
			client, server := realityTestTCPPair(t)
			target, peer := realityTestTCPPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var called atomic.Int32
			hookCalled := make(chan struct{}, 1)
			config := (&RealityConfig{
				DialContext:     func(context.Context, string, string) (net.Conn, error) { return target, nil },
				FallbackContext: ctx,
				ServerNames:     map[string]bool{"example.com": true},
				PrivateKey:      private.Bytes(), ShortIds: map[[8]byte]bool{{}: true},
				MaxTimeDiff: time.Minute,
				AcceptClientHello: func(hello []byte, clientTime time.Time) bool {
					called.Add(1)
					if !bytes.Equal(hello, wire[5:]) {
						t.Error("hook did not receive the original authenticated hello")
					}
					if time.Since(clientTime).Abs() > time.Minute {
						t.Error("hook received wrong timestamp")
					}
					hookCalled <- struct{}{}
					return false
				},
			}).Clone()
			done := make(chan error, 1)
			go func() { _, err := RealityServer(ctx, server, config); done <- err }()
			if _, err := client.Write(wire); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(wire))
			if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, wire) {
				t.Fatalf("target hello: %v", err)
			}
			if !altered {
				select {
				case <-hookCalled:
				case <-ctx.Done():
					t.Fatal("authentication hook was not called")
				}
			}
			peer.Write([]byte("target fallback"))
			peer.CloseWrite()
			got, err = io.ReadAll(client)
			if err != nil || string(got) != "target fallback" {
				t.Fatalf("fallback response: %q, %v", got, err)
			}
			client.CloseWrite()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("fallback did not finish")
			}
			want := int32(1)
			if altered {
				want = 0
			}
			if called.Load() != want {
				t.Fatalf("hook called %d times, want %d", called.Load(), want)
			}
		})
	}
}

func TestRealityFallbackDoesNotAuthenticateLater(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "target-responded-first"
		if deadline {
			name = "deadline-before-complete-hello"
		}
		t.Run(name, func(t *testing.T) {
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			wire := realityAuthenticatedTestHello(t, private)
			client, server := realityTestTCPPair(t)
			target, peer := realityTestTCPPair(t)
			lifecycle, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			handshakeCtx, stop := context.WithTimeout(lifecycle, 50*time.Millisecond)
			defer stop()
			var calls atomic.Int32
			done := make(chan error, 1)
			go func() {
				_, err := RealityServer(handshakeCtx, server, &RealityConfig{
					DialContext:     func(context.Context, string, string) (net.Conn, error) { return target, nil },
					FallbackContext: lifecycle,
					ServerNames:     map[string]bool{"example.com": true},
					PrivateKey:      private.Bytes(), ShortIds: map[[8]byte]bool{{}: true},
					MaxTimeDiff:       time.Minute,
					AcceptClientHello: func([]byte, time.Time) bool { calls.Add(1); return true },
				})
				done <- err
			}()
			client.Write(wire[:7])
			prefix := make([]byte, 7)
			if _, err := io.ReadFull(peer, prefix); err != nil {
				t.Fatal(err)
			}
			if deadline {
				<-handshakeCtx.Done()
			} else {
				peer.Write([]byte("early"))
				if _, err := io.ReadFull(client, prefix[:5]); err != nil {
					t.Fatal(err)
				}
			}
			client.Write(wire[7:])
			rest := make([]byte, len(wire)-7)
			if _, err := io.ReadFull(peer, rest); err != nil || !bytes.Equal(rest, wire[7:]) {
				t.Fatalf("remaining hello was not relayed: %v", err)
			}
			peer.Write([]byte("still target"))
			peer.CloseWrite()
			reply, err := io.ReadAll(client)
			if err != nil || string(reply) != "still target" {
				t.Fatalf("fallback changed after complete hello: %q, %v", reply, err)
			}
			client.CloseWrite()
			select {
			case <-done:
			case <-lifecycle.Done():
				t.Fatal("fallback did not finish")
			}
			if calls.Load() != 0 {
				t.Fatal("authenticated a hello after committing to fallback")
			}
		})
	}
}

func TestRealityDeadlineFlushesPartialTargetFlight(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := realityAuthenticatedTestHello(t, private)
	client, server := realityTestTCPPair(t)
	target, peer := realityTestTCPPair(t)
	lifecycle, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	handshakeCtx, stop := context.WithTimeout(lifecycle, 200*time.Millisecond)
	defer stop()
	authenticated := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := RealityServer(handshakeCtx, server, &RealityConfig{
			DialContext:     func(context.Context, string, string) (net.Conn, error) { return target, nil },
			FallbackContext: lifecycle,
			ServerNames:     map[string]bool{"example.com": true},
			PrivateKey:      private.Bytes(), ShortIds: map[[8]byte]bool{{}: true},
			MaxTimeDiff:       time.Minute,
			AcceptClientHello: func([]byte, time.Time) bool { close(authenticated); return true },
		})
		done <- err
	}()
	if _, err := client.Write(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, len(wire))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-authenticated:
	case <-lifecycle.Done():
		t.Fatal("hello was not authenticated")
	}
	// An incomplete TLS record is held while REALITY inspects the target.
	if _, err := peer.Write([]byte{22}); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(client, first); err != nil || first[0] != 22 {
		t.Fatalf("buffered target byte was not forwarded on deadline: %v", err)
	}
	// The temporary wakeup deadline must not terminate the ensuing relay.
	if _, err := peer.Write([]byte("continued")); err != nil {
		t.Fatal(err)
	}
	peer.CloseWrite()
	rest, err := io.ReadAll(client)
	if err != nil || string(rest) != "continued" {
		t.Fatalf("fallback after wakeup: %q, %v", rest, err)
	}
	client.CloseWrite()
	select {
	case <-done:
	case <-lifecycle.Done():
		t.Fatal("fallback did not finish")
	}
}
