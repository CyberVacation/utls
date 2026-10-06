package tls

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

type realityRecordTestConn struct {
	net.Conn
	bytes.Buffer
	shortWrite bool
}

func (c *realityRecordTestConn) Read(b []byte) (int, error) {
	return c.Buffer.Read(b)
}

func (c *realityRecordTestConn) Write(b []byte) (int, error) {
	if c.shortWrite {
		return len(b) - 1, nil
	}
	return c.Buffer.Write(b)
}

func TestRealityPostHandshakeRecords(t *testing.T) {
	for _, suiteID := range []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256} {
		t.Run(CipherSuiteName(suiteID), func(t *testing.T) {
			suite := cipherSuiteTLS13ByID(suiteID)
			secret := make([]byte, suite.hash.Size())
			wire := new(realityRecordTestConn)
			conn := &Conn{conn: wire, config: &Config{}, vers: VersionTLS13}
			conn.out.version = VersionTLS13
			conn.out.setTrafficSecret(suite, QUICEncryptionLevelApplication, secret)
			peer := halfConn{version: VersionTLS13}
			peer.setTrafficSecret(suite, QUICEncryptionLevelApplication, secret)
			lengths := []int{22, 100, recordHeaderLen + maxPlaintext + 1 + 16}
			if err := conn.writeRealityPostHandshakeRecords(lengths); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.writeRecordLocked(recordTypeApplicationData, []byte("hello")); err != nil {
				t.Fatal(err)
			}
			for i, length := range append(lengths, 27) {
				record := wire.Next(length)
				if len(record) != length || int(binary.BigEndian.Uint16(record[3:5]))+5 != length {
					t.Fatalf("record %d has wrong wire length", i)
				}
				plaintext, typ, err := peer.decrypt(record)
				if err != nil || typ != recordTypeApplicationData {
					t.Fatalf("record %d: type %v, error %v", i, typ, err)
				}
				want := ""
				if i == len(lengths) {
					want = "hello"
				}
				if string(plaintext) != want {
					t.Fatalf("record %d delivered unexpected application bytes", i)
				}
			}
		})
	}
}

func TestRealityPostHandshakeRecordsRejectInvalid(t *testing.T) {
	for _, lengths := range [][]int{{100, -1}, {21}, {recordHeaderLen + maxCiphertextTLS13 + 1}, make([]int, maxUselessRecords+1)} {
		wire := new(realityRecordTestConn)
		conn := &Conn{conn: wire, config: &Config{}, vers: VersionTLS13}
		conn.out.version = VersionTLS13
		conn.out.setTrafficSecret(cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256), QUICEncryptionLevelApplication, make([]byte, 32))
		if err := conn.writeRealityPostHandshakeRecords(lengths); err == nil || wire.Len() != 0 {
			t.Fatalf("invalid lengths %v were not rejected before writing", lengths)
		}
	}
	wire := &realityRecordTestConn{shortWrite: true}
	conn := &Conn{conn: wire, config: &Config{}, vers: VersionTLS13}
	conn.out.version = VersionTLS13
	conn.out.setTrafficSecret(cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256), QUICEncryptionLevelApplication, make([]byte, 32))
	if err := conn.writeRealityPostHandshakeRecords([]int{100}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	if !errors.Is(conn.out.err, io.ErrShortWrite) {
		t.Fatal("write failure did not poison the output state")
	}
	called := false
	config := &RealityConfig{GetPostHandshakeRecordLengths: func(context.Context, string, []string) []int {
		called = true
		return nil
	}}
	config.Clone().GetPostHandshakeRecordLengths(context.Background(), "example.com", nil)
	if !called {
		t.Fatal("clone lost record callback")
	}
}
