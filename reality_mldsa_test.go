package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestRealityMLDSA65Certificate(t *testing.T) {
	publicKey, privateKey := mldsa65.NewKeyFromSeed(&[mldsa65.SeedSize]byte{1})
	authKey := bytes.Repeat([]byte{2}, 32)
	clientHello, serverHello := []byte("client hello"), []byte("server hello")
	for _, enabled := range []bool{false, true} {
		var signingKey []byte
		if enabled {
			signingKey = privateKey.Bytes()
		}
		certificate, err := realityCertificate(authKey, clientHello, serverHello, signingKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		h := hmac.New(sha512.New, authKey)
		h.Write(cert.PublicKey.(ed25519.PublicKey))
		if !hmac.Equal(h.Sum(nil), cert.Signature) {
			t.Fatal("legacy authentication signature changed")
		}
		if !enabled {
			if len(cert.Extensions) != 0 {
				t.Fatal("legacy certificate acquired an extension")
			}
			continue
		}
		if len(cert.Extensions) != 1 || !cert.Extensions[0].Id.Equal([]int{0, 0}) {
			t.Fatal("signature extension differs from Xray's format")
		}
		h.Write(clientHello)
		h.Write(serverHello)
		signature := cert.Extensions[0].Value
		if !mldsa65.Verify(publicKey, h.Sum(nil), nil, signature) {
			t.Fatal("signature does not bind the certificate and hello transcript")
		}
		h.Write([]byte("tampered"))
		if mldsa65.Verify(publicKey, h.Sum(nil), nil, signature) {
			t.Fatal("accepted modified transcript")
		}
		_, template := realityServerCertMLDSA65()
		original, err := x509.ParseCertificate(template)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original.Extensions[0].Value, make([]byte, mldsa65.SignatureSize)) {
			t.Fatal("shared certificate template was modified")
		}
	}
	if _, err := realityCertificate(authKey, clientHello, serverHello, []byte{1}); err == nil {
		t.Fatal("accepted malformed signing key")
	}
	config := &RealityConfig{Mldsa65Key: privateKey.Bytes()}
	if !bytes.Equal(config.Clone().Mldsa65Key, privateKey.Bytes()) {
		t.Fatal("clone lost signing key")
	}
}
