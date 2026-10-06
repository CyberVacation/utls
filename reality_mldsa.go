package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// XTLS/REALITY encodes the ML-DSA-65 signature in an extension with OID 0.0.
// In this certificate template its value begins at byte 126.
const realityMLDSA65SignatureOffset = 126

var realityServerCertMLDSA65 = onceValues(func() (ed25519.PrivateKey, []byte) {
	key, _ := realityServerCert()
	template := &x509.Certificate{
		SerialNumber: new(big.Int),
		ExtraExtensions: []pkix.Extension{{
			Id:    []int{0, 0},
			Value: make([]byte, mldsa65.SignatureSize),
		}},
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		panic(err)
	}
	return key, cert
})

func realityCertificate(authKey, clientHello, serverHello, signingKey []byte) (*Certificate, error) {
	key, template := realityServerCert()
	if len(signingKey) > 0 {
		key, template = realityServerCertMLDSA65()
	}
	cert := bytes.Clone(template)
	h := hmac.New(sha512.New, authKey)
	h.Write(key[32:])
	copy(cert[len(cert)-sha512.Size:], h.Sum(nil))
	if len(signingKey) > 0 {
		privateKey, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(signingKey)
		if err != nil {
			return nil, fmt.Errorf("REALITY: invalid ML-DSA-65 signing key: %w", err)
		}
		h.Write(clientHello)
		h.Write(serverHello)
		signature := cert[realityMLDSA65SignatureOffset : realityMLDSA65SignatureOffset+mldsa65.SignatureSize]
		if err := mldsa65.SignTo(privateKey.(*mldsa65.PrivateKey), h.Sum(nil), nil, false, signature); err != nil {
			return nil, fmt.Errorf("REALITY: sign ML-DSA-65 certificate: %w", err)
		}
	}
	return &Certificate{Certificate: [][]byte{cert}, PrivateKey: key}, nil
}
