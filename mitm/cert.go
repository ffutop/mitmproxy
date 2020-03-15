package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	// Certificate Not Before Tolerance, ensure new signed Certificate is valid at now()
	certificateNotBeforeTolerance = -1 * time.Hour
	// valid for 10 years
	certificateAuthorityMaxAge = 10 * 365 * 24 * time.Hour
	// valid for 1 day
	certificateMaxAge = 24 * time.Hour
	// not sure entirely, so set all to make sure it works
	keyUsage          = x509.KeyUsageCertSign |
		x509.KeyUsageContentCommitment |
		x509.KeyUsageCRLSign |
		x509.KeyUsageDataEncipherment |
		x509.KeyUsageDecipherOnly |
		x509.KeyUsageDigitalSignature |
		x509.KeyUsageEncipherOnly |
		x509.KeyUsageKeyAgreement |
		x509.KeyUsageKeyEncipherment
)

func generateCertificate(rootCA *tls.Certificate, names []string) (*tls.Certificate, error) {
	// if signer certificate is not RootCA, fast-fail
	if !rootCA.Leaf.IsCA {
		return nil, errors.New("not a RootCA file")
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.SHA512WithRSA,
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             now.Add(certificateNotBeforeTolerance),
		NotAfter:              now.Add(certificateMaxAge),
		KeyUsage:              keyUsage,
		DNSNames:              names,
		BasicConstraintsValid: true,
	}
	// generate new RSA private/public key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	// use Root Certificate sign new Certificate
	x, err := x509.CreateCertificate(rand.Reader, template, rootCA.Leaf, privateKey.Public(), rootCA.PrivateKey)
	if err != nil {
		return nil, err
	}
	cert := new(tls.Certificate)
	cert.Certificate = append(cert.Certificate, x)
	cert.PrivateKey = privateKey
	cert.Leaf, _ = x509.ParseCertificate(x)
	return cert, nil
}

func GenerateRootCertificate(name string) (certPEM, keyPEM []byte, err error) {
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		SignatureAlgorithm:    x509.SHA512WithRSA,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(certificateNotBeforeTolerance),
		NotAfter:              now.Add(certificateAuthorityMaxAge),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	// generate new RSA private/public key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	// create self-signed Certificate as Root Certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return
}
