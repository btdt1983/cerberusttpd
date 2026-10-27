// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package localca is a small private CA for LAN use: it creates a root once,
// issues short-lived leaf certificates for this host and renews them on the fly.
// Users trust ca.pem once in their browser/OS.
package localca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	leafLife = 90 * 24 * time.Hour
	caLife   = 10 * 365 * 24 * time.Hour
)

type CA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	pem   []byte
	names []string
}

// Load reads the CA from dir, creating it on first use. extra are additional
// DNS names or IPs to put in the leaf certificate.
func Load(dir string, extra []string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	crtPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	ca := &CA{names: extra}
	crtPEM, err1 := os.ReadFile(crtPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if err1 == nil && err2 == nil {
		if err := ca.parse(crtPEM, keyPEM); err != nil {
			return nil, fmt.Errorf("localca: %w", err)
		}
		return ca, nil
	}
	if err := ca.create(crtPath, keyPath); err != nil {
		return nil, err
	}
	return ca, nil
}

func (c *CA) parse(crtPEM, keyPEM []byte) error {
	b, _ := pem.Decode(crtPEM)
	if b == nil {
		return fmt.Errorf("invalid ca.pem")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return fmt.Errorf("invalid ca-key.pem")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return err
	}
	c.cert, c.key, c.pem = cert, key, crtPEM
	return nil
}

func (c *CA) create(crtPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Cerberusttpd Local CA", Organization: []string{"Cerberusttpd"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caLife),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	c.cert, c.key, c.pem = cert, key, crtPEM
	return nil
}

// RootPEM is the public root certificate users must trust.
func (c *CA) RootPEM() []byte { return c.pem }

// RootDER is the same root certificate in DER form (.crt/.cer), which Windows
// and Android import directly.
func (c *CA) RootDER() []byte { return c.cert.Raw }

// IssueLeaf creates a fresh server certificate for this host and returns it as
// PEM (certificate, private key) with its expiry. Only the process holding the
// CA key calls this; the network process just receives the result.
func (c *CA) IssueLeaf() (certPEM, keyPEM []byte, notAfter time.Time, err error) {
	leaf, err := c.issue()
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	kb, err := x509.MarshalECPrivateKey(leaf.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return certPEM, keyPEM, leaf.Leaf.NotAfter, nil
}

func (c *CA) issue() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dns := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if h, err := os.Hostname(); err == nil {
		dns = append(dns, h)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
				ips = append(ips, ipn.IP)
			}
		}
	}
	for _, n := range c.names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "cerberusttpd"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(leafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}
