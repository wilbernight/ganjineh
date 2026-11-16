package main

// One port, both protocols: a connection that starts with a TLS handshake
// is served as HTTPS (self-signed certificate made at startup, never stored),
// anything else as plain HTTP. So http://IP:443 and https://IP both work,
// and browsers that switch to https automatically still connect.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"time"
)

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(b []byte) (int, error) { return c.r.Read(b) }

type dualListener struct {
	net.Listener
	cfg  *tls.Config
	ch   chan net.Conn
	port int
	err  error
}

func newDualListener(ln net.Listener, cfg *tls.Config) net.Listener {
	d := &dualListener{Listener: ln, cfg: cfg, ch: make(chan net.Conn)}
	if a, ok := ln.Addr().(*net.TCPAddr); ok {
		d.port = a.Port
	}
	go d.loop()
	return d
}

func (d *dualListener) loop() {
	for {
		c, err := d.Listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			d.err = err
			close(d.ch)
			return
		}
		go func() {
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if ch := takePending(d.port, ip); ch != nil { // FTP data connection
				ch <- c
				return
			}
			wait, sniff := 15*time.Second, isSniffPort(d.port)
			if sniff {
				wait = 1500 * time.Millisecond
			}
			c.SetReadDeadline(time.Now().Add(wait))
			br := bufio.NewReader(c)
			b, err := br.Peek(1)
			c.SetReadDeadline(time.Time{})
			pc := &peekConn{c, br}
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() && sniff {
					serveFTPConn(pc) // silent client: FTP
					return
				}
				c.Close()
				return
			}
			if b[0] == 0x16 && d.cfg != nil { // TLS handshake record
				d.ch <- tls.Server(pc, d.cfg)
			} else {
				d.ch <- pc
			}
		}()
	}
}

func (d *dualListener) Accept() (net.Conn, error) {
	c, ok := <-d.ch
	if !ok {
		return nil, d.err
	}
	return c, nil
}

// selfSignedTLS makes a fresh certificate for this computer's names/IPs.
func selfSignedTLS() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil
	}
	host, _ := os.Hostname()
	tpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(randBytes(16)),
		Subject:      pkix.Name{CommonName: "LAN File Server " + host, Organization: []string{"LAN File Server"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	if host != "" {
		tpl.DNSNames = append(tpl.DNSNames, host)
	}
	for _, ip := range lanIPs() {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
}
