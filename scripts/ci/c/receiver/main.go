// Command receiver is the live-macos validation's SIEM stand-in: an RFC 5425
// syslog-over-TLS listener and an HTTPS webhook listener on 127.0.0.1, with
// a throw-away CA it creates (or reuses from -pki, so a restart keeps the
// CA ZAAFVesper pinned). Every syslog message and every webhook body is
// appended as one line to -out/syslog.log and -out/webhook.log. Test tool
// for the CI runner only; it never listens beyond loopback.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxMsg = 1 << 20

func main() {
	pki := flag.String("pki", "", "directory for ca.pem, server.pem and server.key (created when missing)")
	out := flag.String("out", "", "directory for syslog.log and webhook.log")
	syslogAddr := flag.String("syslog", "127.0.0.1:6514", "syslog-over-TLS listen address (loopback only)")
	httpsAddr := flag.String("https", "127.0.0.1:8443", "HTTPS listen address (loopback only)")
	tokenFile := flag.String("token-file", "", "file holding the expected bearer token")
	flag.Parse()
	if *pki == "" || *out == "" || *tokenFile == "" {
		log.Fatal("usage: receiver -pki DIR -out DIR -token-file FILE")
	}
	for _, a := range []string{*syslogAddr, *httpsAddr} {
		host, _, err := net.SplitHostPort(a)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			log.Fatalf("%s: only loopback addresses are allowed", a)
		}
	}
	tok, err := os.ReadFile(*tokenFile)
	if err != nil {
		log.Fatal(err)
	}
	token := strings.TrimSpace(string(tok))
	cert, err := loadOrCreatePKI(*pki)
	if err != nil {
		log.Fatal(err)
	}
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	sl, err := openLog(filepath.Join(*out, "syslog.log"))
	if err != nil {
		log.Fatal(err)
	}
	wl, err := openLog(filepath.Join(*out, "webhook.log"))
	if err != nil {
		log.Fatal(err)
	}
	ln, err := tls.Listen("tcp", *syslogAddr, conf)
	if err != nil {
		log.Fatal(err)
	}
	go serveSyslog(ln, sl)
	mux := http.NewServeMux()
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		want := "Bearer " + token
		if r.Method != http.MethodPost || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, "read", http.StatusBadRequest)
			return
		}
		wl.write(bytes.ReplaceAll(b, []byte("\n"), []byte(" ")))
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Addr: *httpsAddr, Handler: mux, TLSConfig: conf, ReadHeaderTimeout: 10 * time.Second}
	hl, err := tls.Listen("tcp", *httpsAddr, conf)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := srv.Serve(hl); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Print(err)
		}
	}()
	log.Printf("receiver: syslog %s, https %s, pid %d", *syslogAddr, *httpsAddr, os.Getpid())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	_ = ln.Close()
	_ = srv.Close()
	sl.close()
	wl.close()
}

type lineLog struct {
	mu sync.Mutex
	f  *os.File
}

func openLog(p string) (*lineLog, error) {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &lineLog{f: f}, nil
}

func (l *lineLog) write(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(append([]byte(nil), b...), '\n'))
}

func (l *lineLog) close() { _ = l.f.Close() }

// serveSyslog reads octet-counted RFC 5425 frames ("LEN SP MSG").
func serveSyslog(ln net.Listener, l *lineLog) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				n, err := br.ReadString(' ')
				if err != nil {
					return
				}
				size, err := strconv.Atoi(strings.TrimSpace(n))
				if err != nil || size <= 0 || size > maxMsg {
					return
				}
				buf := make([]byte, size)
				if _, err := io.ReadFull(br, buf); err != nil {
					return
				}
				l.write(bytes.ReplaceAll(buf, []byte("\n"), []byte(" ")))
			}
		}(c)
	}
}

// loadOrCreatePKI returns the server certificate for 127.0.0.1, creating a
// CA and the certificate in dir on first use.
func loadOrCreatePKI(dir string) (tls.Certificate, error) {
	certPath, keyPath, caPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "zaafvesper live-macos CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	srvT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, srvT, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	for p, b := range map[string][]byte{
		caPath:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return tls.Certificate{}, fmt.Errorf("%s: %w", p, err)
		}
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}
