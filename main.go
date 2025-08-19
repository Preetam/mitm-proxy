// Command mitm-proxy is a man-in-the-middle proxy for HTTP and HTTPS traffic.
//
// It logs all traffic to a SQLite database. For HTTPS traffic, it generates
// TLS certificates on the fly, signed by a provided root CA. To use it, you
// must configure your client (e.g., a web browser) to trust the root CA
// certificate and route its traffic through this proxy.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	_ "github.com/mattn/go-sqlite3"
)

// Proxy is the state for the MITM proxy.
type Proxy struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	db     *sql.DB
	log    *log.Logger

	// certCache caches generated certificates for hosts to avoid
	// regenerating them on every connection.
	certCache map[string]*tls.Certificate
	certMu    sync.RWMutex

	// transport is the http.Transport used to talk to target servers.
	// We use a custom one to disable automatic features that interfere
	// with our manual response handling.
	transport *http.Transport
}

// NewProxy creates a new Proxy.
func NewProxy(caCertPath, caKeyPath, dbPath string) (*Proxy, error) {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := initDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init database: %w", err)
	}

	return &Proxy{
		caCert:    caCert,
		caKey:     caKey,
		db:        db,
		log:       log.New(os.Stdout, "mitm-proxy: ", log.LstdFlags),
		certCache: make(map[string]*tls.Certificate),
		transport: &http.Transport{
			// By disabling compression, we receive the raw response body from the
			// server, which we can then manually decompress for logging.
			DisableCompression: true,
			// We need to skip verification for the server because the proxy is
			// terminating the TLS connection. The proxy makes its own secure
			// connection to the server.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleTunnel(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP proxies a plain HTTP request.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var reqBody []byte
	if r.Body != nil {
		var err error
		reqBody, err = io.ReadAll(r.Body)
		if err != nil {
			p.log.Printf("error reading request body for %s: %v", r.URL, err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	resp, err := p.transport.RoundTrip(r)
	if err != nil {
		p.log.Printf("http roundtrip for %s: %v", r.URL, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	respBody, err := decodeBody(resp.Header, resp.Body)
	if err != nil {
		p.log.Printf("error decoding response body for %s: %v", r.URL, err)
	}

	p.logTraffic("HTTP", r, reqBody, resp, respBody)

	// Since we manually decompressed the body, we must remove the
	// Content-Encoding header before writing the response to the client.
	resp.Header.Del("Content-Encoding")

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleTunnel handles an HTTPS CONNECT request.
func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		p.log.Printf("failed to send 200 OK to client for %s: %v", r.Host, err)
		return
	}

	host := strings.Split(r.Host, ":")[0]
	cert, err := p.getCert(host)
	if err != nil {
		p.log.Printf("failed to get certificate for %s: %v", host, err)
		return
	}

	tlsConn := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*cert}})
	if err := tlsConn.Handshake(); err != nil {
		p.log.Printf("tls handshake with client for %s: %v", r.Host, err)
		return
	}
	defer tlsConn.Close()

	connReader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(connReader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				p.log.Printf("reading request from tls tunnel for %s: %v", r.Host, err)
			}
			break
		}
		req.URL.Scheme = "https"
		req.URL.Host = req.Host

		var reqBody []byte
		if req.Body != nil {
			reqBody, _ = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		// Use our custom transport, not http.DefaultTransport.
		resp, err := p.transport.RoundTrip(req)
		if err != nil {
			p.log.Printf("https roundtrip for %s: %v", req.URL, err)
			fmt.Fprintf(tlsConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			continue
		}

		respBody, _ := decodeBody(resp.Header, resp.Body)
		resp.Body.Close() // Close original body

		p.logTraffic("HTTPS", req, reqBody, resp, respBody)

		// Replace the response body with our fully-read, decompressed buffer.
		// This ensures that resp.Write can calculate the Content-Length.
		resp.Body = io.NopCloser(bytes.NewReader(respBody))
		resp.Header.Del("Content-Encoding")
		// Let resp.Write calculate the correct Content-Length.
		resp.Header.Del("Content-Length")
		resp.ContentLength = int64(len(respBody))

		if err := resp.Write(tlsConn); err != nil {
			p.log.Printf("writing response to client for %s: %v", req.URL, err)
		}

		if req.Close || resp.Close || req.Header.Get("Connection") == "close" {
			break
		}
	}
}

// getCert retrieves a certificate for the given host, using a cache.
func (p *Proxy) getCert(host string) (*tls.Certificate, error) {
	p.certMu.RLock()
	cert, found := p.certCache[host]
	p.certMu.RUnlock()
	if found {
		return cert, nil
	}

	p.certMu.Lock()
	defer p.certMu.Unlock()
	if cert, found := p.certCache[host]; found {
		return cert, nil
	}

	newCert, err := p.generateCert(host)
	if err != nil {
		return nil, err
	}
	p.certCache[host] = newCert
	return newCert, nil
}

// generateCert creates a new certificate for the given host.
func (p *Proxy) generateCert(host string) (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host},
		DNSNames:              []string{host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &priv.PublicKey, p.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	return &cert, nil
}

func loadCA(certPath, keyPath string) (cert *x509.Certificate, key *rsa.PrivateKey, err error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid CA certificate PEM")
	}
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}

	if k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		return cert, k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		if rsaKey, ok := k.(*rsa.PrivateKey); ok {
			return cert, rsaKey, nil
		}
		return nil, nil, errors.New("not an RSA private key")
	}

	return nil, nil, errors.New("failed to parse CA private key")
}

func initDB(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS traffic (
		id                 INTEGER PRIMARY KEY,
		timestamp          DATETIME NOT NULL,
		protocol           TEXT NOT NULL,
		method             TEXT NOT NULL,
		host               TEXT NOT NULL,
		path               TEXT NOT NULL,
		request_headers    TEXT,
		request_body       BLOB,
		response_status    INTEGER,
		response_headers   TEXT,
		response_body      BLOB
	)`)
	return err
}

func (p *Proxy) logTraffic(protocol string, req *http.Request, reqBody []byte, resp *http.Response, respBody []byte) {
	reqHeaders, _ := json.Marshal(req.Header)
	respHeaders, _ := json.Marshal(resp.Header)

	_, err := p.db.Exec(`
		INSERT INTO traffic (timestamp, protocol, method, host, path, request_headers, request_body, response_status, response_headers, response_body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now(), protocol, req.Method, req.Host, req.URL.Path,
		string(reqHeaders), reqBody, resp.StatusCode, string(respHeaders), respBody,
	)
	if err != nil {
		p.log.Printf("log to db: %v", err)
	}
}

func decodeBody(h http.Header, body io.Reader) ([]byte, error) {
	var r io.Reader
	switch h.Get("Content-Encoding") {
	case "gzip":
		gr, err := gzip.NewReader(body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		r = gr
	case "br":
		r = brotli.NewReader(body)
	default:
		r = body
	}
	return io.ReadAll(r)
}

func main() {
	certFile := flag.String("cert", "", "Path to root CA certificate. (required)")
	keyFile := flag.String("key", "", "Path to root CA private key. (required)")
	addr := flag.String("addr", ":5559", "Proxy listen address.")
	dbFile := flag.String("db", "proxy.db", "Path to SQLite database.")
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		flag.Usage()
		os.Exit(2)
	}

	p, err := NewProxy(*certFile, *keyFile, *dbFile)
	if err != nil {
		log.Fatalf("failed to start proxy: %v", err)
	}
	defer p.db.Close()

	p.log.Printf("starting server on %s", *addr)
	if err := http.ListenAndServe(*addr, p); err != nil {
		p.log.Fatalf("server shut down: %v", err)
	}
}
