package main

import (
	"compress/gzip"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
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
