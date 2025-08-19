package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

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
