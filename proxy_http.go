package main

import (
	"bytes"
	"io"
	"net/http"
)

// handleHTTP proxies a plain HTTP request.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var reqBody []byte
	if r.Body != nil {
		var err error
		reqBody, err = io.ReadAll(r.Body)
		if err != nil {
			p.log.Printf("read request body for %s: %v", r.URL, err)
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
		p.log.Printf("decode response body for %s: %v", r.URL, err)
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
