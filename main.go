// Command mitm-proxy is a man-in-the-middle proxy for HTTP and HTTPS traffic.
//
// It logs all traffic to a SQLite database. For HTTPS traffic, it generates
// TLS certificates on the fly, signed by a provided root CA. To use it, you
// must configure your client (e.g., a web browser) to trust the root CA
// certificate and route its traffic through this proxy.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

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
