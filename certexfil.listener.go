// server is A TLS listenning service to receive payload embedded
// inside client certificate.
// @Sourcefrenchy
package main

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/sourcefrenchy/cryptopayload"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Oo" to the response body
	io.WriteString(w, "Oo\n")
	tls := r.TLS
	certs := tls.PeerCertificates

	if len(certs) > 0 {
		log.Printf("received:\t%s", certs[0].DNSNames[1])
		cryptopayload.Retrieve(certs[0].DNSNames[1])
	}
}

func main() {
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile("./CERTS/server_cert.pem")
	if err != nil {
		log.Fatal("No certificate in ./CERTS. Use certexfil.client at least once.")
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientCAs:  caCertPool,
		//	ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientAuth:               tls.RequestClientCert,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
	}
	tlsConfig.BuildNameToCertificate()

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:         ":8443",
		TLSConfig:    tlsConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	// Set up a /hello resource handler
	http.HandleFunc("/c2cert", rootHandler)
	// Listen to HTTPS connections with the server certificate and wait
	serr := server.ListenAndServeTLS("./CERTS/server_cert.pem", "./CERTS/server_key.pem")
	if serr != nil {
		log.Fatal("ListenAndServe: ", serr)
	}
}
