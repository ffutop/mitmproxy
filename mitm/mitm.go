package mitm

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
)

var statusLineOK = []byte("HTTP/1.1 200 OK\r\n\r\n")

type Proxy struct {
	RootCA       *tls.Certificate
	KeyLogWriter io.Writer
}

//
// +----------+         Self Signed Root Certificate
// |  Client  | <-----------------------------------------------+
// +----------+       Certificate Signed by Self Root CA        |
//      ^                                                       v
//      |                                                  +----------+
//      X No more Direct Communicate                       |   MITM   |
//      |                                                  +----------+
//      v                                                       ^
// +----------+                                                 |
// |  Server  | <-----------------------------------------------+
// +----------+    Trusted Communicate as normal Client-Server
//
func (proxy *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	// as a http proxy tunnel, only handle CONNECT Method
	case http.MethodConnect:
		// prepare domainName, sign a new Certificate
		domainName, _, err := net.SplitHostPort(r.URL.Host)
		if err != nil {
			http.Error(w, "proxy: failed to get domain name", http.StatusBadRequest)
			return
		}

		// hijack http, expose lower layer tcp conn
		hijacker, ok := w.(http.Hijacker)
		if ok == false {
			http.Error(w, "proxy: failed to convert to hijacker", http.StatusInternalServerError)
			return
		}

		cconn, _, err := hijacker.Hijack()
		defer cconn.Close()
		if err != nil {
			http.Error(w, "proxy: failed to hijack", http.StatusInternalServerError)
			return
		}

		// response status 200 OK, official establish http tunnel between client-proxy
		if _, err := cconn.Write(statusLineOK); err != nil {
			// if failed while response to client, close and wait client retry
			log.Fatalln(err)
			return
		}

		// proxy side handshake with client, will use fake Certificate signed by proxy RootCA
		// generate new certificate based on proxy RootCA
		certificate, err := generateCertificate(proxy.RootCA, []string{domainName})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		cconfig := &tls.Config{
			Certificates: []tls.Certificate{*certificate},
		}
		// wrapper raw tcp conn with tls
		cTlsConn := tls.Server(cconn, cconfig)
		defer cTlsConn.Close()
		if err := cTlsConn.Handshake(); err != nil {
			log.Fatalln(err)
			return
		}

		sconn, err := net.Dial("tcp", r.URL.Host)
		defer sconn.Close()
		sconfig := &tls.Config{
			ServerName:   domainName,
			KeyLogWriter: proxy.KeyLogWriter,
		}
		sTlsConn := tls.Client(sconn, sconfig)
		defer sTlsConn.Close()
		if err := sTlsConn.Handshake(); err != nil {
			log.Fatalln(err)
			return
		}

		ch := make(chan struct{})
		listener := &oneConnListener{cTlsConn, ch}

		reverseProxy := &httputil.ReverseProxy{
			Director: func(request *http.Request) {
				request.URL.Host = request.Host
				request.URL.Scheme = "https"
			},
			Transport: &http.Transport{
				DialTLS:         func(network, addr string) (n net.Conn, err error) { return sTlsConn, nil },
			},
		}
		http.Serve(listener, reverseProxy)
		<-ch
	default:
		log.Println("not supported")
	}
}

// Copied From standard lib net/http/serve_test.go, a little modification.
type oneConnListener struct {
	conn   net.Conn
	waitCh chan<- struct{}
}

func (l *oneConnListener) Accept() (c net.Conn, err error) {
	c = l.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	l.conn = nil
	return
}

func (l *oneConnListener) Close() error {
	l.waitCh <- struct{}{}
	return nil
}

func (l *oneConnListener) Addr() net.Addr {
	return nil
}