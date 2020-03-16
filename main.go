package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"github.com/ffutop/mitmproxy/mitm"
	"github.com/ffutop/mitmproxy/netproxy"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var pwd, _ = os.Getwd()
var home = os.Getenv("HOME")
var hostname, _ = os.Hostname()

var (
	configFile string
	config     Config
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var err error

	flag.StringVar(&configFile, "config", "", "Specify custom path to `config.yaml`")
	flag.StringVar(&config.Addr, "addr", "127.0.0.1:53960", "Specify a URI endpoint on which to listen")
	flag.BoolVar(&config.DebugTLS, "debugTLS", false, "Enable debugging information")
	flag.StringVar(&config.CertFile, "certFile", filepath.Join(home, ".mitm/ca-cert.pem"), "Path to a cert file for the root certificate authority")
	flag.StringVar(&config.KeyFile, "keyFile", filepath.Join(home, ".mitm/ca-key.pem"), "Path to a key file for the root certificate authority")
	flag.StringVar(&config.TlsKeyLogFile, "tlsKeyLogFile", filepath.Join(home, ".mitm/master-secret.log"), "Expose NSS Key Log for trace HTTPS traffic via Wireshark. works only DebugTLS is enabled")
	flag.StringVar(&config.LogFile, "logFile", "", "If non-empty, use this log file")
	flag.Parse()

	parseConfig()

	if config.LogFile != "" {
		logFile, err := os.OpenFile(config.LogFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalln(err)
		}
		log.SetOutput(logFile)
	}

	log.Println("final config: ", config)

	// prior create $HOME/.mitm directory
	if err = os.MkdirAll(filepath.Join(home, ".mitm"), 0755); err != nil {
		log.Fatalln(err)
	}

	srv := &mitm.Proxy{}

	if srv.RootCA, err = config.loadRootCA(); err != nil {
		log.Fatalln(err)
	}

	if config.DebugTLS {
		if srv.KeyLogWriter, err = os.OpenFile(config.TlsKeyLogFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600); err != nil {
			log.Fatalln(err)
		}
	}

	if err := netproxy.SetupGlobalNetworkProxy(config.Addr); err != nil {
		log.Fatalln(err)
	}

	go func() {
		log.Println("proxy server started on", config.Addr)
		if err = http.ListenAndServe(config.Addr, srv); err != nil {
			log.Fatalln(err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGHUP, os.Interrupt)
	s := <-c
	log.Println(s)
	netproxy.ShutdownGlobalNetworkProxy()
}

// Note: struct fields must be public in order for unmarshal to
// correctly populate the data.
type Config struct {
	Addr          string `yaml:"Addr"`
	DebugTLS      bool   `yaml:"debugTLS"`
	CertFile      string `yaml:"certFile"`
	KeyFile       string `yaml:"keyFile"`
	TlsKeyLogFile string `yaml:"tlsKeyLogFile"`
	LogFile       string `yaml:"logFile"`
}

func parseConfig() {
	if configFile == "" {
		return
	}
	bytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalln(err)
	}
	if err = yaml.Unmarshal(bytes, &config); err != nil {
		log.Fatalln(err)
	}
}

func (config *Config) loadRootCA() (rootCA *tls.Certificate, err error) {
	var certificate tls.Certificate
	// direct load certificate from storage
	certificate, err = tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		log.Println("RootCA not exist, auto generate")
		// generate new RootCA key, cert
		cert, key, err := mitm.GenerateRootCertificate(hostname)
		if err != nil {
			return nil, err
		}
		// persist to storage
		if err := ioutil.WriteFile(config.CertFile, cert, 0600); err != nil {
			return nil, err
		}
		if err := ioutil.WriteFile(config.KeyFile, key, 0600); err != nil {
			return nil, err
		}

		// build RootCA
		certificate, err = tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, err
		}
	}
	if certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0]); err != nil {
		return nil, err
	}

	return &certificate, nil
}
