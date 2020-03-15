package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/ffutop/mitmproxy/mitm"
	"gopkg.in/yaml.v2"
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

	flag.StringVar(&configFile, "config", filepath.Join(home, ".mitm/config.yaml"), "Specify custom path to `config.yaml`")
	flag.StringVar(&config.addr, "addr", "127.0.0.1:53960", "Specify a URI endpoint on which to listen")
	flag.BoolVar(&config.debugTLS, "debugTLS", false, "Enable debugging information")
	flag.StringVar(&config.certFile, "certFile", filepath.Join(home, ".mitm/ca-cert.pem"), "Path to a cert file for the root certificate authority")
	flag.StringVar(&config.keyFile, "keyFile", filepath.Join(home, ".mitm/ca-key.pem"), "Path to a key file for the root certificate authority")
	flag.StringVar(&config.tlsKeyLogFile, "tlsKeyLogFile", filepath.Join(home, ".mitm/master-secret.log"), "Expose NSS Key Log for trace HTTPS traffic via Wireshark. works only debugTLS is enabled")
	flag.StringVar(&config.logFile, "logFile", filepath.Join(home, ".mitm/mitmproxy.log"), "If non-empty, use this log file")
	flag.Parse()

	parseConfig()

	srv := &mitm.Proxy{}

	if srv.RootCA, err = config.loadRootCA(); err != nil {
		log.Fatalln(err)
	}

	if config.debugTLS {
		if srv.KeyLogWriter, err = os.OpenFile(config.tlsKeyLogFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600); err != nil {
			log.Fatalln(err)
		}
	}

	log.Println("proxy server started on", config.addr)
	if err = http.ListenAndServe(config.addr, srv); err != nil {
		log.Fatalln(err)
	}
}

type Config struct {
	addr          string `yaml:"addr"`
	debugTLS      bool   `yaml:"debugTLS"`
	certFile      string `yaml:"certFile"`
	keyFile       string `yaml:"keyFile"`
	tlsKeyLogFile string `yaml:"tlsKeyLogFile"`
	logFile       string `yaml:"logFile"`
}

func parseConfig() {
	bytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalln(err)
	}
	if err = yaml.Unmarshal(bytes, &config); err != nil {
		log.Fatalln(err)
	}
	log.Println("parse config success. config: ", config)
}

func (config *Config) loadRootCA() (rootCA *tls.Certificate, err error) {
	var certificate tls.Certificate
	// direct load certificate from storage
	certificate, err = tls.LoadX509KeyPair(config.certFile, config.keyFile)
	if err != nil {
		log.Println("RootCA not exist, auto generate")
		// generate new RootCA key, cert
		cert, key, err := mitm.GenerateRootCertificate(hostname)
		if err != nil {
			return nil, err
		}
		// persist to storage
		if err := ioutil.WriteFile(config.certFile, cert, 0600); err != nil {
			return nil, err
		}
		if err := ioutil.WriteFile(config.keyFile, key, 0600); err != nil {
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
