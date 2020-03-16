package netproxy_test

import (
	"testing"

	"github.com/ffutop/mitmproxy/netproxy"
)

func TestGlobalNetwork(t *testing.T) {
	netproxy.SetupGlobalNetworkProxy("127.0.0.1:53960")
	netproxy.ShutdownGlobalNetworkProxy()
}
