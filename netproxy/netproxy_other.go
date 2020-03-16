// +build !darwin

package netproxy

import "log"

func SetupGlobalNetwork(addr string) {
	log.Println("Please setup network proxy manually")
}

func SetdownGlobalNetwork() {
	log.Println("Please shutdown network proxy manually")
}
