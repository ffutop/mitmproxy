// +build darwin

package netproxy

import (
	"net"
	"os/exec"
	"syscall"
)

func SetupGlobalNetworkProxy(addr string) error {
	binary, _ := exec.LookPath("networksetup")
	host, port, _ := net.SplitHostPort(addr)
	if _, err := syscall.ForkExec(binary, []string{"networksetup", "-setsecurewebproxy", "Wi-Fi", host, port, "off"}, nil); err != nil {
		return err
	}
	if _, err := syscall.ForkExec(binary, []string{"networksetup", "-setwebproxy", "Wi-Fi", host, port, "off"}, nil); err != nil {
		return err
	}
	if _, err := syscall.ForkExec(binary, []string{"networksetup", "-setsecurewebproxystate", "Wi-Fi", "on"}, nil); err != nil {
		return err
	}
	if _, err := syscall.ForkExec(binary, []string{"networksetup", "-setwebproxystate", "Wi-Fi", "on"}, nil); err != nil {
		return err
	}
	return nil
}

func ShutdownGlobalNetworkProxy() error {
	binary, _ := exec.LookPath("networksetup")
	if _, err := syscall.ForkExec(binary, []string{"networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"}, nil); err != nil {
		return err
	}
	if _, err := syscall.ForkExec(binary, []string{"networksetup", "-setwebproxystate", "Wi-Fi", "off"}, nil); err != nil {
		return err
	}
	return nil
}
