package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// TestRealUtun proves the macOS privileged path: create an actual utun device
// (the one operation that needs root), bring a WireGuard device up on it, and
// confirm the kernel now shows the interface — then tear it back down.
//
// Skipped unless run as root, so `go test` stays unprivileged. To run it:
//
//	go test -c -o /tmp/mpdproxy.test .
//	sudo /tmp/mpdproxy.test -test.run TestRealUtun -test.v
func TestRealUtun(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a utun; run the compiled test binary under sudo")
	}

	// "utun" lets the kernel pick the next free number (utun6, utun7, …).
	dev, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		t.Fatalf("CreateTUN: %v", err)
	}
	name, _ := dev.Name()
	t.Logf("created %s", name)

	// port 0 = let the kernel choose the UDP port; no peer needed here.
	tn, err := NewTunnel(dev, mustKey(t), 0)
	if err != nil {
		t.Fatalf("NewTunnel on %s: %v", name, err)
	}
	defer tn.Close() // tears the utun back down

	out, err := exec.Command("ifconfig", name).CombinedOutput()
	if err != nil {
		t.Fatalf("ifconfig %s: %v\n%s", name, err, out)
	}
	if !strings.Contains(string(out), name) {
		t.Fatalf("ifconfig did not show %s:\n%s", name, out)
	}
	t.Logf("kernel sees the interface:\n%s", strings.TrimSpace(string(out)))
}
