package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newNetTunnel builds a WireGuard device on a userspace netstack tun with the
// given tunnel address and UDP listen port — no utun, no sudo. It returns the
// Tunnel (to add peers) and the netstack Net (to dial/listen inside it).
func newNetTunnel(t *testing.T, addr string, port int, key wgtypes.Key) (*Tunnel, *netstack.Net) {
	t.Helper()
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(addr)}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	tn, err := NewTunnel(dev, key, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tn.Close() })
	return tn, tnet
}

func loopback(port int) string { return fmt.Sprintf("127.0.0.1:%d", port) }

// listenOn accepts one connection on tnet's addr:9000 and delivers its bytes
// on the returned channel — so a test can assert *which* peer received what.
func listenOn(t *testing.T, tnet *netstack.Net, addr string) <-chan string {
	t.Helper()
	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP(addr), Port: 9000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		ch <- string(data)
	}()
	return ch
}

// send dials addr through tnet's tunnel and writes msg.
func send(t *testing.T, tnet *netstack.Net, addr, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tnet.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s through tunnel: %v", addr, err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
}

// recv waits for a message or fails — a wrong route shows up as silence here.
func recv(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived through the tunnel — handshake or routing failed")
		return ""
	}
}

// TestTunnelLoopback: two devices, peered over 127.0.0.1, a message crossing
// the encrypted tunnel from one address to the other.
func TestTunnelLoopback(t *testing.T) {
	keyA, keyB := mustKey(t), mustKey(t)
	const portA, portB = 58121, 58122

	tA, netA := newNetTunnel(t, "10.99.0.1", portA, keyA)
	tB, netB := newNetTunnel(t, "10.99.0.2", portB, keyB)

	if err := tA.AddPeer(keyB.PublicKey(), loopback(portB), "10.99.0.2/32"); err != nil {
		t.Fatal(err)
	}
	if err := tB.AddPeer(keyA.PublicKey(), loopback(portA), "10.99.0.1/32"); err != nil {
		t.Fatal(err)
	}

	fromA := listenOn(t, netB, "10.99.0.2")
	send(t, netA, "10.99.0.2:9000", "hello through wireguard")
	if got := recv(t, fromA); got != "hello through wireguard" {
		t.Errorf("got %q, want the greeting", got)
	}
}

// TestTunnelCryptokeyRouting is the demux proof: ONE interface (A) with TWO
// peers (B, C). A sends to two destinations, and cryptokey routing must steer
// each to the peer whose AllowedIPs contains it — the exact mechanism that
// lets one utun reach every mpd VM.
func TestTunnelCryptokeyRouting(t *testing.T) {
	keyA, keyB, keyC := mustKey(t), mustKey(t), mustKey(t)
	const portA, portB, portC = 58131, 58132, 58133

	tA, netA := newNetTunnel(t, "10.99.0.1", portA, keyA)
	tB, netB := newNetTunnel(t, "10.99.0.2", portB, keyB)
	tC, netC := newNetTunnel(t, "10.99.0.3", portC, keyC)

	// A's single interface, two peers, split purely by AllowedIPs:
	if err := tA.AddPeer(keyB.PublicKey(), loopback(portB), "10.99.0.2/32"); err != nil {
		t.Fatal(err)
	}
	if err := tA.AddPeer(keyC.PublicKey(), loopback(portC), "10.99.0.3/32"); err != nil {
		t.Fatal(err)
	}
	if err := tB.AddPeer(keyA.PublicKey(), loopback(portA), "10.99.0.1/32"); err != nil {
		t.Fatal(err)
	}
	if err := tC.AddPeer(keyA.PublicKey(), loopback(portA), "10.99.0.1/32"); err != nil {
		t.Fatal(err)
	}

	fromB := listenOn(t, netB, "10.99.0.2")
	fromC := listenOn(t, netC, "10.99.0.3")

	send(t, netA, "10.99.0.2:9000", "for-B")
	send(t, netA, "10.99.0.3:9000", "for-C")

	if got := recv(t, fromB); got != "for-B" {
		t.Errorf("peer B received %q, want for-B — routing sent it wrong", got)
	}
	if got := recv(t, fromC); got != "for-C" {
		t.Errorf("peer C received %q, want for-C — routing sent it wrong", got)
	}
}
