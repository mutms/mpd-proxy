package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// mkIPv4 builds a minimal IPv4 packet: 20-byte header + payload, no
// options. fragOff is in 8-byte units.
func mkIPv4(proto byte, src, dst [4]byte, fragOff uint16, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[6:], fragOff&0x1fff)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], payload)
	return pkt
}

func mkTCP(src, dst [4]byte, sport, dport uint16, flags byte) []byte {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p[0:], sport)
	binary.BigEndian.PutUint16(p[2:], dport)
	p[12] = 5 << 4 // data offset
	p[13] = flags
	return mkIPv4(6, src, dst, 0, p)
}

func mkUDP(src, dst [4]byte, sport, dport uint16) []byte {
	p := make([]byte, 8)
	binary.BigEndian.PutUint16(p[0:], sport)
	binary.BigEndian.PutUint16(p[2:], dport)
	binary.BigEndian.PutUint16(p[4:], 8)
	return mkIPv4(17, src, dst, 0, p)
}

func mkICMP(src, dst [4]byte, typ byte) []byte {
	return mkIPv4(1, src, dst, 0, []byte{typ, 0, 0, 0, 0, 0, 0, 0})
}

var (
	mac = [4]byte{10, 163, 0, 1}
	vm  = [4]byte{10, 163, 141, 23}
)

// The inbound policy, packet by packet: only replies to Mac-initiated
// traffic may enter; everything a scanning VM would send is dropped.
func TestAllowInbound(t *testing.T) {
	const (
		synFlag = 0x02
		ackFlag = 0x10
		finFlag = 0x01
		rstFlag = 0x04
	)
	g := guardInbound(nil).(*inboundGuard)

	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"TCP SYN (VM opens a connection)", mkTCP(vm, mac, 40000, 5173, synFlag), false},
		{"TCP SYN+ACK (reply to our connect)", mkTCP(vm, mac, 443, 50000, synFlag|ackFlag), true},
		{"TCP ACK (established flow)", mkTCP(vm, mac, 443, 50000, ackFlag), true},
		{"TCP FIN+ACK", mkTCP(vm, mac, 443, 50000, finFlag|ackFlag), true},
		{"TCP RST", mkTCP(vm, mac, 443, 50000, rstFlag), true},
		{"UDP without an outbound flow", mkUDP(vm, mac, 53, 40000), false},
		{"ICMP echo request (VM pings the Mac)", mkICMP(vm, mac, 8), false},
		{"ICMP echo reply", mkICMP(vm, mac, 0), true},
		{"ICMP unreachable", mkICMP(vm, mac, 3), true},
		{"ICMP time exceeded", mkICMP(vm, mac, 11), true},
		{"not IPv4", append([]byte{0x60}, make([]byte, 39)...), false},
		{"truncated header", []byte{0x45, 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.allowInbound(tc.pkt); got != tc.want {
				t.Errorf("allowInbound = %v, want %v", got, tc.want)
			}
		})
	}
}

// A UDP reply is admitted exactly when the Mac sent the matching query
// first — and only until the flow expires.
func TestUDPReplyTracking(t *testing.T) {
	g := guardInbound(nil).(*inboundGuard)

	query := mkUDP(mac, vm, 40000, 53)
	reply := mkUDP(vm, mac, 53, 40000)
	wrongPort := mkUDP(vm, mac, 53, 40001)
	wrongHost := mkUDP([4]byte{10, 163, 142, 23}, mac, 53, 40000)

	if g.allowInbound(reply) {
		t.Fatal("reply admitted before any query was sent")
	}
	g.noteOutbound(query)
	if !g.allowInbound(reply) {
		t.Error("reply to a tracked flow refused")
	}
	if g.allowInbound(wrongPort) {
		t.Error("reply to a different local port admitted")
	}
	if g.allowInbound(wrongHost) {
		t.Error("reply from a different host admitted")
	}

	// Expiry: age the entry past the TTL and the door closes again.
	for k := range g.udp {
		g.udp[k] = time.Now().Add(-udpTTL - time.Second)
	}
	if g.allowInbound(reply) {
		t.Error("reply admitted after the flow expired")
	}
}

// Fragment games must not smuggle a transport header past the rules.
func TestFragmentsDropped(t *testing.T) {
	g := guardInbound(nil).(*inboundGuard)

	continuation := mkIPv4(6, vm, mac, 185, make([]byte, 32))
	if g.allowInbound(continuation) {
		t.Error("continuation fragment admitted")
	}
	// First fragment too short for a full TCP header (tiny-fragment attack).
	tiny := mkIPv4(6, vm, mac, 0, make([]byte, 8))
	if g.allowInbound(tiny) {
		t.Error("tiny first fragment admitted")
	}
}

// End-to-end through two real WireGuard devices: the guarded "Mac" side
// reaches the "VM" freely, while the VM's attempt to open a TCP connection
// to a Mac listener dies at the guard — the packet decrypts fine and is
// then dropped, so the dial times out instead of connecting.
func TestGuardEndToEnd(t *testing.T) {
	keyMac, keyVM := mustKey(t), mustKey(t)
	const portMac, portVM = 58141, 58142

	devMac, netMac, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.163.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	tnMac, err := NewTunnel(guardInbound(devMac), keyMac, portMac)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tnMac.Close() })

	tnVM, netVM := newNetTunnel(t, "10.163.141.2", portVM, keyVM)

	if err := tnMac.AddPeer(keyVM.PublicKey(), loopback(portVM), "10.163.141.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := tnVM.AddPeer(keyMac.PublicKey(), loopback(portMac), "10.163.0.1/32"); err != nil {
		t.Fatal(err)
	}

	// Mac → VM: the overlay's purpose, and it must keep working through
	// the guard (this also proves the handshake passes it).
	fromMac := listenOn(t, netVM, "10.163.141.2")
	send(t, netMac, "10.163.141.2:9000", "mac reaches the vm")
	if got := recv(t, fromMac); got != "mac reaches the vm" {
		t.Errorf("got %q, want the greeting", got)
	}

	// VM → Mac: a listener is up on the Mac side, but the VM's SYN must
	// die at the guard and the dial must not complete.
	lnMac, err := netMac.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.163.0.1"), Port: 9000})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lnMac.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := netVM.DialContext(ctx, "tcp", "10.163.0.1:9000"); err == nil {
		c.Close()
		t.Fatal("VM-initiated connection to the Mac succeeded — the guard is not filtering")
	}
}
