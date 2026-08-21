package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Inbound guard: the tunnel must never make the Mac attackable from a VM.
//
// The overlay's whole point is Mac → VM: project URLs, databases, DNS. But
// WireGuard itself has no notion of direction — once a VM is a peer, it can
// send any packet whose source fits its AllowedIPs, and the kernel would
// happily deliver a VM-initiated connection to any Mac service listening on
// 0.0.0.0 (dev servers, debug ports — exactly what a compromised box would
// scan for). mpd's threat model calls every VM compromised, so inbound is
// filtered down to replies:
//
//   - TCP: a segment with SYN and no ACK — the only packet that can open a
//     connection — is dropped. Everything else passes, so Mac-initiated
//     flows (including long-lived ones) are never stalled and no per-flow
//     TCP state is needed. Blind injection into an existing flow still
//     requires the 4-tuple and a live sequence window, and cryptokey
//     routing already stops one VM spoofing another's addresses.
//   - UDP: allowed only as the reverse of a flow the Mac sent first,
//     tracked from the outbound side (DNS lookups, QUIC — anything the Mac
//     keeps using keeps refreshing). Entries expire after udpTTL.
//   - ICMP: echo replies, destination-unreachable and time-exceeded pass
//     (replies and errors for our own traffic); echo requests and the rest
//     are dropped.
//   - Fragments past the first are dropped, and a first fragment too short
//     to carry its transport header is dropped with them — nothing gets to
//     hide a SYN behind a fragment boundary. (DNS answers big enough to
//     fragment fall back to TCP on the truncated retry.)
//   - Anything that is not IPv4 is dropped; the overlay is v4-only.
//
// The guard wraps the utun *inside* the WireGuard device, in this process —
// no pf anchor, no kernel extension, nothing to install or clean up, and it
// filters decrypted cleartext exactly at the trust boundary.
type inboundGuard struct {
	tun.Device // delegates File/MTU/Name/Events/BatchSize/Close

	mu        sync.Mutex
	udp       map[flowKey]time.Time // outbound UDP flows, keyed Mac-side
	lastSweep time.Time

	drops   uint64
	lastLog time.Time
}

// flowKey identifies one outbound UDP flow, Mac side first.
type flowKey struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
}

const (
	// udpTTL is how long a UDP reply path stays open after the last
	// outbound packet. Every outbound packet refreshes it, so anything the
	// Mac is actively using never expires mid-conversation.
	udpTTL = 2 * time.Minute
	// sweepEvery bounds how often the expired entries are collected.
	sweepEvery = time.Minute
)

// guardInbound wraps a tun device with the inbound filter.
func guardInbound(d tun.Device) tun.Device {
	return &inboundGuard{Device: d, udp: map[flowKey]time.Time{}}
}

// Read is the outbound path (Mac → device → VM). Packets pass untouched;
// UDP flows are noted so their replies may come back.
func (g *inboundGuard) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := g.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		g.noteOutbound(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

// Write is the inbound path (VM → device → Mac). Disallowed packets are
// dropped silently at this layer (and counted); the caller sees a full
// write either way — a drop is the contract, not an error.
func (g *inboundGuard) Write(bufs [][]byte, offset int) (int, error) {
	kept := bufs[:0]
	for _, buf := range bufs {
		if g.allowInbound(buf[offset:]) {
			kept = append(kept, buf)
		} else {
			g.countDrop(buf[offset:])
		}
	}
	if len(kept) == 0 {
		return len(bufs), nil
	}
	if _, err := g.Device.Write(kept, offset); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

// noteOutbound records the flow of one outbound UDP packet.
func (g *inboundGuard) noteOutbound(pkt []byte) {
	ihl, ok := ipv4Header(pkt)
	if !ok || pkt[9] != 17 /* UDP */ {
		return
	}
	if fragOffset(pkt) != 0 || len(pkt) < ihl+8 {
		return
	}
	var k flowKey
	copy(k.srcIP[:], pkt[12:16])
	copy(k.dstIP[:], pkt[16:20])
	k.srcPort = binary.BigEndian.Uint16(pkt[ihl:])
	k.dstPort = binary.BigEndian.Uint16(pkt[ihl+2:])

	now := time.Now()
	g.mu.Lock()
	g.udp[k] = now
	if now.Sub(g.lastSweep) > sweepEvery {
		g.lastSweep = now
		for key, seen := range g.udp {
			if now.Sub(seen) > udpTTL {
				delete(g.udp, key)
			}
		}
	}
	g.mu.Unlock()
}

// allowInbound is the whole inbound policy, one packet at a time.
func (g *inboundGuard) allowInbound(pkt []byte) bool {
	ihl, ok := ipv4Header(pkt)
	if !ok {
		return false
	}
	if fragOffset(pkt) != 0 {
		return false // never a fragment past the first
	}
	switch pkt[9] {
	case 6: // TCP — drop connection-opening SYNs, pass the rest
		if len(pkt) < ihl+20 {
			return false // no room for a real TCP header: header-split evasion
		}
		flags := pkt[ihl+13]
		return flags&0x02 == 0 || flags&0x10 != 0 // !SYN, or SYN+ACK (our own connect)
	case 17: // UDP — replies to tracked outbound flows only
		if len(pkt) < ihl+8 {
			return false
		}
		var k flowKey
		copy(k.srcIP[:], pkt[16:20]) // reverse: our src is their dst
		copy(k.dstIP[:], pkt[12:16])
		k.srcPort = binary.BigEndian.Uint16(pkt[ihl+2:])
		k.dstPort = binary.BigEndian.Uint16(pkt[ihl:])
		g.mu.Lock()
		seen, ok := g.udp[k]
		g.mu.Unlock()
		return ok && time.Since(seen) <= udpTTL
	case 1: // ICMP — replies and errors, never probes
		if len(pkt) < ihl+1 {
			return false
		}
		switch pkt[ihl] {
		case 0, 3, 11: // echo reply, unreachable, time exceeded
			return true
		}
		return false
	}
	return false
}

// ipv4Header validates the fixed shape every rule depends on and returns
// the header length.
func ipv4Header(pkt []byte) (ihl int, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl = int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0, false
	}
	return ihl, true
}

// fragOffset is the packet's fragment offset in 8-byte units; nonzero means
// a continuation fragment with no transport header of its own.
func fragOffset(pkt []byte) uint16 {
	return binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff
}

// countDrop tallies and logs drops, rate-limited to one line a second so a
// scanning VM cannot flood the log.
func (g *inboundGuard) countDrop(pkt []byte) {
	g.mu.Lock()
	g.drops++
	drops, last := g.drops, g.lastLog
	now := time.Now()
	if now.Sub(last) >= time.Second {
		g.lastLog = now
	}
	g.mu.Unlock()
	if now.Sub(last) >= time.Second {
		log.Printf("guard: dropped VM-initiated inbound packet — %s (%d dropped total)", describeDrop(pkt), drops)
	}
}

// describeDrop summarizes a dropped packet enough to name the flow the guard is
// refusing — proto, addresses and ports, and for TCP the flags — so an
// over-eager rule shows up in the log by name rather than as a bare "proto N".
// A DNS reply wrongly dropped reads as `udp 10.163.<NNN>.1:53 → 10.163.0.1:<p>`;
// a dropped continuation fragment says so. Best-effort on a malformed packet.
func describeDrop(pkt []byte) string {
	ihl, ok := ipv4Header(pkt)
	if !ok {
		return "non-IPv4"
	}
	src, dst := net.IP(pkt[12:16]), net.IP(pkt[16:20])
	if fragOffset(pkt) != 0 {
		return fmt.Sprintf("proto %d %s → %s (ipv4 fragment)", pkt[9], src, dst)
	}
	switch pkt[9] {
	case 6: // TCP
		if len(pkt) >= ihl+14 {
			return fmt.Sprintf("tcp %s:%d → %s:%d flags=%s", src, binary.BigEndian.Uint16(pkt[ihl:]),
				dst, binary.BigEndian.Uint16(pkt[ihl+2:]), tcpFlags(pkt[ihl+13]))
		}
	case 17: // UDP
		if len(pkt) >= ihl+8 {
			return fmt.Sprintf("udp %s:%d → %s:%d", src, binary.BigEndian.Uint16(pkt[ihl:]),
				dst, binary.BigEndian.Uint16(pkt[ihl+2:]))
		}
	case 1: // ICMP
		if len(pkt) >= ihl+1 {
			return fmt.Sprintf("icmp type %d %s → %s", pkt[ihl], src, dst)
		}
	}
	return fmt.Sprintf("proto %d %s → %s", pkt[9], src, dst)
}

// tcpFlags renders the TCP flag bits that matter to the guard's decision, so a
// dropped segment shows whether it was a bare SYN (a VM opening a connection —
// what the guard is meant to drop) or something the rule caught by mistake.
func tcpFlags(b byte) string {
	var set []string
	for _, f := range []struct {
		bit  byte
		name string
	}{{0x02, "SYN"}, {0x10, "ACK"}, {0x01, "FIN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x20, "URG"}} {
		if b&f.bit != 0 {
			set = append(set, f.name)
		}
	}
	if len(set) == 0 {
		return "none"
	}
	return strings.Join(set, ",")
}
