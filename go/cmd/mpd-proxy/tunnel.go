package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Tunnel is one WireGuard interface with many peers. Cryptokey routing sends
// each outbound packet to the peer whose AllowedIPs contains the destination,
// so a single Tunnel reaches every mpd VM: one peer per box, its AllowedIPs
// the box's 10.163.<NNN>.0/24.
//
// It wraps wireguard-go's device.Device — that does the crypto and the
// routing; we only feed it config in WireGuard's "UAPI" text format.
type Tunnel struct {
	dev *device.Device
}

// NewTunnel brings up a WireGuard device on t (a real utun in production, or a
// userspace netstack tun in tests), keyed by private, listening on listenPort.
func NewTunnel(t tun.Device, private wgtypes.Key, listenPort int) (*Tunnel, error) {
	dev := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "wg "))

	cfg := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", hexKey(private), listenPort)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configuring device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bringing device up: %w", err)
	}
	return &Tunnel{dev: dev}, nil
}

// AddPeer adds or updates one peer: its public key, where to reach it
// (endpoint host:port, empty to leave unset), and which destinations belong to
// it — the AllowedIPs that drive cryptokey routing.
func (tn *Tunnel) AddPeer(public wgtypes.Key, endpoint string, allowedIPs ...string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hexKey(public))
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	for _, ip := range allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
	}
	return tn.dev.IpcSet(b.String())
}

// RemovePeer drops a peer by its public key (the "remove=true" UAPI verb).
func (tn *Tunnel) RemovePeer(public wgtypes.Key) error {
	return tn.dev.IpcSet(fmt.Sprintf("public_key=%s\nremove=true\n", hexKey(public)))
}

// Close tears the device (and its utun) down.
func (tn *Tunnel) Close() { tn.dev.Close() }

// hexKey renders a WireGuard key as the hex string the UAPI expects — wgtypes'
// own String() is base64, which IpcSet does not accept.
func hexKey(k wgtypes.Key) string { return hex.EncodeToString(k[:]) }
