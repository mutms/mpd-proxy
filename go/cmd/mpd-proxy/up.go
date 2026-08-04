package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultSocket = "/tmp/mpd-proxy.sock"
	mpdSubnet     = "10.163.0.0/16"
	clientAddr    = "10.163.0.1" // the Mac's own address in the mpd overlay (10.163.0.x is unused by VMs)
	dnsListen     = "127.0.0.1:5354"
)

// runUp brings the whole proxy up in the foreground: create the utun and the
// route (needs root), start WireGuard + the DNS forwarder + the control
// socket, then drop root and block until Ctrl-C. Every control command is
// logged — the ops are rare, so there's no reason to be quiet.
func runUp(socketPath string) error {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	// --- Privileged setup: the utun and the route are the only root bits. ---
	dev, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return fmt.Errorf("create utun (run under sudo?): %w", err)
	}
	name, _ := dev.Name()
	tn, err := NewTunnel(dev, priv, 0)
	if err != nil {
		return err
	}
	defer tn.Close() // closing the utun also drops its address + route
	log.Printf("utun %s up", name)

	// A point-to-point utun needs an address before the kernel will route a
	// subnet into it.
	if err := assignAddr(name, clientAddr); err != nil {
		return err
	}
	log.Printf("address %s on %s", clientAddr, name)

	if err := addRoute(mpdSubnet, name); err != nil {
		return err
	}
	log.Printf("route %s → %s", mpdSubnet, name)

	// --- DNS forwarder on a high port (no privilege). ---
	fwd := NewForwarder()
	dnsSrv := &dns.Server{Addr: dnsListen, Net: "udp", Handler: fwd}
	go func() {
		if err := dnsSrv.ListenAndServe(); err != nil {
			log.Fatalf("dns %s: %v", dnsListen, err)
		}
	}()
	defer dnsSrv.Shutdown()
	log.Printf("DNS forwarder on %s (routed mpd.test zones only — no upstream)", dnsListen)

	// --- Control socket, reachable by the invoking user after we drop root. ---
	uid, gid := invokingUID(), invokingGID()
	_ = os.Remove(socketPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socketPath)
	_ = os.Chown(socketPath, uid, gid)
	_ = os.Chmod(socketPath, 0o660)

	ctrl := NewController(priv, tn, fwd, uid)
	go ctrl.Serve(ln)
	log.Printf("control socket %s (uid %d may connect)", socketPath, uid)

	// --- Drop root: everything privileged is already done. ---
	if err := dropPrivileges(uid, gid); err != nil {
		log.Printf("warning: staying root, could not drop privileges: %v", err)
	} else {
		log.Printf("dropped root → uid %d", uid)
	}

	log.Printf("mpd-proxy up on %s — logging all control commands. Ctrl-C to stop.", name)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	return nil
}

// assignAddr gives the utun the Mac's overlay address (local == peer for a
// host-style point-to-point link), which is what makes a subnet route into
// the interface actually take.
func assignAddr(name, addr string) error {
	out, err := exec.Command("ifconfig", name, "inet", addr, addr, "alias").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s %s: %v: %s", name, addr, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// addRoute sends a destination subnet into the utun with one route command —
// the whole 10.163.0.0/16, so every VM's /24 is covered without per-VM routes.
func addRoute(cidr, iface string) error {
	out, err := exec.Command("/sbin/route", "-n", "add", "-net", cidr, "-interface", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add %s → %s: %v: %s", cidr, iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// invokingUID/GID recover the real user behind sudo, for the privsep drop.
func invokingUID() int { return sudoInt("SUDO_UID", os.Getuid()) }
func invokingGID() int { return sudoInt("SUDO_GID", os.Getgid()) }

func sudoInt(env string, fallback int) int {
	if s := os.Getenv(env); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return fallback
}

// dropPrivileges lowers the process to uid/gid once the root-only setup is
// done — the OpenSSH-style "root for a few syscalls, then run as you".
func dropPrivileges(uid, gid int) error {
	if os.Geteuid() != 0 {
		return nil // not root; nothing to drop
	}
	_ = syscall.Setgroups([]int{gid})
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}
