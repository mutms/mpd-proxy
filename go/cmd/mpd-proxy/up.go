package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	mpdSubnet  = "10.163.0.0/16"
	clientAddr = "10.163.0.1" // the Mac's own address in the mpd overlay (10.163.0.x is unused by VMs)
	dnsListen  = "127.0.0.1:5354"
)

// runUp brings the whole proxy up in the foreground: create the utun, the
// route, and the resolver hook (the root bits), drop root, then start the
// DNS forwarder + the control socket as the invoking user and block until
// Ctrl-C. Every control command is logged — the ops are rare, so there's no
// reason to be quiet.
func runUp(socketPath string) error {
	// Privsep is not optional: refuse to start when there is no user to drop
	// to. Under sudo the invoking user arrives in SUDO_UID; bare root has
	// none and is refused — mpd-proxy is always started by hand via sudo.
	uid, gid := invokingUID(), invokingGID()
	if os.Geteuid() == 0 && uid == 0 {
		return fmt.Errorf("no user to drop privileges to — run via sudo, not as bare root")
	}

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}

	// --- Privileged setup: the utun and the route are the only root bits. ---
	dev, err := tun.CreateTUN("utun", 1420)
	if err != nil {
		return fmt.Errorf("create utun (run under sudo?): %w", err)
	}
	utunName, _ := dev.Name()
	tn, err := NewTunnel(dev, priv, 0)
	if err != nil {
		return err
	}
	defer tn.Close() // closing the utun also drops its address + route
	log.Printf("utun %s up", utunName)

	// A point-to-point utun needs an address before the kernel will route a
	// subnet into it.
	if err := assignAddr(utunName, clientAddr); err != nil {
		return err
	}
	log.Printf("address %s on %s", clientAddr, utunName)

	if err := addRoute(mpdSubnet, utunName); err != nil {
		return err
	}
	log.Printf("route %s → %s", mpdSubnet, utunName)

	if err := ensureResolverFile(); err != nil {
		return err
	}

	// --- Drop root: everything that needs privilege is done. From here on
	// the process runs as the invoking user — the DNS forwarder and control
	// socket below are created unprivileged, so the socket is born user-owned
	// and nothing is ever served as root. A failed drop is fatal: serving as
	// root is not a mode we run in.
	if err := dropPrivileges(uid, gid); err != nil {
		return fmt.Errorf("dropping privileges: %w", err)
	}
	log.Printf("dropped root → uid %d", uid)

	// --- DNS forwarder on a high port. ---
	fwd := NewForwarder()
	dnsSrv := &dns.Server{Addr: dnsListen, Net: "udp", Handler: fwd}
	go func() {
		if err := dnsSrv.ListenAndServe(); err != nil {
			log.Fatalf("dns %s: %v", dnsListen, err)
		}
	}()
	defer dnsSrv.Shutdown()
	log.Printf("DNS forwarder on %s (routed mpd.test zones only — no upstream)", dnsListen)

	// --- Control socket in the user's own ~/.mpd-virt/proxy/. ---
	if socketPath == "" {
		socketPath, err = defaultSocketPath(uid)
		if err != nil {
			return err
		}
	}
	_ = os.Remove(socketPath)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(socketPath)
	_ = os.Chmod(socketPath, 0o600) // sockets inherit the umask; tighten to owner-only

	ctrl := NewController(priv, tn, fwd, uid)
	go ctrl.Serve(ln)
	log.Printf("control socket %s (uid %d may connect)", socketPath, uid)

	log.Printf("mpd-proxy up on %s — logging all control commands. Ctrl-C to stop.", utunName)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	return nil
}

// assignAddr gives the utun the Mac's overlay address (local == peer for a
// host-style point-to-point link), which is what makes a subnet route into
// the interface actually take.
func assignAddr(iface, addr string) error {
	out, err := exec.Command("ifconfig", iface, "inet", addr, addr, "alias").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s %s: %v: %s", iface, addr, err, strings.TrimSpace(string(out)))
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

// ensureResolverFile installs the /etc/resolver hook that points *.mpd.test
// at the forwarder. Part of the privileged setup: written only when missing
// or different, so ordinary restarts never touch it; `uninstall` removes it.
func ensureResolverFile() error {
	host, port, err := net.SplitHostPort(dnsListen)
	if err != nil {
		return err
	}
	content := fmt.Sprintf("nameserver %s\nport %s\n", host, port)
	if cur, err := os.ReadFile(resolverPath); err == nil && string(cur) == content {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(resolverPath), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(resolverPath), err)
	}
	if err := os.WriteFile(resolverPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s (run under sudo?): %w", resolverPath, err)
	}
	// Flush so macOS starts consulting the new hook right away.
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
	log.Printf("installed %s (nameserver %s port %s)", resolverPath, host, port)
	return nil
}

// defaultSocketPath is ~/.mpd-virt/proxy/socket for the invoking user —
// inside mpd-virt's own state directory, since mpd-virt is the only client.
// Runs after the privilege drop, so plain Mkdir yields user-owned dirs with
// no chown dance. The proxy/ dir is 0700: no other user can even reach the
// socket, a filesystem wall in front of the per-connection peer-uid gate
// (and unlike /tmp, nobody else can play games with the path, and macOS's
// periodic /tmp cleanup can't reap a long-lived socket). The home comes
// from the user database, not $HOME — sudo may leave $HOME at root's.
func defaultSocketPath(uid int) (string, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || u.HomeDir == "" {
		return "", fmt.Errorf("resolving home of uid %d for the control socket (or pass --socket): %v", uid, err)
	}
	root := filepath.Join(u.HomeDir, ".mpd-virt")
	if err := os.Mkdir(root, 0o755); err != nil && !os.IsExist(err) {
		return "", err
	}
	dir := filepath.Join(root, "proxy")
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return "", err
	}
	// Re-assert the mode on every start — this dir is ours.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("chmod %s: %w", dir, err)
	}
	return filepath.Join(dir, "socket"), nil
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
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}
