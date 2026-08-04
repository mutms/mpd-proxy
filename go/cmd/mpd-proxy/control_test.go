package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestControlSocket drives the whole control API over a real unix socket with
// a live tunnel + forwarder: fetch the proxy's key, add a VM, see the DNS
// route and the peer land, list it, remove it, and confirm it's gone. No sudo
// (netstack tunnel), and peer-creds pass because client and server share this
// test's uid.
func TestControlSocket(t *testing.T) {
	tun, _ := newNetTunnel(t, "10.99.1.1", 59000, mustKey(t))
	fwd := NewForwarder()
	ctrl := NewController(mustKey(t), tun, fwd, os.Getuid())

	sock := filepath.Join(t.TempDir(), "mpd-proxy.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ctrl.Serve(ln)

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	enc, dec := json.NewEncoder(conn), json.NewDecoder(conn)
	call := func(req Request) Response {
		t.Helper()
		if err := enc.Encode(req); err != nil {
			t.Fatal(err)
		}
		var resp Response
		if err := dec.Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// mpd-proxy hands out its own public key (what mpd-virt authorizes on VMs).
	if r := call(Request{Op: "pubkey"}); !r.OK || r.Pubkey == "" {
		t.Fatalf("pubkey: %+v", r)
	}

	// Add a VM: peer + DNS route in one command.
	vmKey := mustKey(t).PublicKey().String()
	if r := call(Request{
		Op: "add", ID: "181", PublicKey: vmKey,
		Endpoint: "127.0.0.1:51820", AllowedIPs: []string{"10.163.181.1/32"},
		Resolver: "10.163.181.1:53",
	}); !r.OK {
		t.Fatalf("add: %+v", r)
	}

	// The DNS route took effect in the forwarder.
	if got, ok := fwd.resolverFor("moodle.181.mpd.test."); !ok || got != "10.163.181.1:53" {
		t.Errorf("forwarder route = %q, %v, want 10.163.181.1:53", got, ok)
	}

	// list shows exactly the one VM.
	if r := call(Request{Op: "list"}); !r.OK || len(r.VMs) != 1 || r.VMs[0].ID != "181" {
		t.Fatalf("list: %+v", r)
	}

	// remove drops both the peer and the route.
	if r := call(Request{Op: "remove", ID: "181"}); !r.OK {
		t.Fatalf("remove: %+v", r)
	}
	if r := call(Request{Op: "list"}); len(r.VMs) != 0 {
		t.Errorf("after remove, list = %+v", r.VMs)
	}
	if got, ok := fwd.resolverFor("181.mpd.test."); ok {
		t.Errorf("route not cleared: still resolves to %q", got)
	}
}
