package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Request is one command on the control socket. mpd-virt (unprivileged) sends
// these; mpd-proxy applies them to the tunnel + DNS forwarder. It reads no
// files — everything it needs is in the message.
type Request struct {
	Op         string   `json:"op"`                    // "pubkey" | "add" | "remove" | "list"
	ID         string   `json:"id,omitempty"`          // add/remove key
	PublicKey  string   `json:"public_key,omitempty"`  // add: the VM's WG key (base64)
	Endpoint   string   `json:"endpoint,omitempty"`    // add: VM WG endpoint host:port
	AllowedIPs []string `json:"allowed_ips,omitempty"` // add: e.g. ["10.163.181.0/24"]
	Resolver   string   `json:"resolver,omitempty"`    // add: e.g. "10.163.181.1:53"
}

// Response is the reply to one Request.
type Response struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Pubkey string `json:"pubkey,omitempty"` // "pubkey": mpd-proxy's own key (base64)
	VMs    []VM   `json:"vms,omitempty"`    // "list"
}

// VM is one adopted box as the proxy tracks it — enough to answer "list" and
// to remove the peer later.
type VM struct {
	ID         string   `json:"id"`
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
	Resolver   string   `json:"resolver"`
}

// Controller wires the control socket to the tunnel and the DNS forwarder. It
// is the whole "API" of mpd-proxy.
type Controller struct {
	priv     wgtypes.Key
	tun      *Tunnel
	fwd      *Forwarder
	allowUID int // only this uid (or root) may drive the socket

	mu  sync.Mutex
	vms map[string]VM
}

// NewController builds a Controller. priv is mpd-proxy's own WireGuard key;
// allowUID is the user permitted to push peers (typically the SUDO_UID).
func NewController(priv wgtypes.Key, tun *Tunnel, fwd *Forwarder, allowUID int) *Controller {
	return &Controller{priv: priv, tun: tun, fwd: fwd, allowUID: allowUID, vms: map[string]VM{}}
}

// Serve accepts connections on ln until it is closed, handling each in its own
// goroutine. Every connection is gated on the kernel-reported peer uid.
func (c *Controller) Serve(ln *net.UnixListener) error {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go c.handleConn(conn)
	}
}

func (c *Controller) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	enc := json.NewEncoder(conn)

	uid, err := peerUID(conn)
	if err != nil {
		_ = enc.Encode(Response{Error: "cannot read peer credentials"})
		return
	}
	if uid != c.allowUID && uid != 0 {
		log.Printf("ctl: rejected uid %d (only %d may connect)", uid, c.allowUID)
		_ = enc.Encode(Response{Error: fmt.Sprintf("uid %d is not authorized", uid)})
		return
	}
	log.Printf("ctl: connection from uid %d", uid)

	// One connection may carry a stream of requests; reply to each in turn.
	dec := json.NewDecoder(conn)
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			return // EOF or a malformed frame ends the session
		}
		resp := c.handle(req)
		log.Printf("ctl: %s → ok=%v err=%q", reqLabel(req), resp.OK, resp.Error)
		_ = enc.Encode(resp)
	}
}

// reqLabel is a short, log-friendly rendering of a request.
func reqLabel(r Request) string {
	s := r.Op
	if r.ID != "" {
		s += " id=" + r.ID
	}
	if r.Endpoint != "" {
		s += " endpoint=" + r.Endpoint
	}
	return s
}

func (c *Controller) handle(req Request) Response {
	switch req.Op {
	case "pubkey":
		return Response{OK: true, Pubkey: c.priv.PublicKey().String()}
	case "add":
		return c.add(req)
	case "remove":
		return c.remove(req.ID)
	case "list":
		return c.list()
	default:
		return Response{Error: "unknown op: " + req.Op}
	}
}

func (c *Controller) add(req Request) Response {
	key, err := wgtypes.ParseKey(req.PublicKey)
	if err != nil {
		return Response{Error: "bad public_key: " + err.Error()}
	}
	if err := c.tun.AddPeer(key, req.Endpoint, req.AllowedIPs...); err != nil {
		return Response{Error: "add peer: " + err.Error()}
	}
	if req.Resolver != "" {
		c.fwd.SetRoute(req.ID, req.Resolver)
	}
	c.mu.Lock()
	c.vms[req.ID] = VM{
		ID: req.ID, PublicKey: req.PublicKey, Endpoint: req.Endpoint,
		AllowedIPs: req.AllowedIPs, Resolver: req.Resolver,
	}
	c.mu.Unlock()
	return Response{OK: true}
}

func (c *Controller) remove(id string) Response {
	c.mu.Lock()
	vm, ok := c.vms[id]
	delete(c.vms, id)
	c.mu.Unlock()
	if !ok {
		return Response{OK: true} // already gone — removal is idempotent
	}
	if key, err := wgtypes.ParseKey(vm.PublicKey); err == nil {
		_ = c.tun.RemovePeer(key)
	}
	c.fwd.ClearRoute(id)
	return Response{OK: true}
}

func (c *Controller) list() Response {
	c.mu.Lock()
	defer c.mu.Unlock()
	vms := make([]VM, 0, len(c.vms))
	for _, v := range c.vms {
		vms = append(vms, v)
	}
	return Response{OK: true, VMs: vms}
}
