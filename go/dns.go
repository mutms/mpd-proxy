package main

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// mpdDomain is the suffix every name we split on ends with. A single
// /etc/resolver/mpd.test on the Mac points all of it at this forwarder.
const mpdDomain = "mpd.test"

// Forwarder is a split-horizon DNS forwarder: a query for <NNN>.mpd.test is
// sent to that VM's own resolver (10.163.<NNN>.1) through the tunnel, and
// everything else goes to the host's normal upstream. It answers nothing
// itself — it only routes the question onward — so a VM's dynamic records
// (containers, runtimes) keep resolving without this process knowing them.
type Forwarder struct {
	// mu guards routes. miekg/dns runs ServeDNS in a fresh goroutine per
	// query while the control socket mutates routes concurrently, so every
	// access is under the lock. An RWMutex lets many lookups read in parallel
	// and only serializes the rare write.
	mu     sync.RWMutex
	routes map[string]string // "<NNN>" -> resolver address, e.g. "10.163.150.1:53"

	// upstream is where names outside mpd.test go — the host's normal resolver.
	upstream string

	client dns.Client
}

// NewForwarder builds a Forwarder that sends everything outside mpd.test to
// upstream (host:port, e.g. "1.1.1.1:53").
func NewForwarder(upstream string) *Forwarder {
	return &Forwarder{
		routes:   make(map[string]string),
		upstream: upstream,
	}
}

// SetRoute points <NNN>.mpd.test at resolver (host:port). The control socket
// calls this when mpd-virt adopts or starts a VM.
func (f *Forwarder) SetRoute(nnn, resolver string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[nnn] = resolver
}

// ClearRoute drops a VM's route (on removal).
func (f *Forwarder) ClearRoute(nnn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.routes, nnn)
}

// resolverFor picks the upstream for a query name: a VM's own resolver when
// the name is inside its zone and a route exists, otherwise the default.
func (f *Forwarder) resolverFor(qname string) string {
	nnn, ok := zoneID(qname)
	if !ok {
		return f.upstream
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if r, ok := f.routes[nnn]; ok {
		return r
	}
	// Inside mpd.test but no route yet (VM down or not adopted): fall through
	// to upstream, which simply won't find it — better than hanging.
	return f.upstream
}

// ServeDNS makes *Forwarder a dns.Handler: miekg/dns calls it for every query.
// We forward the message unchanged and copy the reply straight back.
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	upstream := f.upstream
	if len(req.Question) > 0 {
		upstream = f.resolverFor(req.Question[0].Name)
	}

	resp, _, err := f.client.Exchange(req, upstream)
	if err != nil || resp == nil {
		// Report the failure rather than dropping the query on the floor.
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		return
	}
	_ = w.WriteMsg(resp)
}

// zoneID extracts the <NNN> label from a name inside mpd.test — always the
// label immediately before "mpd.test":
//
//	150.mpd.test.                 -> "150"
//	moodle.150.mpd.test.          -> "150"
//	adminer.service.181.mpd.test. -> "181"
func zoneID(qname string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	rest, ok := strings.CutSuffix(name, "."+mpdDomain)
	if !ok || rest == "" {
		return "", false
	}
	if i := strings.LastIndexByte(rest, '.'); i >= 0 {
		rest = rest[i+1:] // keep only the last label
	}
	return rest, rest != ""
}
