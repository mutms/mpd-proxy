package main

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// mpdDomain is the suffix every name we split on ends with. A single
// /etc/resolver/mpd.test on the Mac points all of it at this forwarder.
const mpdDomain = "mpd.test"

// Forwarder is a split-horizon DNS forwarder for mpd.test and nothing else:
// a query for <NNN>.mpd.test is sent to that VM's own resolver
// (10.163.<NNN>.1) through the tunnel, so a VM's dynamic records
// (containers, runtimes) keep resolving without this process knowing them.
// A name in mpd.test with no route gets NXDOMAIN, and anything outside
// mpd.test is REFUSED — there is deliberately no upstream. Forwarding
// upstream would leak internal names to an outside resolver and, worse,
// invite a cycle when the LAN's own DNS also serves mpd.test names (as a
// home dnsmasq may). LAN names like warp.mpd.test live in the Mac's
// /etc/hosts, which macOS consults before DNS — they never reach us.
type Forwarder struct {
	// mu guards routes. miekg/dns runs ServeDNS in a fresh goroutine per
	// query while the control socket mutates routes concurrently, so every
	// access is under the lock. An RWMutex lets many lookups read in parallel
	// and only serializes the rare write.
	mu     sync.RWMutex
	routes map[string]string // "<NNN>" -> resolver address, e.g. "10.163.150.1:53"

	client dns.Client
}

// NewForwarder builds a Forwarder with no routes; the control socket adds them.
func NewForwarder() *Forwarder {
	return &Forwarder{routes: make(map[string]string)}
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

// resolverFor picks the VM resolver for a query name inside a routed zone.
// !ok means we won't forward this name: outside mpd.test, or no route (VM
// down or not adopted).
func (f *Forwarder) resolverFor(qname string) (string, bool) {
	nnn, ok := zoneID(qname)
	if !ok {
		return "", false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	r, ok := f.routes[nnn]
	return r, ok
}

// ServeDNS makes *Forwarder a dns.Handler: miekg/dns calls it for every query.
// Routed names are forwarded unchanged and the reply copied straight back;
// everything else is answered locally (NXDOMAIN in-zone, REFUSED out-of-zone)
// rather than sent anywhere.
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		refuse(w, req, dns.RcodeRefused)
		return
	}
	qname := req.Question[0].Name
	resolver, ok := f.resolverFor(qname)
	if !ok {
		if inMpdDomain(qname) {
			// mpd.test, but no such VM registered right now (or the apex,
			// which deliberately does not resolve).
			refuse(w, req, dns.RcodeNameError)
		} else {
			// Not our domain — the /etc/resolver hook should never send
			// these; answer "wrong server" instead of resolving them.
			refuse(w, req, dns.RcodeRefused)
		}
		return
	}

	resp, _, err := f.client.Exchange(req, resolver)
	if err != nil || resp == nil {
		// Report the failure rather than dropping the query on the floor.
		refuse(w, req, dns.RcodeServerFailure)
		return
	}
	nnn, _ := zoneID(qname) // ok: resolverFor already proved the name has a zone
	sanitize(resp, nnn)
	_ = w.WriteMsg(resp)
}

// sanitize strips every record outside the VM's own zone from a reply. A VM's
// resolver is authoritative for <nnn>.mpd.test and nothing else, so records
// for any other name — another VM's zone, an outside domain — can only be a
// poisoning attempt by a compromised VM and are dropped from all three
// sections, whatever bailiwick rules the client applies on its own. OPT
// (EDNS) pseudo-records live at the root by definition and pass through.
func sanitize(resp *dns.Msg, nnn string) {
	keep := func(rrs []dns.RR) []dns.RR {
		out := rrs[:0]
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT || inVMZone(rr.Header().Name, nnn) {
				out = append(out, rr)
			}
		}
		return out
	}
	resp.Answer = keep(resp.Answer)
	resp.Ns = keep(resp.Ns)
	resp.Extra = keep(resp.Extra)
}

// inVMZone reports whether name is <nnn>.mpd.test or below it.
func inVMZone(name, nnn string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	zone := nnn + "." + mpdDomain
	return n == zone || strings.HasSuffix(n, "."+zone)
}

// refuse answers req locally with the given rcode.
func refuse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(req, rcode)
	_ = w.WriteMsg(m)
}

// inMpdDomain reports whether qname is mpd.test or below it.
func inMpdDomain(qname string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	return name == mpdDomain || strings.HasSuffix(name, "."+mpdDomain)
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
