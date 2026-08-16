package main

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// zoneID must pull the id label out of any depth of name inside mpd.test, and
// reject anything outside it — that decision is what routes a query to the
// right VM's resolver.
func TestZoneID(t *testing.T) {
	cases := map[string]struct {
		want string
		ok   bool
	}{
		"150.mpd.test.":                 {"150", true},
		"moodle.150.mpd.test.":          {"150", true},
		"adminer.service.181.mpd.test.": {"181", true},
		"MOODLE.150.MPD.TEST":           {"150", true}, // case-insensitive, no trailing dot
		"254.mpd.test.":                 {"254", true}, // top of the id range
		"example.com.":                  {"", false},
		"mpd.test.":                     {"", false}, // the apex has no id label
		"":                              {"", false},
	}
	for name, exp := range cases {
		got, ok := zoneID(name)
		if got != exp.want || ok != exp.ok {
			t.Errorf("zoneID(%q) = (%q, %v), want (%q, %v)", name, got, ok, exp.want, exp.ok)
		}
	}
}

// resolverFor sends a name to its VM's resolver when a route exists, and
// reports !ok for everything else — names outside mpd.test and names inside
// it with no route (VM down/unadopted). There is deliberately no upstream to
// fall back to.
func TestResolverFor(t *testing.T) {
	f := NewForwarder()
	f.SetRoute("150", "10.163.150.1:53")

	cases := map[string]struct {
		want string
		ok   bool
	}{
		"moodle.150.mpd.test.": {"10.163.150.1:53", true}, // routed to its VM
		"150.mpd.test.":        {"10.163.150.1:53", true},
		"181.mpd.test.":        {"", false}, // in mpd.test but no route
		"example.com.":         {"", false}, // outside mpd.test
	}
	for name, exp := range cases {
		if got, ok := f.resolverFor(name); got != exp.want || ok != exp.ok {
			t.Errorf("resolverFor(%q) = (%q, %v), want (%q, %v)", name, got, ok, exp.want, exp.ok)
		}
	}

	// A cleared route stops resolving.
	f.ClearRoute("150")
	if _, ok := f.resolverFor("150.mpd.test."); ok {
		t.Error("after ClearRoute, resolverFor still ok")
	}
}

// Unroutable queries are answered locally: NXDOMAIN inside mpd.test (unknown
// VM, or the apex), REFUSED outside it. Nothing is ever forwarded upstream —
// that would leak internal names and can cycle when the LAN DNS also serves
// mpd.test.
func TestServeDNSLocalAnswers(t *testing.T) {
	f := NewForwarder()

	cases := map[string]int{
		"181.mpd.test.": dns.RcodeNameError, // no route
		"mpd.test.":     dns.RcodeNameError, // apex never resolves
		"example.com.":  dns.RcodeRefused,   // not our domain
	}
	for name, want := range cases {
		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)
		w := &recordingWriter{}
		f.ServeDNS(w, req)
		if w.msg == nil || w.msg.Rcode != want {
			got := -1
			if w.msg != nil {
				got = w.msg.Rcode
			}
			t.Errorf("ServeDNS(%q) rcode = %d, want %d", name, got, want)
		}
	}
}

// TestServeDNSSanitizesReplies runs a fake malicious VM resolver that answers
// a 150.mpd.test query with extra records for another VM's zone and for an
// outside domain. The forwarder must strip everything outside the VM's own
// zone before replying — a compromised VM controls its own names and nothing
// else, whatever bailiwick rules the client applies.
func TestServeDNSSanitizesReplies(t *testing.T) {
	mustRR := func(s string) dns.RR {
		t.Helper()
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}

	evil := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{
			mustRR("moodle.150.mpd.test. 60 IN A 10.163.150.2"), // legit, in zone
			mustRR("151.mpd.test. 60 IN A 6.6.6.6"),             // another VM's zone
			mustRR("example.com. 60 IN A 6.6.6.6"),              // outside domain
		}
		m.Ns = []dns.RR{
			mustRR("mpd.test. 60 IN NS evil.150.mpd.test."), // above the VM's zone
		}
		m.Extra = []dns.RR{
			mustRR("login.151.mpd.test. 60 IN A 6.6.6.6"), // cross-VM poison
		}
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: evil}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.PacketConn = pc
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })

	f := NewForwarder()
	f.SetRoute("150", pc.LocalAddr().String())

	req := new(dns.Msg)
	req.SetQuestion("moodle.150.mpd.test.", dns.TypeA)
	w := &recordingWriter{}
	f.ServeDNS(w, req)

	if w.msg == nil {
		t.Fatal("no reply written")
	}
	if len(w.msg.Answer) != 1 || w.msg.Answer[0].Header().Name != "moodle.150.mpd.test." {
		t.Errorf("answer section = %v, want only moodle.150.mpd.test.", w.msg.Answer)
	}
	if len(w.msg.Ns) != 0 || len(w.msg.Extra) != 0 {
		t.Errorf("authority/additional not stripped: ns=%v extra=%v", w.msg.Ns, w.msg.Extra)
	}
}

// recordingWriter captures the reply; the rest of dns.ResponseWriter is
// unused by these paths.
type recordingWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *recordingWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
