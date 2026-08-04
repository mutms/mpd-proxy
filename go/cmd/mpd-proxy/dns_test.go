package main

import (
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
		"001.mpd.test.":                 {"001", true}, // zero-padded ids
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

// recordingWriter captures the reply; the rest of dns.ResponseWriter is
// unused by these paths.
type recordingWriter struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (w *recordingWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
