package main

import "testing"

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

// resolverFor sends a name to its VM's resolver when a route exists, and to the
// default upstream otherwise — including names inside mpd.test with no route
// yet (VM down/unadopted), which must not hang.
func TestResolverFor(t *testing.T) {
	f := NewForwarder("1.1.1.1:53")
	f.SetRoute("150", "10.163.150.1:53")

	cases := map[string]string{
		"moodle.150.mpd.test.": "10.163.150.1:53", // routed to its VM
		"150.mpd.test.":        "10.163.150.1:53",
		"181.mpd.test.":        "1.1.1.1:53", // in mpd.test but no route → upstream
		"example.com.":         "1.1.1.1:53", // outside mpd.test → upstream
	}
	for name, want := range cases {
		if got := f.resolverFor(name); got != want {
			t.Errorf("resolverFor(%q) = %q, want %q", name, got, want)
		}
	}

	// A cleared route falls back to upstream.
	f.ClearRoute("150")
	if got := f.resolverFor("150.mpd.test."); got != "1.1.1.1:53" {
		t.Errorf("after ClearRoute, resolverFor = %q, want upstream", got)
	}
}
