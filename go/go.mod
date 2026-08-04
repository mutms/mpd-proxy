module github.com/mutms/mpd-proxy/go

go 1.26.5

// DEP PINNING — read before "upgrading" anything here.
//
// Do NOT run a blanket dependency upgrade (e.g. GoLand's "Upgrade all",
// `go get -u ./...`). It breaks this module every time.
//
// gvisor.dev/gvisor is INDIRECT: it is pulled in only by
// golang.zx2c4.com/wireguard/tun/netstack, and wireguard-go hand-pins it
// to a specific known-good commit its netstack was written against. gvisor's
// repo has package-conflict commits at HEAD (the `stack`/`bridge` build
// error), so it is deliberately not `go get`-able to arbitrary newer
// commits. Bumping gvisor independently of wireguard desyncs the two and
// will not compile.
//
// wireguard-go publishes NO release tags — only master pseudo-versions —
// so the pin below (`v0.0.0-<date>-<sha>`) IS its @latest. gvisor's version
// is therefore whatever that wireguard commit's own go.mod declares; let
// MVS resolve it, never hand-pick it.
//
// To move forward: bump a DIRECT dep on purpose
// (`go get golang.zx2c4.com/wireguard@latest`, `go get github.com/miekg/dns@latest`)
// then `go mod tidy`, and let the matching gvisor come along for the ride.

require (
	github.com/miekg/dns v1.1.72
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)
