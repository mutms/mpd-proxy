# mpd-proxy

The small, privileged helper for [mpd-virt](https://github.com/mutms/mpd-virt).
It runs a **WireGuard** tunnel and a **split-DNS** forwarder so this Mac can
reach every mpd VM's internal `10.163.<NNN>.0/24` podman bridge — transparently,
for every app — without per-VM routes or `/etc/resolver` files.

It is deliberately a **separate binary** from mpd-virt, because it is the only
component that needs root. It reads **no files** and holds none of mpd-virt's
secrets (no CA, no registry): everything it needs arrives over a local control
socket. It is root only for a few syscalls at startup — create the utun, add
the route — then **drops to the invoking user** for the rest of its life.

## How it works

- **One `utun`, many peers.** mpd-virt adds one WireGuard peer per VM, its
  `AllowedIPs` set to the VM's `10.163.<NNN>.0/24`. WireGuard's cryptokey
  routing demuxes each packet to the right VM — one interface reaches them all.
- **One aggregate route.** `10.163.0.0/16 → utun`, installed once. A new VM's
  `/24` is already covered, so adopting a VM needs no new route and no `sudo`.
- **Split DNS.** A forwarder on `127.0.0.1:5354` sends `<NNN>.mpd.test` to that
  VM's own resolver (`10.163.<NNN>.1`) through the tunnel, and everything else
  to the host's upstream. A single `/etc/resolver/mpd.test` (with `port 5354`)
  points all of `*.mpd.test` at it — written once, never touched again as VMs
  come and go.

The only value that changes — an Apple-container or Parallels DHCP lease — lives
solely in a peer's `endpoint`, rewritten in place; everything id-keyed
(`10.163.<NNN>.x`, `<NNN>.mpd.test`) stays put.

## Usage

```sh
make build              # → bin/mpd-proxy
sudo bin/mpd-proxy up   # foreground: creates utun + route, drops root, then logs
```

`up` runs in the foreground and **logs every control command** (the ops are
rare, so there is no quiet mode). Ctrl-C tears the utun, route, and socket down
cleanly. In production a LaunchDaemon runs the same binary at boot.

Flags: `--socket PATH` (default `/tmp/mpd-proxy.sock`).

## Control protocol

mpd-virt is the only client. Newline-delimited JSON over the unix socket, one
request → one response; every connection is gated on the kernel-reported peer
uid (`LOCAL_PEERCRED`).

| Op | Fields | Effect |
|---|---|---|
| `pubkey` | — | returns mpd-proxy's own WireGuard public key |
| `add` | `id`, `public_key`, `endpoint`, `allowed_ips`, `resolver` | upsert a peer + its DNS route |
| `remove` | `id` | drop the peer + DNS route |
| `list` | — | current VMs |

mpd-proxy is a dumb plumber: mpd-virt derives `allowed_ips`
(`10.163.<NNN>.0/24`) and `resolver` (`10.163.<NNN>.1:53`) from the id and sends
them; mpd-proxy just applies what it is handed. It has its own keypair and hands
out the public half via `pubkey` — mpd-virt authorizes that on each VM's
WireGuard endpoint at takeover, and the VM's key comes back in `add`.

## Build

```sh
make build       # bin/mpd-proxy
make test        # go test ./...
make vet
make fmt-check
make clean
```

Pure Go and self-contained: WireGuard is the embedded
[`wireguard-go`](https://git.zx2c4.com/wireguard-go/) (no `wg`/`wg-quick`), DNS
is [`miekg/dns`](https://github.com/miekg/dns), and the only external commands
are macOS built-ins (`ifconfig`, `/sbin/route`). Nothing to install.

## Portability

macOS today. The one OS-specific file is `go/peercreds_darwin.go`
(`LOCAL_PEERCRED`); a Linux port swaps in a `peercreds_linux.go` (`SO_PEERCRED`)
plus the utun/route/resolver calls, and nothing else changes.

## Status

Prototype. Proven working: the DNS forwarder, WireGuard + cryptokey routing
(embedded, unit-tested via userspace netstack), real `utun` creation, the
control socket with peer-cred auth, and `sudo mpd-proxy up` (utun + address +
route + WireGuard + DNS + control socket + privsep drop, verified live).
Pending: a real WireGuard endpoint on a VM for end-to-end reachability, the
mpd-virt client that drives the socket, a persisted key, and a LaunchDaemon.

Design and rationale: `docs/proposals/mpd-proxy-wireguard.md` in the mpd-virt
repo.

## Acknowledgments

Part of the [mpd](https://github.com/mutms/mpd) project. mpd and its related
tools are my first fully AI-driven project — the code and docs are largely
written by [Claude Code](https://claude.com/claude-code) (Anthropic) under my
direction (design and review stay human).

## License

Copyright (C) 2026 Petr Skoda. [GPL-3.0](LICENSE) or later.

Moodle is a registered trademark of [Moodle Pty Ltd](https://moodle.com).
