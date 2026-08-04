# mpd-proxy

The small, privileged helper for [mpd-virt](https://github.com/mutms/mpd-virt).
It runs a **WireGuard** tunnel and a **split-DNS** forwarder so this Mac can
reach every mpd VM's gateway `10.163.<NNN>.1` (caddy + dnsmasq) — transparently,
for every app, several VMs at once — without per-VM routes.

**The mpd family:** [mpd](https://github.com/mutms/mpd) is the Moodle dev
platform that runs *inside* each VM; [mpd-virt](https://github.com/mutms/mpd-virt)
manages those VMs *from the Mac* and is the only client of this proxy;
mpd-proxy (this repo) is the optional root-only network plumbing that makes
`https://moodle.<NNN>.mpd.test` open in any browser with no proxy settings.

This is the **advanced, daily-driver** reachability path, for developers running
several VMs every day. It needs `sudo` (to create the utun). For occasional use
or a first setup there is a simpler, sudo-free alternative: mpd-virt writes a
**SOCKS-over-SSH** block (`ssh -N mpd-<NNN>-socks` + a dedicated browser), which
tunnels one VM through plain SSH with no overlay — see mpd-virt's docs. mpd-proxy
is what you graduate to.

It is deliberately a **separate binary** from mpd-virt, because it is the only
component that needs root. It reads **no mpd files** and holds none of
mpd-virt's secrets (no CA, no registry): everything it needs arrives over a
local control socket. It is root only for a few syscalls at startup — create
the utun, add the route — then **drops to the invoking user** for the rest of
its life.

## How it works

- **One `utun`, many peers.** mpd-virt adds one WireGuard peer per VM, its
  `AllowedIPs` scoped to just the VM's gateway `10.163.<NNN>.1/32` — the
  container IPs behind it are deliberately *not* routed (reached indirectly via
  caddy/ssh, and sealed by an in-VM firewall). WireGuard's cryptokey routing
  demuxes each packet to the right VM — one interface reaches them all. The
  Mac's own address in the overlay is `10.163.0.1` (the `10.163.0.x` net is
  unused by VMs), which is exactly what each VM's firewall allow-lists.
- **One aggregate route.** `10.163.0.0/16 → utun`, installed once. A new VM's
  `/24` is already covered, so adopting a VM needs no new route and no `sudo`.
- **Split DNS, mpd.test only.** A UDP forwarder on `127.0.0.1:5354` sends
  `<NNN>.mpd.test` to that VM's own resolver (`10.163.<NNN>.1`) through the
  tunnel — and that is all it does. An mpd.test name with no registered VM
  gets NXDOMAIN, anything outside mpd.test is REFUSED, and nothing is ever
  forwarded to an outside resolver: internal names don't leak, and there is
  no resolution cycle even when the LAN's own DNS serves mpd.test names too.
  Non-VM LAN hosts (`warp.mpd.test`, …) live in the Mac's `/etc/hosts`, which
  macOS consults before DNS, so they never reach the forwarder. A single
  `/etc/resolver/mpd.test` file (see First run) points all of `*.mpd.test` at
  it — created once, never touched again as VMs come and go.

The only value that changes — an Apple-container or Parallels DHCP lease — lives
solely in a peer's `endpoint`, rewritten in place; everything id-keyed
(`10.163.<NNN>.x`, `<NNN>.mpd.test`) stays put.

## Requirements

- macOS (the utun/route/resolver mechanics are Darwin-specific — see
  Portability).
- Go 1.26.5 or newer to build (`GOTOOLCHAIN=local` makes an older toolchain
  fail loudly rather than auto-download).
- `sudo` for `mpd-proxy up` and for writing `/etc/resolver/mpd.test`.

## First run

```sh
make build install                     # → bin/mpd-proxy, ~/.local/bin/mpd-proxy

sudo tee /etc/resolver/mpd.test <<'EOF' # route *.mpd.test lookups to the forwarder
nameserver 127.0.0.1
port 5354
EOF

sudo mpd-proxy up                      # foreground: utun + route, drops root, logs

# in another terminal, register each running VM with the fresh proxy:
mpd-virt start <NNN>

dig +short <NNN>.mpd.test @127.0.0.1 -p 5354   # sanity check the forwarder
open https://<NNN>.mpd.test/                   # portal, via the tunnel
```

`up` runs in the foreground and **logs every control command** (the ops are
rare, so there is no quiet mode). Ctrl-C tears the utun, route, and socket down
cleanly. A LaunchDaemon for boot is planned but not built yet — today you start
it by hand.

**The key is ephemeral.** mpd-proxy generates a fresh WireGuard keypair on
every start, so after a restart (or reboot) each VM must be re-authorized —
just re-run `mpd-virt start <NNN>` per VM. A persisted key is on the wish list.

## Usage

- `sudo mpd-proxy up [--socket PATH]` — bring the proxy up (foreground).
  Default socket: `/tmp/mpd-proxy.sock`. `--socket` is a flag of `up`, not a
  global flag.
- `sudo mpd-proxy uninstall` — remove every system trace: kill a running
  instance, delete `/etc/resolver/mpd.test`, flush the DNS cache (and remove
  the LaunchDaemon plist, once that exists). Not to be confused with
  `make uninstall`, which removes the *binary* from `~/.local/bin`.

## Control protocol

mpd-virt is the only client. Newline-delimited JSON over the unix socket — a
connection may carry several requests, each answered in order. Every
connection is gated on the kernel-reported peer uid (`LOCAL_PEERCRED`): the
user who invoked `sudo mpd-proxy up`, or root, may connect; everyone else is
dropped.

| Op | Fields | Effect |
|---|---|---|
| `pubkey` | — | returns mpd-proxy's own WireGuard public key |
| `add` | `id`, `public_key`, `endpoint`, `allowed_ips`, `resolver` | upsert a peer + its DNS route |
| `remove` | `id` | drop the peer + DNS route (idempotent) |
| `list` | — | current VMs |

Every response carries `ok` plus, per op, the `pubkey` or the `vms` list;
failures come back as `ok:false` with an `error` string.

mpd-proxy is a dumb plumber: mpd-virt derives `allowed_ips`
(`10.163.<NNN>.1/32` — the gateway only, not the container subnet) and `resolver`
(`10.163.<NNN>.1:53`) from the id and sends them; mpd-proxy just applies what it
is handed. It has its own keypair and hands
out the public half via `pubkey` — mpd-virt authorizes that on each VM's
WireGuard endpoint at takeover, and the VM's key comes back in `add`.

## What root is for

`sudo` is needed for exactly two syscall clusters at startup: creating the
utun and installing the `10.163.0.0/16` route. Immediately after, the process
drops to the invoking user (OpenSSH-style privsep) — the WireGuard engine, DNS
forwarder, and control socket all run unprivileged. What an authorized socket
client can do is bounded by the overlay itself: add/remove WireGuard peers and
DNS routes inside `10.163.0.0/16` / `*.mpd.test`. It cannot make mpd-proxy
read files, touch other routes, or resolve other domains differently.

## Build

```sh
make build       # bin/mpd-proxy
make install     # copy to ~/.local/bin/mpd-proxy
make uninstall   # remove ~/.local/bin/mpd-proxy
make test        # go test ./...
make vet fmt fmt-check tidy clean
```

Pure Go and self-contained: WireGuard is the embedded
[`wireguard-go`](https://git.zx2c4.com/wireguard-go/) (no `wg`/`wg-quick`), DNS
is [`miekg/dns`](https://github.com/miekg/dns), and the runtime external
commands are macOS built-ins (`ifconfig`, `/sbin/route`; `uninstall` also uses
`pkill`, `launchctl`, `dscacheutil`/`killall`).

## Troubleshooting

- **`*.mpd.test` doesn't resolve** — check `/etc/resolver/mpd.test` exists
  (see First run) and `scutil --dns | grep -A2 mpd.test` shows it; then check
  the proxy log for the VM's route.
- **Resolves but doesn't connect** — the proxy was probably restarted after
  the VM registered (fresh key): re-run `mpd-virt start <NNN>`.
- **`create utun (run under sudo?)`** — `up` needs root.
- **Two proxies** — a second `sudo mpd-proxy up` takes over the control socket
  but leaves the first instance's utun and route in place; stop the old one
  first (Ctrl-C, or `sudo mpd-proxy uninstall` to sweep everything).
- mpd-virt itself prints a SOCKS fallback hint whenever the proxy isn't
  running, so nothing hard-fails without it.

## Portability

macOS today. The one OS-specific file is
`go/cmd/mpd-proxy/peercreds_darwin.go` (`LOCAL_PEERCRED`); a Linux port swaps
in a `peercreds_linux.go` (`SO_PEERCRED`) plus the utun/route/resolver calls,
and nothing else changes.

## Status

Working end-to-end. Proven live: the DNS forwarder, WireGuard + cryptokey
routing (embedded, unit-tested via userspace netstack), real `utun` creation,
the control socket with peer-cred auth, and `sudo mpd-proxy up` (utun + address
+ route + WireGuard + DNS + control socket + privsep drop). mpd-virt drives the
socket at takeover/start, and reachability is validated against real VMs —
transparent HTTPS and split DNS through the tunnel. Pending: a persisted
WireGuard key and a LaunchDaemon for boot.

## Acknowledgments

Part of the [mpd](https://github.com/mutms/mpd) project. mpd and its related
tools are my first fully AI-driven project — the code and docs are largely
written by [Claude Code](https://claude.com/claude-code) (Anthropic) under my
direction (design and review stay human).

## License

Copyright (C) 2026 Petr Skoda. [GPL-3.0](LICENSE) or later.

Moodle is a registered trademark of [Moodle Pty Ltd](https://moodle.com).
