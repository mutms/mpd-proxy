# AI Agent Starting Point

Neutral bootstrap document for AI agents working in this repository — and the
detailed reference the terse `README.md` points at. `CLAUDE.md` imports this
file via `@AGENTS.md`.

## What mpd-proxy is

The small privileged helper for [mpd-virt](https://github.com/mutms/mpd-virt):
one **WireGuard** tunnel plus a **split-DNS** forwarder, so the Mac reaches
every mpd VM's gateway `10.163.<NNN>.1` (caddy + dnsmasq) transparently, for
every app, several VMs at once. It is deliberately a separate binary because
it is the only component in the mpd family that needs root, and it holds none
of mpd-virt's secrets (no CA, no registry): everything arrives over a local
control socket.

The family: [mpd](https://github.com/mutms/mpd) runs inside each VM;
[mpd-virt](https://github.com/mutms/mpd-virt) manages VMs from the Mac and is
the **only client** of this proxy; [mudev](https://github.com/mutms/mudev)
holds Moodle recipes. mpd-virt works without mpd-proxy (SOCKS-over-SSH is the
simple tier); this is the daily-driver upgrade.

## How it works

- **One `utun`, many peers.** mpd-virt adds one WireGuard peer per VM, its
  `AllowedIPs` covering the VM's whole container subnet `10.163.<NNN>.0/24`
  (project URLs are served at container IPs; the in-VM firewall admits wg0
  and seals the subnet from the LAN only). WireGuard's cryptokey
  routing demuxes each packet to the right VM. The Mac's own overlay address
  is `10.163.0.1` (the `10.163.0.x` net is unused by VMs), which is exactly
  what each VM's firewall allow-lists.
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
  `/etc/resolver/mpd.test` file points all of `*.mpd.test` at it — installed
  by `up` during privileged setup (only when missing or different), never
  touched again as VMs come and go; `uninstall` removes it.

The only value that changes — an Apple-container or Parallels DHCP lease —
lives solely in a peer's `endpoint`, rewritten in place; everything id-keyed
(`10.163.<NNN>.x`, `<NNN>.mpd.test`) stays put.

**The key is ephemeral.** mpd-proxy generates a fresh WireGuard keypair on
every start, so after a restart each VM must be re-authorized — re-run
`mpd-virt start <NNN>` per VM. A persisted key, and a LaunchDaemon for boot,
are pending; today `up` is started by hand and runs in the foreground.

## What root is for

`sudo` is needed for three things at startup: creating the utun, installing
the `10.163.0.0/16` route, and writing the `/etc/resolver/mpd.test` hook
(first run only — skipped when already in place). Immediately after, the process
drops to the invoking user (OpenSSH-style privsep) — the WireGuard engine,
DNS forwarder, and control socket all run unprivileged. The drop is
mandatory: a failed drop is fatal, and starting as bare root (no `SUDO_UID`,
so no user to drop to) is refused outright. What an authorized socket client
can do is bounded by the overlay itself, and the proxy enforces the bound
rather than trusting the client: an `add` is rejected unless its
`allowed_ips` sit inside the id's own `10.163.<NNN>.0/24` and its `resolver`
is an address in that same subnet. It cannot make mpd-proxy read files,
touch other routes, or resolve other domains.

## Control protocol

Newline-delimited JSON over the unix socket (default `/tmp/mpd-proxy.sock`) —
a connection may carry several requests, each answered in order. Every
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
(`10.163.<NNN>.0/24` — the whole container subnet) and `resolver` (`10.163.<NNN>.1:53`)
from the id and sends them; mpd-proxy applies what it is handed after
verifying it stays inside the id's own `/24` (`add` is rejected otherwise —
the overlay bound holds even against a misbehaving client). It has
its own keypair and hands out the public half via `pubkey` — mpd-virt
authorizes that on each VM's WireGuard endpoint at takeover, and the VM's key
comes back in `add`.

## Code layout

Everything lives in `go/cmd/mpd-proxy/` — small enough to read in one
sitting:

- `main.go` — the two verbs: `up [--socket PATH]`, `uninstall`
- `up.go` — privileged setup (utun, address, route), then privsep drop
- `tunnel.go` — the embedded wireguard-go device and its UAPI config
- `dns.go` — the split-horizon forwarder (routed zones only, no upstream)
- `control.go` — the unix-socket protocol and peer-uid gate
- `peercreds_darwin.go` — `LOCAL_PEERCRED`; the one OS-specific file. A Linux
  port swaps in a `peercreds_linux.go` (`SO_PEERCRED`) plus the
  utun/route/resolver calls, and nothing else changes.
- `uninstall.go` — removes system traces: kills a running instance, deletes
  `/etc/resolver/mpd.test`, flushes the DNS cache. Distinct from
  `make uninstall`, which removes the installed binary.

Pure Go and self-contained: WireGuard is the embedded
[`wireguard-go`](https://git.zx2c4.com/wireguard-go/) (no `wg`/`wg-quick`),
DNS is [`miekg/dns`](https://github.com/miekg/dns), and the runtime external
commands are macOS built-ins (`ifconfig`, `/sbin/route`; `uninstall` also
uses `pkill`, `launchctl`, `dscacheutil`/`killall`).

## Build and validation

Go 1.26.5+ (`GOTOOLCHAIN=local` makes an older toolchain fail loudly).

- `make build` → `bin/mpd-proxy`; `make install` → `~/.local/bin/mpd-proxy`
- `make test vet fmt-check` after any change; also `fmt`, `tidy`, `clean`,
  `uninstall`

`up` runs in the foreground and logs every control command (the ops are rare,
so there is no quiet mode); Ctrl-C tears the utun, route, and socket down
cleanly.

## Troubleshooting

- **`*.mpd.test` doesn't resolve** — check `/etc/resolver/mpd.test` exists
  (restarting `sudo mpd-proxy up` recreates it) and
  `scutil --dns | grep -A2 mpd.test` shows it; then check the proxy log
  for the VM's route. NXDOMAIN for a VM name means it isn't registered — run
  `mpd-virt start <NNN>`.
- **Resolves but doesn't connect** — the proxy was probably restarted after
  the VM registered (fresh key): re-run `mpd-virt start <NNN>`.
- **`create utun (run under sudo?)`** — `up` needs root.
- **Two proxies** — a second `sudo mpd-proxy up` takes over the control
  socket but leaves the first instance's utun and route in place; stop the
  old one first (Ctrl-C, or `sudo mpd-proxy uninstall` to sweep everything).
- `dig @127.0.0.1 -p 5354 example.com` returning REFUSED is correct — only
  the `/etc/resolver` hook should ever send traffic there, and only for
  mpd.test.
- mpd-virt itself prints a SOCKS fallback hint whenever the proxy isn't
  running, so nothing hard-fails without it.
