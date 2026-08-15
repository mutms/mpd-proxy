# mpd-proxy

The small privileged helper for [mpd-virt](https://github.com/mutms/mpd-virt):
one WireGuard tunnel plus a split-DNS forwarder, so every `*.mpd.test` site
served by your [mpd](https://github.com/mutms/mpd) VMs works transparently in
every app on the Mac — several VMs at once, no per-VM routes, no browser proxy
settings. It is the only piece of the mpd family that needs `sudo`, and it is
optional: for occasional single-VM use, mpd-virt's SOCKS-over-SSH tier in a
dedicated browser (Firefox) is perfectly fine with no mpd-proxy running at
all. A hand-started CLI tool for developers by design — it runs in the
foreground, and boot-time start (a LaunchDaemon) is not planned.

Root is used for exactly two things at startup — create the utun, add one
`10.163.0.0/16` route — then the process drops to the invoking user. DNS
answers only registered `<NNN>.mpd.test` zones and refuses everything else;
nothing is ever forwarded to an outside resolver.

## First run

Needs macOS, Go 1.26.5+, and `sudo`.

```sh
make build install                     # → bin/mpd-proxy, ~/.local/bin/mpd-proxy

sudo mpd-proxy up                      # foreground: utun + route + /etc/resolver hook, drops root, logs

# in another terminal, register each running VM with the fresh proxy:
mpd-virt start <NNN>

open https://<NNN>.mpd.test/           # any browser, via the tunnel
```

`up` installs `/etc/resolver/mpd.test` on first run (and leaves it alone
afterwards), so `*.mpd.test` lookups reach the forwarder — no manual DNS
setup. Restarting the proxy generates a fresh WireGuard key — re-run
`mpd-virt start <NNN>` for each VM afterwards.

## Uninstall

`sudo mpd-proxy uninstall` stops a running proxy and removes every system
trace — the `/etc/resolver` hook and a LaunchDaemon if present; the utun and
route die with the process. `make uninstall` removes the installed binary.

## Documentation

The repo is small enough to read in one sitting; the write-up lives in
[AGENTS.md](AGENTS.md) — how the tunnel and split DNS work, the control
protocol, what root is for, code layout, troubleshooting. Point an AI
assistant at it, or just ask it questions about the code.

## About

I built these tools for my own daily Moodle work and release them because I
like open source — try them, break them, send issues or PRs.

mpd and its related tools are my first fully AI-driven project — the code and
docs are largely written by [Claude Code](https://claude.com/claude-code)
(Anthropic) under my direction (design and review stay human).

## License

Copyright (C) 2026 Petr Skoda. [GPL-3.0](LICENSE) or later.

Moodle is a registered trademark of [Moodle Pty Ltd](https://moodle.com).
