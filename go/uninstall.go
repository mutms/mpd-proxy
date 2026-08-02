package main

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	resolverPath = "/etc/resolver/mpd.test"
	// launchdPath is where a boot-install would drop the LaunchDaemon (not yet
	// built); removed here if present so uninstall is forward-compatible.
	launchdPath = "/Library/LaunchDaemons/test.mpd-proxy.plist"
)

// runUninstall removes mpd-proxy's Mac-side plumbing: it stops a running
// instance (its utun and route are ephemeral — they vanish with the process),
// removes a LaunchDaemon if one was installed, and deletes the /etc/resolver
// hook that points *.mpd.test at the forwarder. Needs root, like `up`. No VM
// data is touched; reinstall by running `sudo mpd-proxy up` again.
func runUninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall needs root — run: sudo mpd-proxy uninstall")
	}

	// Stop a running instance so its utun, route, and DNS forwarder go away.
	_ = exec.Command("pkill", "-f", "mpd-proxy up").Run()

	// A LaunchDaemon, if boot-install ever put one there.
	if _, err := os.Stat(launchdPath); err == nil {
		_ = exec.Command("launchctl", "unload", launchdPath).Run()
		if err := os.Remove(launchdPath); err != nil {
			return fmt.Errorf("remove %s: %w", launchdPath, err)
		}
		fmt.Printf("removed %s\n", launchdPath)
	}

	// The /etc/resolver hook pointing *.mpd.test at this forwarder.
	switch err := os.Remove(resolverPath); {
	case err == nil:
		fmt.Printf("removed %s\n", resolverPath)
	case os.IsNotExist(err):
		fmt.Printf("%s already absent\n", resolverPath)
	default:
		return fmt.Errorf("remove %s: %w", resolverPath, err)
	}

	// Flush so the removed hook stops being consulted.
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()

	fmt.Println("mpd-proxy uninstalled — Mac-side plumbing removed, VM data untouched.")
	fmt.Println("Reinstall by running `sudo mpd-proxy up`.")
	return nil
}
