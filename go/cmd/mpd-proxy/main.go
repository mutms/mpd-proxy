package main

import (
	"fmt"
	"log"
	"os"
)

// version is stamped at build time via -ldflags.
var version = "dev"

func main() {
	log.SetFlags(log.Ltime)

	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "up":
		if err := runUp(parseUpArgs(os.Args[2:])); err != nil {
			log.Fatal(err)
		}
	case "uninstall":
		if err := runUninstall(); err != nil {
			log.Fatal(err)
		}
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
	}
}

// parseUpArgs reads `up`'s only optional flag. --disable-wg-filter turns off
// the inbound guard (filter.go) for the run — a debugging escape hatch to rule
// the filter out as the cause of a dropped connection; see runUp for the
// warning it carries. Any other argument is a usage error.
func parseUpArgs(args []string) (disableFilter bool) {
	for _, a := range args {
		switch a {
		case "--disable-wg-filter":
			disableFilter = true
		default:
			usage() // exits; `up` takes no other flags
		}
	}
	return disableFilter
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sudo mpd-proxy up [--disable-wg-filter]")
	fmt.Fprintln(os.Stderr, "       sudo mpd-proxy uninstall")
	fmt.Fprintln(os.Stderr, "       mpd-proxy version")
	os.Exit(2)
}
