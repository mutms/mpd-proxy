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
		if len(os.Args) > 2 {
			usage() // `up` takes no flags!
		}
		if err := runUp(); err != nil {
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sudo mpd-proxy up")
	fmt.Fprintln(os.Stderr, "       sudo mpd-proxy uninstall")
	fmt.Fprintln(os.Stderr, "       mpd-proxy version")
	os.Exit(2)
}
