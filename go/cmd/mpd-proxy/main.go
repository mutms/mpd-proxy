package main

import (
	"fmt"
	"log"
	"os"
)

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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sudo mpd-proxy up")
	fmt.Fprintln(os.Stderr, "       sudo mpd-proxy uninstall")
	os.Exit(2)
}
