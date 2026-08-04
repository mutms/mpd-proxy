package main

import (
	"flag"
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
		fs := flag.NewFlagSet("up", flag.ExitOnError)
		socket := fs.String("socket", defaultSocket, "control socket path")
		_ = fs.Parse(os.Args[2:])
		if err := runUp(*socket); err != nil {
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
	fmt.Fprintln(os.Stderr, "usage: mpd-proxy up [--socket PATH]")
	fmt.Fprintln(os.Stderr, "       sudo mpd-proxy uninstall")
	os.Exit(2)
}
