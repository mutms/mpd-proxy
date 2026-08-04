//go:build darwin

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the uid of the process on the other end of a unix socket, as
// vouched for by the kernel — unforgeable, unlike anything the client could
// claim in a message. On macOS that is LOCAL_PEERCRED, read off the raw fd.
//
// This is the one file that is darwin-specific (the //go:build tag); a Linux
// build gets a peercreds_linux.go using SO_PEERCRED instead, and nothing else
// in the program changes.
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		uid      int
		innerErr error
	)
	// Control runs the closure with the socket's fd held open. Getpeereid via
	// GetsockoptXucred reads the peer's credentials from the kernel.
	if err := raw.Control(func(fd uintptr) {
		xu, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			innerErr = e
			return
		}
		uid = int(xu.Uid)
	}); err != nil {
		return 0, err
	}
	return uid, innerErr
}
