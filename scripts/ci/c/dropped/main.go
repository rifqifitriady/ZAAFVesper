// Command dropped is the stand-in for an unsigned second-stage payload in the
// live-macos validation: the harness copies it into /tmp and runs it. It
// only prints a line; with -connect host:port it also holds a TCP connection
// open for a few seconds (loopback only), for the socket-polling checks.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	connect := flag.String("connect", "", "loopback host:port to hold a connection to")
	hold := flag.Duration("hold", 4*time.Second, "how long to hold the connection")
	flag.Parse()
	fmt.Println("zaafvesper live-macos dropped binary, pid", os.Getpid())
	if *connect == "" {
		return
	}
	host, _, err := net.SplitHostPort(*connect)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(os.Stderr, "only loopback addresses are allowed")
		os.Exit(2)
	}
	c, err := net.DialTimeout("tcp", *connect, 3*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	time.Sleep(*hold)
	_ = c.Close()
}
