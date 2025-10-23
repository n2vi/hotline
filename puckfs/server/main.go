// Copyright © 2020,2025 Eric Grosse n2vi.com/0BSD

/*
	Command puckfs provides a primitive network file server.
	Server listens on a fixed port for one call at a time from a single client.
*/

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/n2vi/hotline/puckfs"
)

var p *puckfs.PuckFS

func sighandler(sig os.Signal) {
	if sig == syscall.SIGINT {
		// This may be a data race, but usually gets manually invoked during a quiet time.
		log.Printf("caught SIGINT; trying to save packet counters")
		p.WritePktCnt()
		log.Fatalf("caught %s", sig)
	} else {
		log.Printf("ignoring signal %s", sig)
	}
}

func main() {
	if len(os.Args) != 1 {
		log.Fatal("usage: cd dir; puckfs")
	}
	p = puckfs.Listen()
	chanSignal := make(chan os.Signal, 1)
	signal.Notify(chanSignal, os.Interrupt, syscall.SIGTERM)
	go func() {
		sighandler(<-chanSignal)
	}()
	p.HandleRPC()
	log.Fatal("broker shutting down")
}
