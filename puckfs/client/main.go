// Copyright © 2020,2025 Eric Grosse n2vi.com/0BSD

/*
	Command client fetches a named file from the server to Stdout.
	This is just an simple example of how puckfs can be used.
*/

package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/n2vi/hotline/puckfs"
)

func sighandler(sig os.Signal) {
	if sig == syscall.SIGINT {
		log.Fatalf("caught %s", sig)
	} else {
		log.Printf("ignoring signal %s", sig)
	}
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: puckfs {get|put} path")
	}
	secretfile, err := os.UserHomeDir()
	if err != nil {
		log.Print("unable to get UserHomeDir, using .")
		secretfile = "."
	}
	secretfile = filepath.Join(secretfile, ".ssh", ".puckfs")
	p, err := puckfs.Dial(secretfile)
	chk(err)
	chanSignal := make(chan os.Signal, 1)
	signal.Notify(chanSignal, os.Interrupt, syscall.SIGTERM)
	go func() {
		sighandler(<-chanSignal)
	}()

	switch os.Args[1] {
	case "get":
		data, err := p.ReadFile(os.Args[2])
		chk(err)
		err = os.WriteFile(os.Args[2], data, 0660)
		chk(err)
	case "put":
		data, err := os.ReadFile(os.Args[2])
		chk(err)
		err = p.WriteFile(os.Args[2], data)
		chk(err)
	default:
		log.Fatalf("unimplemented command %s", os.Args[1])
	}

	err = p.Close()
	chk(err)
}

func chk(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
