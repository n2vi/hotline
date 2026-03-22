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
	secretfile := os.Getenv("SF")
	if secretfile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Print("unable to get UserHomeDir, using .")
			home = "."
		}
		secretfile = filepath.Join(home, ".ssh", ".puckfs")
	}
	p, err := puckfs.Dial(secretfile)
	chk(p, err)
	chanSignal := make(chan os.Signal, 1)
	signal.Notify(chanSignal, os.Interrupt, syscall.SIGTERM)
	go func() {
		sighandler(<-chanSignal)
	}()

	switch os.Args[1] {
	case "get":
		data, err := p.ReadFile(os.Args[2])
		chk(p, err)
		err = os.WriteFile(os.Args[2], data, 0660)
		chk(p, err)
	case "put":
		data, err := os.ReadFile(os.Args[2])
		chk(p, err)
		err = p.WriteFile(os.Args[2], data)
		chk(p, err)
	default:
		log.Fatalf("unimplemented command %s", os.Args[1])
	}

	err = p.Close()
	chk(nil, err)
}

func chk(p *puckfs.PuckFS, err error) {
	if err != nil {
		if p != nil {
			p.Close()
		}
		log.Fatal(err)
	}
}
