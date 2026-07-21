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

	cmd := os.Args[1]
	pathname := os.Args[2]
	isdir := pathname[len(pathname)-1] == '/'
	if cmd == "get" && !isdir {
		data, err := p.ReadFile(pathname)
		chk(p, err)
		err = os.WriteFile(pathname, data, 0660)
		chk(p, err)
	} else if cmd == "get" && isdir {
		fi, err := p.ReadDir(pathname)
		chk(p, err)
		err = os.MkdirAll(pathname, 0770)
		for _, f := range fi {
			if f.IsDir() {
				log.Printf("get %s: skipping %s/", pathname, f.Name())
				continue
			}
			fn := pathname + f.Name()
			data, err := p.ReadFile(fn)
			chk(p, err)
			err = os.WriteFile(fn, data, 0660)
		}
	} else if cmd == "put" && !isdir {
		data, err := os.ReadFile(pathname)
		chk(p, err)
		err = p.WriteFile(pathname, data)
		chk(p, err)
	} else if cmd == "put" && isdir {
		p.Close()
		log.Fatalf("put {dir} not implemented yet")
	} else {
		p.Close()
		log.Fatalf("unimplemented command %s", cmd)
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
