// Copyright © 2020,2025,2026 Eric Grosse n2vi.com/0BSD

package puckfs

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
)

func Listen() (p *PuckFS) {
	var err error
	var addr *net.UDPAddr
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	secretfile := os.Getenv("SF")
	if secretfile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Print("unable to get UserHomeDir, using .")
			home = "."
		}
		secretfile = filepath.Join(home, ".ssh", ".puckfs")
	}
	if addr, p, err = readSecretFile(secretfile); err != nil {
		log.Fatalf("euid %d readSecretFile returned %v", os.Geteuid(), err)
	}
	p.serverside = true
	if p.sec.KeyID&1 != 1 { // can't happen except by catastrophic blunder
		log.Fatal("wanted KeyID for server, got client")
	}
	p.readPktCnt()
	if p.udp, err = net.ListenUDP("udp", addr); err != nil {
		log.Fatalf("net.ListenUDP returned %v", err)
	}
	return p
}

// HandleRPC is the server main loop for receiving packets and responding.
// Puck is a single client which is single threaded, so Broker can handle requests sychronously.
func (p *PuckFS) HandleRPC() {
	errCount := 0
	for {
		cmd, req, err := p.readCmd()
		if err != nil {
			if errCount > 3 {
				log.Printf("%v\ntoo many errors; giving up", err)
				p.Close()
				return
			}
			log.Printf("will retry; readCmd err %v", err)
			errCount++
			continue
		}
		resp := []byte{}
		var file string
		switch cmd {
		case cHello:
			log.Print("Hello is special-cased in readPacket().")
			continue
		case cReadfile:
			if file, req, err = extractFilename(req); err != nil {
				reject(p, cError, "bad filename")
				continue
			}
			_ = req
			if resp, err = os.ReadFile(file); err != nil { // open file under local directory
				reject(p, cError, err.Error())
				continue
			}
			if err = p.sendCmd(cReadfile, resp); err != nil {
				log.Printf("cReadfile err %v", err)
				p.Close()
				return
			}
		case cWritefile:
			if file, req, err = extractFilename(req); err != nil {
				reject(p, cError, "bad filename")
				continue
			}
			if err = os.WriteFile(file, req, 0660); err != nil { // create under local directory
				reject(p, cError, err.Error())
				continue
			}
			if err = p.sendCmd(cWritefile, resp); err != nil {
				log.Printf("cWritefile sendCmd err %v", err)
				p.Close()
				return
			}
		case cRemove:
			if file, req, err = extractFilename(req); err != nil {
				reject(p, cError, "bad filename")
				continue
			}
			_ = req
			if err = os.Remove(file); err != nil {
				reject(p, cError, err.Error())
				continue
			}
			if err = p.sendCmd(cRemove, resp); err != nil {
				log.Printf("cReadfile err %v", err)
				p.Close()
				return
			}
		case cReaddir:
			// fs Path Names must not end with a slash, but we require it. Adjust.
			file := string(req)
			_ = req
			if file[len(file)-1] != '/' {
				reject(p, cError, "cReaddir requires trailing slash")
				continue
			}
			file = file[:len(file)-1]
			if !fs.ValidPath(file) {
				reject(p, cError, "bad dirname")
				continue
			}
			entries, err := os.ReadDir(file)
			if err != nil {
				reject(p, cError, err.Error())
				continue
			}
			for _, entry := range entries {
				f, err := entry.Info()
				if err != nil {
					continue
				}
				suffix := ""
				if f.IsDir() {
					suffix = "/"
				}
				resp = append(resp, fmt.Sprintf("%s%s\000%d\000%d\n",
					f.Name(), suffix, f.Size(), f.ModTime().Unix())...)
			}
			if err = p.sendCmd(cReaddir, resp); err != nil {
				log.Printf("cReaddir err %v", err)
				p.Close()
				return
			}
		case cBye:
			p.Close()
			log.Print("Bye")
		default:
			log.Printf("unrecognized cmd %d; giving up", cmd)
			p.Close()
			return
		}
		// At this point, we've sent our full reply but it may not yet have
		// been received if there were lost packets. Our retransmit timers
		// are still running. Also, we expect the client to soon send another
		// command, likely Bye, including an ack.
		if p.sec.DEBUG {
			log.Printf("------------- %d pending", p.snd.w-p.snd.r)
		}
	}
}

// Extract zero-byte terminated file name (or entire input).
func extractFilename(req []byte) (file string, remainder []byte, err error) {
	j := bytes.IndexByte(req, 0)
	if j < 0 {
		file = string(req)
		remainder = []byte{}
	} else {
		file = string(req[:j])
		remainder = req[j+1:]
	}

	if !fs.ValidPath(file) {
		return "", req, errBye
	}
	return file, remainder, nil
}

// Reject sends error message, else fatal.
func reject(p *PuckFS, cmd uint16, mess string) {
	var err error
	log.Printf("rejected %x %s", cmd, mess)
	if err = p.sendCmd(cmd, []byte(mess)); err != nil {
		log.Fatalf("unable to even send rejection %v", err)
	}
}

func (p *PuckFS) readPktCnt() error {
	data, err := os.ReadFile(p.sec.PktCnt)
	if err != nil {
		return err
	}
	var sw, rw uint32
	n, err := fmt.Sscanf(string(data), "%d %d %d", &p.greetings, &sw, &rw)
	if n != 3 || err != nil {
		log.Fatalf("unable to parse %s: %d %v", p.sec.PktCnt, n, err)
	}
	if sw > uint32(1<<29) || rw > uint32(1<<29) {
		log.Print("time to rekey; PktCnt getting large") // I doubt I'll ever get this.
	}
	p.snd.r = sw
	p.snd.w = sw
	p.rcv.r = rw
	p.rcv.w = rw
	return err
}

func (p *PuckFS) WritePktCnt() {
	f, err := os.OpenFile(p.sec.PktCnt, os.O_RDWR, 0600)
	if err != nil {
		log.Printf("%d %d %d\n", p.greetings, p.snd.w, p.rcv.w)
		log.Fatal(err)
	}
	fmt.Fprintf(f, "%d %d %d\n", p.greetings, p.snd.w, p.rcv.w)
	err = f.Close()
	if err != nil {
		log.Printf("%d %d %d\n", p.greetings, p.snd.w, p.rcv.w)
		log.Fatal(err)
	}
}
