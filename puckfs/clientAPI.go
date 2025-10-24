// Copyright © 2020,2025 Eric Grosse n2vi.com/0BSD

/*
Package puckfs provides a primitive network file server and client,
atop Go-Back-N retransmission and transport encryption, atop udp.
*/
package puckfs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Dial calls the puckfs server and checks clocks for consistency.
func Dial(secretfile string) (p *PuckFS, err error) {
	var addr *net.UDPAddr
	if addr, p, err = readSecretFile(secretfile); err != nil {
		return p, err
	}
	p.caller = nil
	if p.sec.KeyID&1 != 0 { // can't happen except by catastrophic blunder
		return p, errors.New("wanted KeyID for client, got server")
	}
	if p.udp, err = net.DialUDP("udp", nil, addr); err != nil {
		return p, err
	}
	cmd, data := p.clientRPC(cHello, []byte(time.Now().UTC().Format(time.RFC3339)))
	if err = expect(cHello, cmd, data); err != nil {
		return p, err
	}
	if len(data) > 0 {
		log.Printf("our clock is %s behind", data)
	}
	return p, err
}

// ReadFile fetches file contents.
func (p *PuckFS) ReadFile(path string) (data []byte, err error) {
	cmd, data := p.clientRPC(cReadfile, []byte(path))
	return data, expect(cReadfile, cmd, data)
}

// WriteFile writes file contents,
// but without permission modes since puckfs is a single-user filesystem.
func (p *PuckFS) WriteFile(path string, data []byte) (err error) {
	var mess []byte
	if mess, err = pathPrefix(path); err != nil {
		return err
	}
	mess = append(mess, data...)
	cmd, mess := p.clientRPC(cWritefile, mess)
	return expect(cWritefile, cmd, mess)
}

// Remove deletes the file.
func (p *PuckFS) Remove(path string) (err error) {
	cmd, mess := p.clientRPC(cRemove, []byte(path))
	return expect(cRemove, cmd, mess)
}

// ReadDir reads a directory and returns a slice of stat data.
func (p *PuckFS) ReadDir(path string) (fi []fs.FileInfo, err error) {
	cmd, data := p.clientRPC(cReaddir, []byte(path))
	if err = expect(cReaddir, cmd, data); err != nil {
		return []fs.FileInfo{}, err
	}
	datalines := bytes.Split(data, []byte("\n"))
	fi = make([]fs.FileInfo, len(datalines))
	for i, s := range datalines {
		if len(s) == 0 {
			if i != len(fi)-1 {
				log.Fatalf("unanticipated empty file from ReadDir %d", i)
			}
			fi = fi[:i] // chop empty after final newline
			break
		}
		field := bytes.Split(s, []byte("\000"))
		if len(field) != 3 {
			return fi, errors.New("can't happen; expect dir{name,size,mtime}")
		}
		f := myFileInfo{}
		n := len(field[0])
		if field[0][n-1] == '/' {
			f.isdir = true
			field[0] = field[0][:n-1]
		}
		f.name = string(field[0])
		if f.size, err = strconv.ParseInt(string(field[1]), 10, 64); err != nil {
			return fi, fmt.Errorf("can't happen %q %s", field[1], err)
		}
		if f.mtime, err = strconv.ParseInt(string(field[2]), 10, 64); err != nil {
			return fi, fmt.Errorf("can't happen %q %s", field[2], err)
		}
		fi[i] = fs.FileInfo(f)
	}
	return fi, err
}

// Chtime changes the "modified" time on the file.
func (p *PuckFS) Chtime(path string, mtime int64) (err error) {
	var mess []byte
	if mess, err = pathPrefix(path); err != nil {
		return err
	}
	mess = strconv.AppendInt(mess, mtime, 10)
	cmd, mess := p.clientRPC(cChtime, mess)
	return expect(cChtime, cmd, mess)
}

func (p *PuckFS) Close() (err error) {
	if p.sec.DEBUG {
		log.Printf("Close")
	}
	if p.udp == nil {
		return errBye
	}
	if p.caller == nil { // We're a client. Drop the network call.
		cmd, mess := p.clientRPC(cBye, []byte{})
		if expect(cBye, cmd, mess) != nil {
			log.Print("may have had trouble saying Bye")
		}
		_ = p.udp.Close()
		p.udp = nil
	} else { // We're a server. Record the call as dropped but keep listening.
		p.sendCmd(cBye, []byte{}) // No error checking needed here, we're stopping regardless.
		p.snd.pop()               // We won't be getting an ack for the reply Bye, but pretend we did.
		p.caller = &unsetCaller
	}
	if !p.snd.empty() || !p.rcv.empty() {
		log.Print("Buffers not empty. Check file *-secret on puck and broker!!!")
		// discard any pending packets
		p.snd.r = p.snd.w
		p.rcv.r = p.rcv.w
	}
	p.WritePktCnt()
	return
}

func (p *PuckFS) WritePktCnt() {
	f, err := os.OpenFile(p.sec.PktCnt, os.O_RDWR, 0600)
	if err != nil {
		log.Printf("%d %d\n", p.snd.w, p.rcv.w)
		log.Fatal(err)
	}
	fmt.Fprintf(f, "%d %d\n", p.snd.w, p.rcv.w)
	err = f.Close()
	if err != nil {
		log.Printf("%d %d\n", p.snd.w, p.rcv.w)
		log.Fatal(err)
	}
}

func Keygen() string {
	// TODO	Provide rekeying using ML-KEM xor'd with old secret and an optional hashed passphrase.
	r := make([]byte, chacha20poly1305.KeySize) // 32
	rand.Read(r)
	return "chacha20poly1305:" + base64.StdEncoding.EncodeToString(r)
}

func expect(wanted, got uint16, data []byte) (err error) {
	if wanted == got {
		return nil
	}
	if got == cError {
		return fmt.Errorf("server declined call %s", data)
	}
	return fmt.Errorf("server returned %x, we expected %x", got, wanted)
}

// myFileInfo implements fs.FileInfo
type myFileInfo struct {
	name  string
	size  int64
	mtime int64
	isdir bool
}

func (fi myFileInfo) Name() string {
	return fi.name
}

func (fi myFileInfo) Size() int64 {
	return fi.size
}

func (fi myFileInfo) Mode() fs.FileMode {
	bits := fs.FileMode(0600)
	if fi.isdir {
		bits |= fs.ModeDir
	}
	return bits
}

func (fi myFileInfo) ModTime() time.Time {
	return time.Unix(fi.mtime, 0)
}

func (fi myFileInfo) IsDir() bool {
	return fi.isdir
}

func (fi myFileInfo) Sys() any {
	return nil
}
