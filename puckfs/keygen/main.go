// Copyright © 2020-2026 Eric Grosse n2vi.com/0BSD

/*
	Command keygen produces new broker-secret file and prints cmdline
	as pronounceable words to create a matching puck-secret file.
*/

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

type secretFile struct {
	DEBUG      bool
	MTU        int    // largest payload size we will send
	KeyID      uint32 // unique to (client,server)-pair
	Secret     string // "chacha20poly1305:"+base64.StdEncoding.EncodeToString(secret)
	ServerAddr string // host:port on network "udp"
}

func main() {
	var s secretFile
	s.MTU = 1200
	sec := make([]byte, 4+chacha20poly1305.KeySize) // 36
	narg := len(os.Args)
	switch narg {
	case 1:
		rand.Read(sec)
		sec[0] = 3 // puckfsVERSION
		fmt.Fprintf(os.Stderr, "./keygen")
		for i := 1; i < 19; i++ {
			u16 := uint16(sec[2*i-2])<<8 | uint16(sec[2*i-1])
			fmt.Fprintf(os.Stderr, " %s", Encode(u16))
		}
		fmt.Fprintf(os.Stderr, " > puck-secret\n")
	case 19: // 1 + 18 proquints
		for i := 1; i < 19; i++ {
			u16 := Decode([]byte(os.Args[i]))
			sec[2*i-2] = byte(u16>>8)
			sec[2*i-1] = byte(u16&0xff)
		}
	default:
		log.Fatalf("expected 0 or 18 args, got %d", narg-1)
	}
	keyid := binary.BigEndian.Uint32(sec[:4])
	s.KeyID = keyid & 0xfffffffe // puck has low bit 0
	if narg == 1 {
		s.KeyID |= 1 // broker has low bit 1
	}
	sec = sec[4:]
	s.Secret = "chacha20poly1305:" + base64.StdEncoding.EncodeToString(sec)
	s.ServerAddr = "h.n2vi.net:14400"

	data, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(data))
}



// from upspin.io/key/proquint.go
// See http://arxiv.org/html/0901.4016.
var (
	cons  = []byte("bdfghjklmnprstvz")
	vowel = []byte("aiou")
)

// Encode returns a five-letter word representing a uint16.
func Encode(x uint16) (s []byte) {
	cons3 := x & 0x0f
	x >>= 4
	vow2 := x & 0x03
	x >>= 2
	cons2 := x & 0x0f
	x >>= 4
	vow1 := x & 0x03
	x >>= 2
	cons1 := x & 0x0f
	s = make([]byte, 5)
	s[0] = cons[cons1]
	s[1] = vowel[vow1]
	s[2] = cons[cons2]
	s[3] = vowel[vow2]
	s[4] = cons[cons3]
	return
}

// Decode parses a five-letter word, returning a uint16.
func Decode(s []byte) (x uint16) {
	cons1 := uint16(bytes.IndexByte(cons, s[0]))
	vow1 := uint16(bytes.IndexByte(vowel, s[1]))
	cons2 := uint16(bytes.IndexByte(cons, s[2]))
	vow2 := uint16(bytes.IndexByte(vowel, s[3]))
	cons3 := uint16(bytes.IndexByte(cons, s[4]))
	return (((cons1<<2|vow1)<<4|cons2)<<2|vow2)<<4 | cons3
}
