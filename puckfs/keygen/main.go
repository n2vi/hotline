// Copyright © 2020,2025 Eric Grosse n2vi.com/0BSD

/*
	Command keygen produces new puck-secret, broker-secret files.
*/

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

type secretFile struct {
	DEBUG          bool
	MTU            int    // largest payload size we will send
	KeyID          uint32 // unique to (client,server)-pair
	Secret         string // "chacha20poly1305:"+base64.StdEncoding.EncodeToString(secret)
	ServerAddr     string // host:port on network "udp"
}

func main() {
	var s secretFile
	s.MTU = 1200
	sec := make([]byte, 4+chacha20poly1305.KeySize)
	rand.Read(sec)
	sec[0] = 3 // puckfsVERSION
	keyid := binary.BigEndian.Uint32(sec[:4])
	s.KeyID = keyid & 0xfffffffe // puck has low bit 0
	sec = sec[4:]
	s.Secret = "chacha20poly1305:"+base64.StdEncoding.EncodeToString(sec)
	s.ServerAddr = "h.n2vi.net:9901"

	data, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("puckfs-client:")
	fmt.Println(string(data))

	s.KeyID = keyid | 1
	s.ServerAddr = ":9901"
	data, err = json.MarshalIndent(s, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("puckfs-server")
	fmt.Println(string(data))
}

