// Copyright (c) 2020-2026 Eric Grosse n2vi.com/0BSD

/*
This small test aims to simplify porting the code by
providing a quick check that crypto libraries are compatible.
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestMain(mn *testing.M) {
	// simulate reading PrincipalsDB
	db.Me = 1440123456
	db.Peers = make([]*Principal, 1)
	mine := sha256.Sum256([]byte("abracadabra"))
	theirs := sha256.Sum256([]byte("opensesame"))
	db.Peers[0] = & Principal {
		Id: 1446543210,
		Nick: "POTUS",
		My: Key{2345, 2, mine[:]},
		Their: Key{6789, 2, theirs[:]},
	}
	np := len(db.Peers)
	nick = make(map[ID]string, np+1)
	nickP = make(map[string]*Principal, np)
	keyP = make(map[uint32]*Principal, np)
	nick[db.Me] = "me"
	nick[db.Peers[0].Id] = db.Peers[0].Nick
	nickP[db.Peers[0].Nick] = db.Peers[0]
	keyP[db.Peers[0].Their.KeyID] = db.Peers[0]
	// pfs is left nil, which tells puck.go not to call puckfs/

	cryptotest = make([]byte, 200)
	os.Exit(mn.Run())
}

func TestSeal(t *testing.T) {
	nicks := []string{"POTUS"}
	_, err := sendTo(nicks, "доверяй, но проверяй", "UTF8")
	if err != nil {
		t.Fatalf("sendTo: %s", err)
	}
	expect, err := hex.DecodeString("000009296162636465666768696a6b6c6d6e6f7071727374757677780fc634905d6c655fad3140d1877553a9e9fba87e10f95d650043998aad09b91eb699a1ae4a5d755fdf93a3688eb2868b6f657aed1bd0b919fc306f0fd2d0e1bd9fb665979db4691584ea4114d275b9")
	if err != nil {
		t.Fatalf("expect hex: %s", err)
	}
	if !bytes.Equal(cryptotest, expect) {
		t.Errorf("TestSeal = %x, want %x", cryptotest, expect)
	}
}
