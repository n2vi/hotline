// Copyright © 2020 Eric Grosse n2vi.com/0BSD

package main

import (
	"encoding/binary"
	"errors"
	"log"
	"math/bits"
)

var BadVerify = errors.New("ASCON decrypt verify failed! Do not use any partial results.")

// asconEncrypt implements the authenticated cipher ASCON80pq.
// len(cleartext) == len(plaintext) + 16
// Last 16 bytes of ciphertext are the authentication tag.
// len(key) = 20
// "associated data" len(ad) = 0 for our purposes, but needed for testing
// ciphertext[0:16] == plaintext[0:16] is the public, unique nonce.
// Any errors are fatal.
// The algorithm is described at https://ascon.iaik.tugraz.at.
//
func asconEncrypt(ciphertext, plaintext, ad, key []byte) {
	if len(plaintext) < 16 || len(key) != 20 {
		log.Fatal("recheck lengths of nonce and key")
	}
	if len(ciphertext) != len(plaintext)+16 {
		log.Fatal("recheck length of ciphertext")
	}
	K0 := uint64(binary.BigEndian.Uint32(key[0:4]))
	K1 := binary.BigEndian.Uint64(key[4:12])
	K2 := binary.BigEndian.Uint64(key[12:20])
	N0 := binary.BigEndian.Uint64(plaintext[0:8])
	N1 := binary.BigEndian.Uint64(plaintext[8:16])
	IV := uint64(0xa0400c06) << 32
	copy(ciphertext[0:16], plaintext[0:16])
	plaintext = plaintext[16:]
	ciphertext = ciphertext[16:]

	var s state
	s.x0 = IV | K0
	s.x1 = K1
	s.x2 = K2
	s.x3 = N0
	s.x4 = N1
	s = perm12(s)
	s.x2 ^= K0
	s.x3 ^= K1
	s.x4 ^= K2
	if len(ad) > 0 {
		for len(ad) >= 8 {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s = perm6(s)
			ad = ad[8:]
		}
		s.x0 ^= bigendianUint64(ad[0:])
		s.x0 ^= uint64(0x80) << (56 - 8*len(ad))
		s = perm6(s)
	}
	s.x4 ^= 1

	for len(plaintext) >= 8 {
		s.x0 ^= binary.BigEndian.Uint64(plaintext[:8])
		plaintext = plaintext[8:]
		binary.BigEndian.PutUint64(ciphertext[:8], s.x0)
		ciphertext = ciphertext[8:]
		s = perm6(s)
	}
	s.x0 ^= bigendianUint64(plaintext)
	s.x0 ^= uint64(0x80) << (56 - 8*len(plaintext))
	bigendianPutUint64(ciphertext, s.x0, len(plaintext))
	ciphertext = ciphertext[len(plaintext):]

	s.x1 ^= K0<<32 | K1>>32
	s.x2 ^= K1<<32 | K2>>32
	s.x3 ^= K2 << 32
	s = perm12(s)
	s.x3 ^= K1
	s.x4 ^= K2
	binary.BigEndian.PutUint64(ciphertext[:8], s.x3)
	binary.BigEndian.PutUint64(ciphertext[8:], s.x4)
}

func asconDecrypt(plaintext, ciphertext, ad, key []byte) (err error) {
	if len(key) != 20 {
		log.Fatal("recheck length of key")
	}
	if len(ciphertext) != len(plaintext)+16 {
		log.Fatal("recheck length of plaintext")
	}
	plaintext0 := plaintext
	copy(plaintext, ciphertext[:16])
	plaintext = plaintext[16:]

	K0 := uint64(binary.BigEndian.Uint32(key[0:4]))
	K1 := binary.BigEndian.Uint64(key[4:12])
	K2 := binary.BigEndian.Uint64(key[12:20])
	N0 := binary.BigEndian.Uint64(ciphertext[0:8])
	N1 := binary.BigEndian.Uint64(ciphertext[8:16])
	IV := uint64(0xa0400c06) << 32
	ciphertext = ciphertext[16:]

	// Initialization phase
	var s state
	s.x0 = IV | K0
	s.x1 = K1
	s.x2 = K2
	s.x3 = N0
	s.x4 = N1
	s = perm12(s)
	s.x2 ^= K0
	s.x3 ^= K1
	s.x4 ^= K2
	if len(ad) > 0 {
		for len(ad) >= 8 {
			s.x0 ^= binary.BigEndian.Uint64(ad[0:8])
			s = perm6(s)
			ad = ad[8:]
		}
		s.x0 ^= bigendianUint64(ad[0:])
		s.x0 ^= uint64(0x80) << (56 - 8*len(ad))
		s = perm6(s)
	}
	s.x4 ^= 1

	for len(ciphertext) >= 24 {
		c0 := binary.BigEndian.Uint64(ciphertext[:8])
		binary.BigEndian.PutUint64(plaintext[:8], s.x0^c0)
		s.x0 = c0
		plaintext = plaintext[8:]
		s = perm6(s)
		ciphertext = ciphertext[8:]
	}
	nc := len(ciphertext) - 16
	// TODO test case of nc==0
	c0 := bigendianUint64(ciphertext[:nc])
	tag0 := binary.BigEndian.Uint64(ciphertext[nc : nc+8])
	tag1 := binary.BigEndian.Uint64(ciphertext[nc+8 : nc+16])
	bigendianPutUint64(plaintext, s.x0^c0, nc)
	s.x0 &= uint64(0xffffffffffffffff) >> (8 * nc)
	s.x0 |= c0
	s.x0 ^= uint64(0x80) << (56 - 8*nc)

	// Finalization phase
	s.x1 ^= K0<<32 | K1>>32
	s.x2 ^= K1<<32 | K2>>32
	s.x3 ^= K2 << 32
	s = perm12(s)
	s.x3 ^= K1
	s.x4 ^= K2
	if tag0 != s.x3 || tag1 != s.x4 {
		for j := range plaintext0 {
			plaintext0[j] = 0
		}
		return BadVerify
	}
	return nil

}

type state struct{ x0, x1, x2, x3, x4 uint64 }

func round(C uint8, s state) state {
	var t state
	// addition of round constant
	s.x2 ^= uint64(C)
	// substitution layer S-box
	s.x0 ^= s.x4
	s.x4 ^= s.x3
	s.x2 ^= s.x1
	t.x0 = ^s.x0
	t.x1 = ^s.x1
	t.x2 = ^s.x2
	t.x3 = ^s.x3
	t.x4 = ^s.x4
	t.x0 &= s.x1
	t.x1 &= s.x2
	t.x2 &= s.x3
	t.x3 &= s.x4
	t.x4 &= s.x0
	s.x0 ^= t.x1
	s.x1 ^= t.x2
	s.x2 ^= t.x3
	s.x3 ^= t.x4
	s.x4 ^= t.x0
	s.x1 ^= s.x0
	s.x0 ^= s.x4
	s.x3 ^= s.x2
	s.x2 = ^s.x2
	// linear diffusion layer P-box
	s.x0 ^= bits.RotateLeft64(s.x0, -19) ^ bits.RotateLeft64(s.x0, -28)
	s.x1 ^= bits.RotateLeft64(s.x1, -61) ^ bits.RotateLeft64(s.x1, -39)
	s.x2 ^= bits.RotateLeft64(s.x2, -1) ^ bits.RotateLeft64(s.x2, -6)
	s.x3 ^= bits.RotateLeft64(s.x3, -10) ^ bits.RotateLeft64(s.x3, -17)
	s.x4 ^= bits.RotateLeft64(s.x4, -7) ^ bits.RotateLeft64(s.x4, -41)
	return s
}

func perm12(s state) state {
	s = round(0xf0, s)
	s = round(0xe1, s)
	s = round(0xd2, s)
	s = round(0xc3, s)
	s = round(0xb4, s)
	s = round(0xa5, s)
	s = round(0x96, s)
	s = round(0x87, s)
	s = round(0x78, s)
	s = round(0x69, s)
	s = round(0x5a, s)
	s = round(0x4b, s)
	return s
}

func perm6(s state) state {
	s = round(0x96, s)
	s = round(0x87, s)
	s = round(0x78, s)
	s = round(0x69, s)
	s = round(0x5a, s)
	s = round(0x4b, s)
	return s
}

// Function bigendianUint64 is similar to binary.BigEndian.Uint64,
// but allows partial or empty input.
func bigendianUint64(b []byte) uint64 {
	x := uint64(0)
	n := len(b)
	for i := 0; i < n; i++ {
		x |= uint64(b[i]) << (56 - 8*uint64(i))
	}
	return x
}

func bigendianPutUint64(b []byte, x uint64, n int) {
	for i := 0; i < n; i++ {
		b[i] = uint8(x >> (56 - 8*i))
	}
}
