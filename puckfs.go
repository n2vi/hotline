// Copyright © 2020 Eric Grosse n2vi.com/0BSD

/*
	Package puckfs provides a primitive network file server and client,
	atop Go-Back-N retransmission and transport encryption, atop udp.
*/
package main // will become github.com/n2vi/puckfs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"path"
	"time"
)

// SecretFile describes the json secretfile on local disk, mode 0600.
type secretFile struct {
	DEBUG          bool
	SndW, RcvW     uint32 // packet sequence numbers this side sent or is awaiting
	SndAck, RcvAck uint32 // high water marks
	ServerAddr     string // host:port on network "udp"
	MTU            uint32    // conservative upper bound on msg that does not fragment
	KeyID          uint32 // unique to (client,server)-pair
	Secret         string // "ascon80pq:"+base64.StdEncoding.EncodeToString(secret)
	secretfile     string // filename such as "clientdemo"
}

// PuckFS holds the parsed secretFile and ring buffers for the network connection.
type PuckFS struct {
	snd, rcv       ringBuf // packets unack'd, undeliv'd
	sndAck, rcvAck uint32  // high water marks
	caller         *net.UDPAddr
	udp            *net.UDPConn // handle for reading and writing packets
	mtu            uint32
	keyID          uint32
	secret         []byte // base64.StdEncoding.DecodeString(Secret[10:])
	sec            *secretFile
}

// Auxiliary routing information in PuckFS is currently just caller and mtu.
//	in a client, caller=nil;
//	in a fresh server instance, caller=&unsetCaller;
//	in an active server, caller=address of client.
// Fitting with rest of the design, mtu is manually set to a conservative fragmentation size.

// Dial calls the puckfs server and checks clocks for consistency.
func Dial(secretfile string) (p *PuckFS, err error) {
	var addr *net.UDPAddr
	if addr, p, err = readSecretFile(secretfile); err != nil {
		return p, err
	}
	if p.keyID&1 != 0 { // can't happen except by catastrophic blunder
		log.Fatalf("wanted keyID for client, got server in %s", secretfile)
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
	return
}

// ReadFile fetches file contents, similar to ioutil.
func (p *PuckFS) ReadFile(path string) (data []byte, err error) {
	cmd, data := p.clientRPC(cReadfile, []byte(path))
	return data, expect(cReadfile, cmd, data)
}

// WriteFile writes file contents, similar to ioutil
// but without permission modes since puckfs is a single-user filesystem.
func (p *PuckFS) WriteFile(path string, data []byte) (err error) {
	mess := []byte(path)
	if j := bytes.IndexByte(mess, 0); j >= 0 {
		return fmt.Errorf("zero byte not allowed in path names %d", j)
	}
	mess = append(mess, 0)
	mess = append(mess, data...)
	cmd, mess := p.clientRPC(cWritefile, mess)
	return expect(cWritefile, cmd, mess)
}

// TimeToRekey is an error indication that the secretFile needs updating.
var TimeToRekey = errors.New("puckfs: secret is becoming stale; time to rekey!")

// Close saves sequence numbers and returns TimeToRekey if secret is due for refresh.
func (p *PuckFS) Close() (err error) {
	p.sendAck(cBye)
	writeSecretFile(p)
	err = p.udp.Close()
	if (p.snd.w+p.rcv.w)*uint32(p.mtu) >= maxKeyCount {
		err = TimeToRekey // This is the more critical error to return.
	}
	return
}

// ------ The client API ends here. For server API, see functions at bottom of file. ------
// Read the "Hotline Networking" doc first.
// Here is a sketch of packets as encoded on the wire:
// (~40 bytes) ether, IP, UDP headers which we ignore here.
// (16) nonce  =  (4) keyID, (4) packet sequence number, (8) random
// (2) cmd, ASCON-enciphered
// (n) data, ASCON-enciphered
// (16) authentication tag; if ASCON-decrypt fails, packet is discarded.
// cmd == Partial means data is to be concatenated with the following packet.
// We do not intend to support any version negotiation.
// Possibly we should use pure text rather than a binary format like this, but
// don't want protocol compilers, JIT, reflection, or large parsers. Even JSON on
// the network is a poor spec, as studies show conflicting implementations.
// Someday clients may be mobile, so perhaps best identified by keyID, with
// IP addr regarded as a hint of where to reply. But leave that for later.
//
// The first byte of keyID (which is the high order byte since we adopt
// BigEndian network byte order) is also used as a protocol version number
// to ensure that anytime a protocol change is made, all systems update
// keys as well as software. A client keyID has low bit zero and the matching
// server keyID has low bit one, ensuring that keyID+seqno is unique
// and preventing packet replay confusion between client and server.
// Client and server are actually using the same encryption key.
//
// Packets with cmd < Partial are ephemeral, not added to ring buffers
// and hence no automatic retransmission if lost, but still authenticated
// so we do need monotonic seqno for them as well and distinct from
// normal commands, so add ackOffset before stuffing into packet.
// These ack values are the sender's rcv.w, which is the packet
// sequence number the sender is awaiting, one higher than the number
// most recently accepted. That value is 0 if nothing received yet.
//
// Packet sequence numbers start at 0 and increment by 1, even across
// program restarts. Yes, this implies we need to take great care saving.
// It is not a catastrophic failure if we miss, but let's try hard not to.
// There is not enough cryptographic research yet to say how often we
// need to rekey with ascon80pq. We conjecture that limiting the number
// of encrypted bytes to maxKeyCount is safe. This leaves plenty of
// room so sequence numbers never collide.
//
// We assume a reasonably low latency, low error network. The timeouts in
// readPacket() are intended to recover from rare glitches. If they fire
// frequently, it is likely time to redesign.

const (
	cAck uint16 = iota
	cQAck
	cBye
	cPartial
	cHello
	cReadfile
	cWritefile
	cReaddir
	cRemove
	cChtime
	cError
)
const (
	puckfsVERSION = 0
	maxKeyCount   = 0x20000000
	ackOffset     = 0x40000000
)

var unsetCaller net.UDPAddr
var errBye = errors.New("Bye")       // treat similarly to network disconnect
var sendTimeout = time.Duration(5e9) // 5 sec
var noDeadline time.Time

// ClientRPC sends scmd+req and then reads rcmd+resp.
// Most errors are returned in rcmd, but catastrophic errors are log.Fatal.
// p.snd and p.rcv are empty before and after; no overlap of RPCs.
func (p *PuckFS) clientRPC(scmd uint16, req []byte) (rcmd uint16, resp []byte) {
	var err error
	if err = p.sendCmd(scmd, req); err != nil {
		return cError, []byte(err.Error())
	}
	if rcmd, resp, err = p.readCmd(); err != nil {
		return cError, []byte(err.Error())
	}
	p.awaitEmpty()
	if p.sec.DEBUG {
		log.Printf("-------------")
	}
	return
}

func expect(wanted, got uint16, data []byte) (err error) {
	if wanted == got {
		return nil
	}
	if got == cError {
		return fmt.Errorf("server declined call %v", data)
	}
	return fmt.Errorf("server returned %x, we expected %x", got, wanted)
}

// Send a command, if necessary as multiple packets.
func (p *PuckFS) sendCmd(cmd uint16, data []byte) (err error) {
	if p.sec.DEBUG {
		log.Printf("sendCmd %d", cmd)
	}
	for {
		for p.snd.full() {
			if err = p.readPacket(); err != nil {
				return
			}
		}
		var plaintext []byte
		plaintext, data = p.marshal(cmd, data)
		ciphertext := make([]byte, len(plaintext)+16) // add room for auth tag
		asconEncrypt(ciphertext, plaintext, []byte{}, p.secret)
		p.write(ciphertext)
		if p.sec.DEBUG {
			log.Printf(" [%d]", p.snd.w)
		}
		if ok := p.snd.push(ciphertext, time.Now().Add(sendTimeout)); !ok {
			log.Fatal("send ring buffer overflow") // can't happen; we checked above
		}
		if len(data) == 0 {
			break
		}
	}
	return
}

// Read an RPC request or response.
func (p *PuckFS) readCmd() (cmd uint16, r []byte, err error) {
	r = make([]byte, 0)
	var data []byte
	var ok bool
	var packetCount int
	for cmd = cPartial; cmd == cPartial; {
		for p.rcv.empty() {
			if err = p.readPacket(); err != nil {
				return
			}
		}
		if data, ok = p.rcv.pop(); !ok {
			log.Fatal("can't happen; pop fail on nonempty ring?")
		}
		if cmd = binary.BigEndian.Uint16(data[:2]); cmd < cPartial {
			log.Fatal("can't happen: no acks in ring buffer")
		}
		r = append(r, data[2:]...)
		packetCount++
		if packetCount%(ringN/2) == 0 {
			p.sendAck(cAck)
		}
	}
	if packetCount%(ringN/2) != 0 { // avoid duplicate Ack
		p.sendAck(cAck)
	}
	if p.sec.DEBUG {
		log.Printf("readCmd %d", cmd)
	}
	return
}

// SendAck signals progress using a separate packet.
func (p *PuckFS) sendAck(cmd uint16) {
	if p.caller == &unsetCaller {
		return // If server hasn't seen an authenticated packet yet, then no place to send to.
	}
	if p.sec.DEBUG {
		log.Printf("sendAck [%d] %d %x", p.sndAck+1, cmd, p.rcv.w)
	}
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, p.rcv.w) // packet seqno we are awaiting
	plaintext, msg := p.marshal(cmd, msg)
	if len(msg) != 0 {
		log.Fatalf("can't happen; acks are too short to fragment %d %v", cmd, msg)
	}
	ciphertext := make([]byte, len(plaintext)+16)
	asconEncrypt(ciphertext, plaintext, []byte{}, p.secret)
	p.write(ciphertext)
}

func (p *PuckFS) awaitEmpty() {
	var err error
	for !p.snd.empty() {
		if err = p.readPacket(); err != nil {
			log.Printf("awaitEmpty %s", err)
			return
		}
	}
	if !p.rcv.empty() {
		log.Fatal("received full cmd and then more")
	}
}

// Read a packet from network with decryption and initial processing:
// If Ack, QAck or Bye, handle and return.
// If partial or complete, push cmd+data onto p.rcv and return.
// If timeout, keep trying forever.
func (p *PuckFS) readPacket() (err error) {
	var caller *net.UDPAddr
	var seqno uint32
	var cmd uint16
	ciphertext := make([]byte, p.mtu+32) // last 16 bytes is the auth tag
	plaintext := make([]byte, p.mtu+16)
	p.udp.SetReadDeadline(time.Now().Add(3 * time.Second))
	for { // keep reading and QAcking until we get a valid packet
		if ciphertext, caller, err = p.read(ciphertext); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				p.sendAck(cQAck)
				p.udp.SetReadDeadline(time.Now().Add(15 * time.Second))
				continue
			}
			p.udp.SetReadDeadline(noDeadline)
			return // some kind of network error; give up
		}
		if binary.BigEndian.Uint32(ciphertext[:4]) != p.keyID^1 {
			continue // Ignore packets with wrong keyID.
		}
		n := len(ciphertext)
		plaintext = plaintext[:n-16]
		if err = asconDecrypt(plaintext, ciphertext, []byte{}, p.secret); err != nil {
			continue // Ignore corrupted or forged packets.
		}
		break
	}
	p.udp.SetReadDeadline(noDeadline)
	seqno = binary.BigEndian.Uint32(ciphertext[4:8])
	cmd = binary.BigEndian.Uint16(plaintext[16:18])
	p.callerSet(cmd, caller)
	if cmd < cPartial { // Immediately process cAck, cQAck, cBye from other side.
		if seqno < ackOffset {
			log.Fatal("can't happen; acks have high seqno")
		}
		seqno = seqno - ackOffset
		if seqno <= p.rcvAck {
			return // Ignore replay of acks.
		} else {
			p.rcvAck = seqno
		}
		ack := binary.BigEndian.Uint32(plaintext[18:22])
		if p.sec.DEBUG {
			log.Printf("readAck [%d] %d %d", seqno, cmd, ack)
		}
		if ack > p.snd.w {
			log.Fatalf("got ack %d for packet never sent; wanted at most %d", ack, p.snd.w)
		}
		for ack > p.snd.r { // Release acknowledged packets.
			if _, ok := p.snd.pop(); !ok {
				log.Fatalf("can't happen %d %d %d", ack, p.snd.r, p.snd.w)
			}
		}
		if cmd == cQAck {
			p.sendAck(cAck)
		} else if cmd == cBye { // A motion to adjourn is always in order.
			hangup(p)
			return errBye
		}
		// Done processing acks. Take the opportunity to check retransmission timers.
		p.retransmit()
		return
	}
	if seqno != p.rcv.w { // Ignore this out-of-sequence packet.
		// TODO Introduce a command asking to retransmit? Measure first.
		return
	}
	if p.rcv.full() { // Ignore if we don't have room to save.
		// Shouldn't happen; other side should wait for acks before sending this many.
		return
	}
	p.rcv.push(plaintext[16:], noDeadline)
	return
}

// Check if oldest retransmit deadline has expired and, if so, resend.
func (p *PuckFS) retransmit() {
	old, t, expired := p.snd.timeout()
	if expired {
		if p.sec.DEBUG {
			log.Printf("retransmit [%d]", p.snd.r)
		}
		p.write(old)
		*t = time.Now().Add(sendTimeout)
	}
}

// Read a packet from network.
func (p *PuckFS) read(ciphertext []byte) ([]byte, *net.UDPAddr, error) {
	var err error
	var n int
	var caller *net.UDPAddr
	ciphertext = ciphertext[:p.mtu+32] // undo any previous trimming
	if p.caller == nil {
		n, err = p.udp.Read(ciphertext)
	} else {
		n, caller, err = p.udp.ReadFromUDP(ciphertext)
	}
	ciphertext = ciphertext[:n]
	if err != nil {
		return ciphertext, caller, err
	}
	if n < 32 {
		log.Fatalf("short packet with no err (%d) %v", n, ciphertext)
	}
	return ciphertext, caller, nil
}

// Write a packet to the network.
func (p *PuckFS) write(ciphertext []byte) {
	var err error
	var nw int
	if p.caller == nil {
		nw, err = p.udp.Write(ciphertext)
	} else {
		nw, err = p.udp.WriteToUDP(ciphertext, p.caller)
	}
	if nw != len(ciphertext) {
		log.Fatalf("short write; got %d, wanted %d", nw, len(ciphertext))
	}
	if err != nil {
		log.Fatalf("udp.Write %s", err)
		// TODO Perhaps this doesn't have to be fatal until several failures?
	}
}

// If server receives a validated cHello, remember caller's address.
func (p *PuckFS) callerSet(cmd uint16, caller *net.UDPAddr) {
	if p.caller == nil {
		return // client already knows server's address
	}
	if cmd != cHello {
		return // callerSet is only relevant for first packet of connection from client.
	}
	if p.caller == &unsetCaller {
		p.caller = caller
	} else if p.caller == caller {
		log.Fatal("Perhaps our earlier cHello reply to the client was lost?")
	} else {
		log.Printf("cHello while still listening for a client that didn't Bye.")
		hangup(p) // assume the old client crashed and let's try to proceed...
		p.caller = caller
	}
}

// Copy (part of) msg into plaintext, prefixed by 18 bytes of nonce+cmd.
func (p *PuckFS) marshal(cmd uint16, msg []byte) (plaintext, unread []byte) {
	plaintext = appendUint32(make([]byte, 0, p.mtu+16), p.keyID)
	seqno := p.snd.w // this packet seqno
	if cmd < cPartial {
		p.sndAck++
		if p.sndAck > maxKeyCount {
			log.Fatal("Implausibly large number of acks.")
		}
		seqno = p.sndAck + ackOffset
	}
	plaintext = appendUint32(plaintext, seqno)
	var random [8]byte
	nn, err := rand.Read(random[:])
	if nn != 8 || err != nil {
		// First half of nonce is unique, so not truly fatal even if random part isn't random.
		log.Fatalf("crypto rand fail: %d %s", nn, err)
	}
	plaintext = append(plaintext, random[:]...) // completes the 16 byte nonce
	n := int(p.mtu - 2)
	if len(msg) > n {
		cmd = cPartial
	} else {
		n = len(msg)
	}
	plaintext = appendUint16(plaintext, cmd)
	plaintext = append(plaintext, msg[:n]...)
	return plaintext, msg[n:]
}

func readSecretFile(secretfile string) (addr *net.UDPAddr, p *PuckFS, err error) {
	var data []byte
	if data, err = ioutil.ReadFile(secretfile); err != nil {
		log.Fatalf("unable to read secretfile %s: %v", secretfile, err)
	}
	sec := secretFile{}
	if err = json.Unmarshal(data, &sec); err != nil {
		log.Fatalf("%v", err)
	}
	if (sec.KeyID >> 24) != puckfsVERSION {
		log.Fatalf("%s is version %d, wanted %d", sec.KeyID>>24, puckfsVERSION)
	}
	if sec.Secret[:10] != "ascon80pq:" {
		log.Fatal("unsupported key type in secretfile")
	}
	if (sec.SndW+sec.RcvW)*sec.MTU >= ackOffset {
		log.Fatal("way past time to rekey; you were warned")
	}
	if addr, err = net.ResolveUDPAddr("udp", sec.ServerAddr); err != nil {
		log.Fatalf("unable to resolve udp %s %v", sec.ServerAddr, err)
	}
	sec.secretfile = secretfile
	snd := ringBuf{sec.SndW, sec.SndW, [ringN][]byte{}, [ringN]time.Time{}}
	rcv := ringBuf{sec.RcvW, sec.RcvW, [ringN][]byte{}, [ringN]time.Time{}}
	secret, err := base64.StdEncoding.DecodeString(sec.Secret[10:])
	if err != nil {
		log.Fatalf("%v", err)
	}
	puckfs := PuckFS{snd, rcv, sec.SndAck, sec.RcvAck, nil, nil, sec.MTU, sec.KeyID, secret, &sec}
	return addr, &puckfs, nil
}

func writeSecretFile(p *PuckFS) {
	// TODO Rekey should also reset snd.w, rcv.w, and ackCounter.
	var data []byte
	var err error
	if p.snd.r != p.snd.w || p.rcv.r != p.rcv.w {
		log.Printf("snd.r,w=%d,%d rcv.r,w=%d,%d snd,rcvAck=%d,%d",
			p.snd.r, p.snd.w, p.rcv.r, p.rcv.w, p.sndAck, p.rcvAck)
	}
	p.sec.SndW = p.snd.w
	p.sec.RcvW = p.rcv.w
	p.sec.SndAck = p.sndAck
	p.sec.RcvAck = p.rcvAck
	if data, err = json.MarshalIndent(p.sec, "", "\t"); err != nil {
		// can't happen?
		log.Fatalf("%v", err)
	}
	if err = ioutil.WriteFile(p.sec.secretfile, data, 0600); err != nil {
		log.Printf("snd.r,w=%d,%d rcv.r,w=%d,%d snd,rcvAck=%d,%d",
			p.snd.r, p.snd.w, p.rcv.r, p.rcv.w, p.sndAck, p.rcvAck)
		log.Fatalf("%v", err)
	}
	return
}

// The append/consume functions are from go/src/crypto/sha1/sha1.go.

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func appendUint16(b []byte, x uint16) []byte {
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

func consumeUint16(b []byte) ([]byte, uint16) {
	_ = b[1]
	x := uint16(b[1]) | uint16(b[0])<<8
	return b[2:], x
}

// We are using simple Go-Back-N retransmission with no out-of-order packet handling.
// So we can use ring buffers for keeping track of unacknowleged packets and for
// keeping track of packets that have been read from the network but not yet processed.

const ringN = 16

type ringBuf struct {
	r, w uint32 // rekey long before these overflow
	p    [ringN][]byte
	t    [ringN]time.Time // timeout deadline
}

func (ringBuf *ringBuf) empty() bool {
	return ringBuf.r == ringBuf.w
}

func (ringBuf *ringBuf) full() bool {
	return ringBuf.w-ringBuf.r == ringN
}

func (ringBuf *ringBuf) push(val []byte, t time.Time) (ok bool) {
	if ringBuf.full() {
		return false
	}
	j := ringBuf.w & (ringN - 1)
	ringBuf.p[j] = val
	ringBuf.t[j] = t
	ringBuf.w++
	return true
}

func (ringBuf *ringBuf) pop() (val []byte, ok bool) {
	if ringBuf.empty() {
		return nil, false
	}
	val = ringBuf.p[ringBuf.r&(ringN-1)]
	ringBuf.r++
	return val, true
}

// Return data, timeout slot, and status for oldest packet in ringBuf.
func (ringBuf *ringBuf) timeout() (data []byte, t *time.Time, expired bool) {
	if ringBuf.empty() {
		return nil, nil, false
	}
	now := time.Now()
	j := ringBuf.r & (ringN - 1)
	return ringBuf.p[j], &ringBuf.t[j], now.After(ringBuf.t[j])
}

// ------ The server API starts here. ------

// Server assumes it will hear on a fixed port from a single client with a predetermined secret.
func Listen(secretfile string) (p *PuckFS, err error) {
	var addr *net.UDPAddr
	if addr, p, err = readSecretFile(secretfile); err != nil {
		log.Fatalf("%v", err)
	}
	if p.keyID&1 != 1 { // can't happen except by catastrophic blunder
		log.Fatalf("wanted keyID for server, got client")
	}
	if p.udp, err = net.ListenUDP("udp", addr); err != nil {
		log.Fatalf("%v", err)
	}
	p.caller = &unsetCaller
	return
}

// HandleRPC is the server main loop for receiving packets and responding.
// There is a single client which is single threaded, so we can handle requests sychronously.
func (p *PuckFS) HandleRPC() {
	errCount := 0
	for {
		cmd, req, err := p.readCmd()
		if err != nil {
			if errCount > 20 {
				log.Printf("%v\ntoo many errors; giving up", err)
				hangup(p)
				return
			}
			log.Printf("will retry; readCmd err %v", err)
			errCount++
			continue
		}
		resp := []byte{}
		switch cmd {
		case cHello:
			now := time.Now().UTC()
			there, err := time.Parse(time.RFC3339, string(req))
			delta := now.Sub(there).Seconds()
			if math.Abs(delta) > 30. {
				reject(p, cHello, "computer clocks can surely be better calibrated than 30sec?")
				continue
			}
			if math.Abs(delta) > 5. {
				resp = []byte(fmt.Sprintf("%.0f", delta))
			}
			if err = p.sendCmd(cHello, resp); err != nil {
				log.Printf("cHello err %v", err)
				hangup(p)
				return
			}
		case cReadfile:
			file := path.Clean(string(req))
			if len(file) < 1 || file[0] == '/' {
				reject(p, cError, "bad filename")
				continue
			}
			if resp, err = ioutil.ReadFile(file); err != nil { // open file under local directory
				reject(p, cError, err.Error())
				continue
			}
			if err = p.sendCmd(cReadfile, resp); err != nil {
				log.Printf("cReadfile err %v", err)
				hangup(p)
				return
			}
		case cWritefile:
			// Extract zero-byte terminated file name. Remainder is file contents.
			j := bytes.IndexByte(req, 0)
			if j < 0 {
				reject(p, cError, "missing filename")
				continue
			}
			file := string(req[:j])
			req = req[j+1:]
			file = path.Clean(file)
			if len(file) < 1 || file[0] == '/' {
				reject(p, cError, "bad filename")
				continue
			}
			if err = ioutil.WriteFile(file, req, 0600); err != nil { // create under local directory
				reject(p, cError, err.Error())
				continue
			}
			resp = []byte{}
			if err = p.sendCmd(cWritefile, resp); err != nil {
				log.Printf("cWritefile sendCmd err %v", err)
				hangup(p)
				return
			}
		default: // includes case Bye:
			p.sendAck(cBye)
			hangup(p)
			return
		}
		p.awaitEmpty()
	}
}

func reject(p *PuckFS, cmd uint16, mess string) {
	var err error
	log.Printf("rejected %x %s", cmd, mess)
	if err = p.sendCmd(cmd, []byte(mess)); err != nil {
		log.Fatalf("unable to even send rejection %v", err)
	}
}

// Hangup makes a best effort to save updated counters, but no guarantee.
// TODO Also arrange for this upon SIGHUP?
func hangup(p *PuckFS) {
	if p.sec.DEBUG {
		log.Printf("hangup")
	}
	if p.caller == nil { // client
		_ = p.udp.Close()
		p.udp = nil
	} else { // server
		p.caller = &unsetCaller
	}
	writeSecretFile(p)
}
