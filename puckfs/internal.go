// Copyright © 2020,2025 Eric Grosse n2vi.com/0BSD

package puckfs

// These are the network and crypto internal mechanisms. For context,
// first read the "Hotline Networking" doc at github.com/n2vi/hotline/.
// TODO   That doc needs updating, since we've changed to xchacha20poly1305.
// A sketch of packets as encoded on the wire:
// (~40 bytes) ether, IP, UDP header bytes which we ignore.
// (8) ad "Associated Data": (4) KeyID, (4) seqno of this packet
// (24) random nonce;    included in plaintext/ciphertext
// (4) ack, enciphered
// (2) cmd, enciphered
// (n) data, enciphered
// (16) authentication tag; if decrypt fails, packet is discarded.
// Packet sequence numbers, "seqno", are independent for sender and receiver
// and monotonic until rekeying to avoid any replay attack.
//
// The first byte of KeyID (which is the high order byte since we adopt
// BigEndian network byte order) is also used as a protocol version number
// to ensure that anytime a protocol change is made, all systems update
// keys as well as software. A client KeyID has low bit zero and the matching
// server KeyID has low bit one, ensuring that KeyID+seqno is unique
// and preventing packet replay confusion between client and server.
// After clearing that bit, client and server are using the same encryption key.
//
// The ack value is the packet sender's rcv.w, which is the seqno
// the sender is awaiting from the other side, one higher
// than most recently received and validated. That value is 0 if
// nothing has been received yet.
//
// cmd == Partial means data is to be concatenated with the following packet.
//
// We do not intend to support any version negotiation.
// Possibly we should use pure text rather than a binary format like this, but
// we don't want protocol compilers, JIT, reflection, or large parsers.
//
// Someday clients may be mobile, so perhaps best identified by KeyID, with
// IP addr regarded as a hint of where to reply. But leave that for later.
// My server has a static IP address, which I like to use explicitly in the secretFile
// to avoid DNS troubles, but do as you like.
//
// We assume a reasonably low latency, low error network. The timeouts in
// readPacket are intended to recover from rare glitches. If they fire
// frequently, it is likely time to redesign.

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Type secretFile holds the parsed secret file.
type secretFile struct {
	DEBUG          bool
	MTU            int    // largest payload size we will send
	PktCnt         string // name of file for snd.w, rcv.w
	KeyID          uint32 // unique to (client,server)-pair
	Secret         string // "chacha20poly1305:"+base64.StdEncoding.EncodeToString(secret)
	ServerAddr     string // host:port on network "udp"
}

// PuckFS holds the parsed secretFile and ring buffers for the network connection.
type PuckFS struct {
	snd            ringBuf // unack'd packets   snd.val=ciphertext including nonce
	rcv            ringBuf // undeliv'd packets   rcv.val=plaintext cmd+data
	aead	cipher.AEAD // xchacha20poly1305
	sec	*secretFile
	caller	*net.UDPAddr // for client, caller==nil; for server, init &unsetCaller
	udp	*net.UDPConn // handle for reading and writing packets
}

const (
	puckfsVERSION = 3
	maxPayload = 1500 // Largest MTU that the other side might have chosen.
	ringN = 1<<12 // max cmd payload < MTU*ringN
	minPacketlen = 8+24+4+2+16
)

const (
	cPartial uint16 = iota
	cError
	cBye
	cHello
	cReadfile
	cWritefile
	cRemove
	cReaddir
	cChtime
)
var cmdNames = []string{"Partial", "Error", "Bye", "Hello", "Readfile",
	"Writefile", "Remove", "Readdir", "Chtime"}
var unsetCaller net.UDPAddr
var errBye = errors.New("errBye")       // treat like network disconnect
var errKey = errors.New("wrongKey")
var sendTimeout = time.Duration(5e9) // 5 sec
var noDeadline time.Time

// ClientRPC sends scmd+req and then reads rcmd+resp. Errors are returned in rcmd.
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

// Send a command, if necessary as multiple packets.
func (p *PuckFS) sendCmd(cmd uint16, data []byte) (err error) {
	if p.sec.DEBUG {
		log.Printf("sendCmd %s[%d] seqno=%d await %d", cmdNames[cmd], len(data), p.snd.w, p.rcv.w)
	}
	if len(data) > p.sec.MTU * ringN / 2 {
		log.Printf("implausibly large transfer size %d, likely to fail or hang", len(data))
	}
	for {
		for p.snd.full() {
			if err = p.readPacket(); err != nil {
				log.Printf("sendCmd %s can't push any more; giving up!!!", cmdNames[cmd])
				return
			}
		}
		if p.sec.DEBUG {
			log.Printf("  cmd=%s data=%q", cmdNames[cmd], data)
		}
		ad, plaintext, data := p.marshal(cmd, data)
		ciphertext := make([]byte, 0, len(ad)+24+len(plaintext)+16)
		ciphertext = append(ciphertext, ad...)
		n := len(ad)
		nonce := ciphertext[n:n+24]
		rand.Read(nonce)
		ciphertext = p.aead.Seal(ciphertext[:n+24], nonce, plaintext, ad)
		err = p.write(ciphertext)
		if err != nil {
			return
		}
		if ok := p.snd.push(ciphertext, time.Now().Add(sendTimeout)); !ok {
			log.Fatal("can't happen; send ring buffer overflow") // we checked above
		}
		if p.sec.DEBUG {
			log.Printf("  %s", p.packetCounters())
		}
		if len(data) == 0 {
			break
		}
	}
	return
}

// Read an RPC request or response.
func (p *PuckFS) readCmd() (cmd uint16, data []byte, err error) {
	data = make([]byte, 0)
	var sav []byte // cmd+data from one ringBuf entry
	var ok bool
	for cmd = cPartial; cmd == cPartial; {
		for p.rcv.empty() {
			if err = p.readPacket(); err != nil {
				log.Printf("readCmd failed %s", err)
				return
			}
		}
		if sav, ok = p.rcv.pop(); !ok {
			log.Fatal("can't happen; pop fail on nonempty ring?")
		}
		cmd = binary.BigEndian.Uint16(sav[:2])
		data = append(data, sav[2:]...)
		if p.sec.DEBUG {
			log.Printf("  got {%d} %s", len(sav)-2, p.packetCounters())
		}
	}
	if p.sec.DEBUG {
		log.Printf("readCmd %s[%d]", cmdNames[cmd], len(data))
	}
	return
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

// Read a packet from network, validate, and push onto rcv buffer.
func (p *PuckFS) readPacket() (error) {
	var caller *net.UDPAddr
	var seqno uint32
	buf := make([]byte, maxPayload)
	plaintext := make([]byte, maxPayload)

	if !p.snd.empty() { // only useful to timeout if we have something to retransmit
		p.udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	retry := 0
	for {
		var ciphertext []byte
		var err error
		retry++
		ciphertext, caller, err = p.read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				if p.sec.DEBUG {
					log.Printf("deadline")
				}
				p.retransmit()
				p.udp.SetReadDeadline(time.Now().Add(30 * time.Second))
				continue
			}
			p.udp.SetReadDeadline(noDeadline)
			log.Printf("readPacket network read error %s; giving up!!!", err)
			return errBye
		}
		ad, ciphertext := ciphertext[:8], ciphertext[8:]
		keyid := binary.BigEndian.Uint32(ad[:4])
		if keyid != p.sec.KeyID^1 {
			log.Printf("wrong KeyID %d, expected %d!!!", keyid, p.sec.KeyID^1)
			if retry < 2 {
				continue // Ignore one packet with wrong KeyID.
			}
			return errKey // configuration error or DoS attack; give up
		}
		seqno = binary.BigEndian.Uint32(ad[4:8])
		plaintext, err = p.aead.Open(plaintext[:0], ciphertext[:24], ciphertext[24:], ad)
		if err != nil {
			log.Fatal("decrypt failed! Do not use any partial results.")
		}
		break
	}
	p.udp.SetReadDeadline(noDeadline)
	ack := binary.BigEndian.Uint32(plaintext[0:4])
	cmd := binary.BigEndian.Uint16(plaintext[4:6])
	if p.sec.DEBUG {
		log.Printf("  readPacket seqno=%d ack=%d %s", seqno, ack, cmdNames[cmd])
	}
	p.callerSet(cmd, caller)
	if ack > p.snd.w {
		log.Printf("got ack %d for packet never sent; wanted at most %d", ack, p.snd.w)
		// return p.bail(seqno, ack)
		return nil // ignore; probably from an old connection
	}
	for ack > p.snd.r { // Release acknowledged packets.
		if _, ok := p.snd.pop(); !ok {
			log.Printf("can't happen %d %d %d", ack, p.snd.r, p.snd.w)
			p.Close()
			return errBye
		}
	}
	p.retransmit() // Check retransmission timers.
	if seqno != p.rcv.w { // Ignore out-of-sequence packets.
		log.Printf("dropping out-of-sequence packet %s %d %s",
			cmdNames[cmd], seqno, p.packetCounters())
		return nil
	}
	if ok := p.rcv.push(plaintext[4:], noDeadline); !ok { // Ignore if we don't have room to save.
		log.Printf("Other side should wait for acks. %d %s", seqno, p.packetCounters())
		return nil
	}
	return nil
}

func (p *PuckFS) packetCounters() string {
	return fmt.Sprintf("next %d pend %d await %d", p.snd.w, p.snd.w-p.snd.r, p.rcv.w)
}

// Check if oldest retransmit deadline has expired and, if so, resend.
func (p *PuckFS) retransmit() {
	old, t, expired := p.snd.timeout()
	if expired {
		if p.sec.DEBUG {
			log.Printf("retransmit seqno=%d", p.snd.r)
		}
		if p.write(old) != nil {
			return
		}
		*t = time.Now().Add(sendTimeout)
	}
}

// Low-level read from network.
func (p *PuckFS) read(buf []byte) ([]byte, *net.UDPAddr, error) {
	var err error
	var n int
	var caller *net.UDPAddr
	if p.caller == nil {
		n, err = p.udp.Read(buf)
	} else {
		n, caller, err = p.udp.ReadFromUDP(buf)
	}
	ciphertext := buf[:n]
	if err != nil {
		return ciphertext, caller, err
	}
	if n < minPacketlen {
		log.Printf("short packet with no err (%d) %v", n, ciphertext)
		err = errors.New("short packet")
	}
	return ciphertext, caller, nil
}

// Low-level write to the network.
func (p *PuckFS) write(ciphertext []byte) (err error) {
	var nw int
	if p.caller == nil {
		nw, err = p.udp.Write(ciphertext)
	} else {
		nw, err = p.udp.WriteToUDP(ciphertext, p.caller)
	}
	if nw != len(ciphertext) {
		log.Printf("!!!  short write; got %d, wanted %d", nw, len(ciphertext))
	}
	if err != nil {
		log.Fatalf("!!!  can't happen? udp.Write %s", err)
	}
	return
}

// If server receives a validated cHello, remember caller's address.
func (p *PuckFS) callerSet(cmd uint16, caller *net.UDPAddr) {
	if p.caller == nil {
		 // If nil, we're a client. And we already know the server's address.
		return
	}
	if cmd != cHello {
		return // callerSet is only relevant for first packet of connection from client.
	}
	if p.caller == &unsetCaller {
		p.caller = caller
	} else if p.caller == caller {
		log.Fatal("Perhaps our earlier cHello reply to the client was lost? Unable to recover.")
	} else {
		log.Printf("cHello while still listening for a client that didn't Bye.")
		p.Close() // Let's assume the old client crashed and let's try to proceed...
		p.caller = caller
	}
}

// Copy (part of) msg into plaintext, prefixed by 6 bytes of ack+cmd.
func (p *PuckFS) marshal(cmd uint16, msg []byte) (ad, plaintext, unread []byte) {
	ad = appendUint32(make([]byte,0,8), p.sec.KeyID)
	ad = appendUint32(ad, p.snd.w) // seqno
	plaintext = make([]byte, 0, p.sec.MTU)
	plaintext = appendUint32(plaintext, p.rcv.w) // ack
	n := len(msg)
	if n + 54 > p.sec.MTU { // Is there room for ad, nonce, ack, cmd, msg and auth tag?
		if p.sec.DEBUG {
			log.Printf("  needPartial n=%d MTU=%d\n", n, p.sec.MTU)
		}
		cmd = cPartial
		n = p.sec.MTU - 54
	}
	plaintext = appendUint16(plaintext, cmd)
	plaintext = append(plaintext, msg[:n]...)
	return ad, plaintext, msg[n:]
}

// Try to recover from stale counters.
func (p *PuckFS) bail(seqno, ack uint32) (error){
	log.Printf("Probably we failed earlier while saving our counters; bailing.")
	p.snd.w = ack
	for ok := true; ok; _, ok = p.snd.pop() {
		// Discard until buffer is empty.
	}
	p.rcv.w = seqno+1
	for ok := true; ok; _, ok = p.rcv.pop() {
		// Discard until buffer is empty.
	}
	log.Printf("forced %d %d %d %d", p.snd.r, p.snd.w, p.rcv.r, p.rcv.w)
	p.Close()
	return errBye
}

func readSecretFile(secretfile string) (addr *net.UDPAddr, p *PuckFS, err error) {
	log.SetFlags(log.Ldate|log.Ltime|log.Lmicroseconds)
	sec := secretFile{}
	data, err := os.ReadFile(secretfile)
	if  err != nil {
		return addr, p, err
	}
	if err = json.Unmarshal(data, &sec); err != nil {
		return addr, p, err
	}
	if (sec.KeyID >> 24) != puckfsVERSION {
		return addr, p, fmt.Errorf("KeyID VER %d, wanted %d", sec.KeyID>>24, puckfsVERSION)
	}
	pref := len("chacha20poly1305:")
	if sec.Secret[:pref] != "chacha20poly1305:" {
		return addr, p, fmt.Errorf("unsupported key type in secretfile: %s", sec.Secret[:pref])
	}
	secret, err := base64.StdEncoding.DecodeString(sec.Secret[pref:])
	if err != nil {
		return addr, p, err
	}
	aead, err := chacha20poly1305.NewX(secret)
	if err != nil {
		log.Fatal("NewX failed; something must be wrong with secret.")
	}
	if aead.NonceSize() != 24 || aead.Overhead() != 16 {
		log.Fatal("internal sanity check failed in readSecretFile()")
	}
	if addr, err = net.ResolveUDPAddr("udp", sec.ServerAddr); err != nil {
		return addr, p, fmt.Errorf("unable to resolve udp %s %w", sec.ServerAddr, err)
	}
	snd := ringBuf{0, 0, [ringN][]byte{}, [ringN]time.Time{}}
	rcv := ringBuf{0, 0, [ringN][]byte{}, [ringN]time.Time{}}
	if data, err = os.ReadFile(sec.PktCnt); err != nil {
		return addr, p, err
	}
	var sw, rw uint32
	n, err := fmt.Sscanf(string(data), "%d %d", &sw, &rw)
	if n != 2 || err != nil {
		log.Fatalf("unable to parse %s: %d %v", p.sec.PktCnt, n, err)
	}
	if sw > uint32(1<<29) || rw > uint32(1<<29) {
		log.Print("time to rekey; PktCnt getting large") // I doubt I'll ever get this.
	}
	snd.r = sw
	snd.w = sw
	rcv.r = rw
	rcv.w = rw
	puckfs := PuckFS{snd, rcv, aead, &sec, &unsetCaller, nil}
	return addr, &puckfs, nil
}

// Check filename for validity and copy it to a zero-terminated byte array.
// Possibly in the future we will change to a more general purpose binary design like 9P2000
// but for now we're putting mostly-human-readable bytes into messages.
func pathPrefix(path string) (mess []byte, err error) {
	if fs.ValidPath(path) == false {
		return []byte{}, errors.New("%s does not meet standards of io/fs.ValidPath")
	}
	mess = []byte(path)
	mess = append(mess, 0)
	return mess, nil
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

// We are using crude Go-Back-N retransmission with no out-of-order packet handling,
// so we can use ring buffers for keeping track of unacknowleged packets and for
// keeping track of packets that have been read from the network but not yet processed.
// This makes for simple scheduling and is good enough for our network assumptions above.

type ringBuf struct {
	r, w uint32 // seqno
	p    [ringN][]byte // indexed by seqno mod ringN
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
	j := ringBuf.r&(ringN-1)
	val = ringBuf.p[j]
	// ringBuf.p[j] = []byte{} // for benefit of garbage collection   TODO confirm this
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

