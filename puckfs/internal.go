// Copyright © 2020-2026 Eric Grosse n2vi.com/0BSD

package puckfs

// These are the network and crypto internal mechanisms. For context,
// first read github.com/n2vi/hotline/networking.pdf.
// A sketch of packets as encoded on the wire:
// (~40 bytes) ether, IP, UDP header bytes which we ignore.
// (8) ad "Associated Data": (4) KeyID, (4) seqno of this packet
// (24) random nonce;    included in plaintext/ciphertext
// (4) ack, enciphered
// (2) cmd, enciphered
// (n) data, enciphered
// (16) authentication tag; if decrypt fails, packet is discarded.
//
// The first byte of KeyID (which is the high order byte since we adopt
// BigEndian network byte order) is also used as a protocol version number
// to ensure that anytime a protocol change is made, all systems update
// keys as well as software. A client KeyID has low bit zero and the matching
// server KeyID has low bit one, ensuring that KeyID+seqno is unique
// and providing some defense-in-depth against confusion between client and server.
// After clearing that bit, client and server are using the same encryption key.
//
// Packet sequence numbers, "seqno", are independent for sender and receiver
// and monotonic until rekeying, as defense-in-depth against replay attacks.
// To avoid client counter storage, Dial uses time.UnixMilli for replay
// protection and initializes seqno based on reply from server. 
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
// Clients are identified by KeyID and may be mobile, with
// IP addr regarded as a hint of where to reply.
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
	"math"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Type secretFile holds the parsed secret file.
type secretFile struct {
	DEBUG      bool
	MTU        int    // largest payload size we will send
	PktCnt     string // name of file on server for greetings, snd.w, rcv.w
	KeyID      uint32 // unique to (client,server)-pair
	Secret     string // "chacha20poly1305:"+base64.StdEncoding.EncodeToString(secret)
	ServerAddr string // host:port on network "udp"
}

// PuckFS holds crypto and ring buffers for the network connection.
type PuckFS struct {
	snd    ringBuf     // unack'd packets   snd.val=ciphertext including nonce
	rcv    ringBuf     // undeliv'd packets   rcv.val=plaintext cmd+data
	aead   cipher.AEAD // xchacha20poly1305
	sec    *secretFile
	serverside bool
	greetings int64 // time.UnixMilli at client for most recent Hello
	caller *net.UDPAddr
	udp    *net.UDPConn // handle for reading and writing packets
	dropcnt	int // client bails out if too many dropped packets
}

const (
	puckfsVERSION = 3
	maxPayload    = 1500    // Largest MTU that the other side might have chosen.
	ringN         = 1 << 5   // max cmd payload < MTU*ringN
	minPacketlen  = 8 + 24 + 4 + 2 + 16
)

const (
	cAck 	uint16 = iota
	cPartial
	cError
	cBye
	cHello
	cReadfile
	cWritefile
	cRemove
	cReaddir
)

var cmdNames = []string{"Ack", "Partial", "Error", "Bye", "Hello", "Readfile",
	"Writefile", "Remove", "Readdir"}
var errBye = errors.New("errBye") // treat like network disconnect
var errKey = errors.New("wrongKey")
var sendTimeout = time.Duration(200e6) // 200 millisec
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
	var ciphertext []byte
	if p.sec.DEBUG {
		log.Printf("sendCmd %s[%d] seqno=%d await %d", cmdNames[cmd], len(data), p.snd.w, p.rcv.w)
	}
	for {
		for p.snd.full() {
			if err = p.readPacket(); err != nil {
				log.Printf("sendCmd %s can't push any more; giving up!!!", cmdNames[cmd])
				return
			}
		}
		if p.sec.DEBUG {
			if len(data) > 300 {
				log.Printf("  cmd=%s data=%q...%q", cmdNames[cmd], data[:250],
					data[len(data)-50:])
			} else {
				log.Printf("  cmd=%s data=%q", cmdNames[cmd], data)
			}
		}
		data, ciphertext, err = p.bareCmd(cmd, data)
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

// Just send the command packet; no buffering.
func (p *PuckFS) bareCmd(cmd uint16, data []byte) ([]byte, []byte, error) {
	var ad, plaintext []byte
	ad, plaintext, data = p.marshal(cmd, data)
	ciphertext := make([]byte, 0, len(ad)+24+len(plaintext)+16)
	ciphertext = append(ciphertext, ad...)
	n := len(ad)
	nonce := ciphertext[n : n+24]
	rand.Read(nonce)
	ciphertext = p.aead.Seal(ciphertext[:n+24], nonce, plaintext, ad)
	err := p.write(ciphertext)
	return data, ciphertext, err
}

// Send a lightweight Ack packet; no need for retransmit or ack. Don't advance p.snd.
func (p *PuckFS) sendAck() (err error) {
	var ad, plaintext []byte
	if p.sec.DEBUG {
		log.Printf("sendAck seqno=%d await %d", p.snd.w, p.rcv.w)
	}
	data := []byte{}
	ad, plaintext, data = p.marshal(cAck, data)
	ciphertext := make([]byte, 0, len(ad)+24+len(plaintext)+16)
	ciphertext = append(ciphertext, ad...)
	n := len(ad)
	nonce := ciphertext[n : n+24]
	rand.Read(nonce)
	ciphertext = p.aead.Seal(ciphertext[:n+24], nonce, plaintext, ad)
	err = p.write(ciphertext)
	return
}

// Read an RPC request or response.
func (p *PuckFS) readCmd() (cmd uint16, data []byte, err error) {
	data = make([]byte, 0)
	var sav []byte // cmd+data from one ringBuf entry
	var ok bool
	partialcnt := 0
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
		partialcnt++
		if partialcnt >= 10 {
			if err = p.sendAck(); err != nil {
				log.Printf("tried to send Ack: %s", err)
			}
			partialcnt = 0
		}
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
func (p *PuckFS) readPacket() error {
	var caller *net.UDPAddr
	var seqno uint32
	buf := make([]byte, maxPayload)
	plaintext := make([]byte, maxPayload)

	if !p.snd.empty() { // only useful to timeout if we have something to retransmit
		p.udp.SetReadDeadline(time.Now().Add(sendTimeout))
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
				p.udp.SetReadDeadline(time.Now().Add(2 * sendTimeout))
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
			log.Printf("decrypt failed! Do not use any partial results.")
			return errBye
		}
		break
	}
	p.udp.SetReadDeadline(noDeadline)
	ack := binary.BigEndian.Uint32(plaintext[0:4])
	cmd := binary.BigEndian.Uint16(plaintext[4:6])
	req := plaintext[6:]
	if p.sec.DEBUG {
		log.Printf("  readPacket seqno=%d ack=%d %s", seqno, ack, cmdNames[cmd])
	}
	if cmd == cHello {
		// acks aren't synchronized yet, so handle this specially
		var sw, rw uint32
		if !p.serverside {
			n, err := fmt.Sscanf(string(req), "%d %d", &sw, &rw)
			if n != 2 {
				return err
			}
			p.snd.w = sw
			p.snd.r = p.snd.w
			p.rcv.w = rw+1 // account for server sending a cHello seqno
			p.rcv.r = p.rcv.w
			if p.sec.DEBUG {
				log.Printf("initialized %s",p.packetCounters())
			}
			return nil
		}
		now := time.Now().UnixMilli()
		there, err := strconv.ParseInt(string(req), 10, 64)
		if err != nil {
			log.Printf("invalid time in %s: %s", req, err)
			return nil // just ignore it
		}
		delta := float64(now-there)/1000.
		if math.Abs(delta) > 10. {
			log.Printf("server %d, client %dms;" +
				" surely can do better\n", now, there)
			return nil // just ignore it
		}
		if there <= p.greetings {
			log.Printf("client sent %dms;" +
				" previously had %d\n", there, p.greetings)
			return nil // just ignore it
		}
		p.caller = caller
		p.greetings = there
		p.WritePktCnt()
		resp := []byte{}
		resp = fmt.Appendf(resp, "%d %d", p.rcv.w, p.snd.w)
		if err = p.sendCmd(cHello, resp); err != nil {
			log.Printf("cHello err %v", err)
			p.Close()
			return err
		}
		log.Printf("Hello from %s", caller)
		return nil
	}
	if ack > p.snd.w {
		log.Printf("got ack %d; wanted at most %d", ack, p.snd.w)
		// return p.bail(seqno, ack)
		return nil // ignore; probably from an old connection
	}
	if p.serverside {
		p.caller = caller
	}
	for ack > p.snd.r { // Release acknowledged packets.
		if _, ok := p.snd.pop(); !ok {
			log.Printf("can't happen %d %d %d", ack, p.snd.r, p.snd.w)
			p.Close()
			return errBye
		}
	}
	p.retransmit()        // Check retransmission timers.
	if seqno != p.rcv.w { // Ignore out-of-sequence packets.
		log.Printf("dropping out-of-sequence packet %s %d %s",
			cmdNames[cmd], seqno, p.packetCounters())
		p.dropcnt++
		if p.dropcnt > ringN+10 && !p.serverside {
			log.Fatal("too many drops in a row, bailing out")
		}
		if err := p.sendAck(); err != nil {
			log.Printf("tried to send Ack: %s", err)
		}
		return nil
	}
	p.dropcnt = 0 // got a valid packet, so presumably network recovered
	if cmd == cAck { // special lightweight packet; don't advance p.rcv.
		return nil
	}
	if ok := p.rcv.push(plaintext[4:], noDeadline); !ok {
		// Ignore if we don't have room to save.
		log.Printf("wait for acks %d %s", seqno, p.packetCounters())
		return nil
	}
	return nil
}

func (p *PuckFS) packetCounters() string {
	return fmt.Sprintf("next %d pend %d await %d", p.snd.w, p.snd.w-p.snd.r, p.rcv.w)
}

// Low-level read from network.
func (p *PuckFS) read(buf []byte) ([]byte, *net.UDPAddr, error) {
	var err error
	var n int
	var caller *net.UDPAddr
	if p.serverside {
		n, caller, err = p.udp.ReadFromUDP(buf)
	} else {
		n, err = p.udp.Read(buf)
	}
	ciphertext := buf[:n]
	if err != nil {
		return ciphertext, caller, err
	}
	if n < minPacketlen {
		log.Printf("short packet with no err (%d) %v", n, ciphertext)
		err = errors.New("short packet")
	}
	return ciphertext, caller, err
}

// Low-level write to the network.
func (p *PuckFS) write(ciphertext []byte) (err error) {
	var nw int
	if p.serverside {
		nw, err = p.udp.WriteToUDP(ciphertext, p.caller)
	} else {
		nw, err = p.udp.Write(ciphertext)
	}
	if nw != len(ciphertext) {
		log.Printf("!!!  short write; got %d, wanted %d", nw, len(ciphertext))
	}
	if err != nil {
		log.Fatalf("!!!  can't happen? udp.Write %s", err)
	}
	return
}

// Copy (part of) msg into plaintext, prefixed by 6 bytes of ack+cmd.
func (p *PuckFS) marshal(cmd uint16, msg []byte) (ad, plaintext, unread []byte) {
	ad = make([]byte, 8)
	binary.BigEndian.PutUint32(ad[0:4], p.sec.KeyID)
	binary.BigEndian.PutUint32(ad[4:8], p.snd.w) // seqno
	plaintext = make([]byte, 0, p.sec.MTU)
	binary.BigEndian.PutUint32(plaintext[0:4], p.rcv.w) // ack
	n := len(msg)
	if n+54 > p.sec.MTU { // Is there room for ad, nonce, ack, cmd, msg and auth tag?
		if p.sec.DEBUG {
			log.Printf("  needPartial n=%d MTU=%d\n", n, p.sec.MTU)
		}
		cmd = cPartial
		n = p.sec.MTU - 54
	}
	binary.BigEndian.PutUint16(plaintext[4:6], cmd)
	plaintext = plaintext[:6+n]
	copy(plaintext[6:], msg[:n])
	return ad, plaintext, msg[n:]
}

func readSecretFile(secretfile string) (addr *net.UDPAddr, p *PuckFS, err error) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	sec := secretFile{}
	data, err := os.ReadFile(secretfile)
	if err != nil {
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
	puckfs := PuckFS{snd, rcv, aead, &sec, false, 0, nil, nil, 0}
	return addr, &puckfs, nil
}

// Check filename for validity and copy it to a zero-terminated byte array.
// Possibly in the future we will change to a more general purpose binary design like 9P2000
// but for now we're putting mostly-human-readable bytes into messages.
func pathPrefix(path string) (mess []byte, err error) {
	if !fs.ValidPath(path) {
		return []byte{}, errors.New("%s does not meet standards of io/fs.ValidPath")
	}
	mess = []byte(path)
	mess = append(mess, 0)
	return mess, nil
}

// We are using crude Go-Back-N retransmission with no out-of-order packet handling,
// so we can use ring buffers for keeping track of unacknowleged packets and for
// keeping track of packets that have been read from the network but not yet processed.
// This makes for simple scheduling and is good enough for our network assumptions above.

type ringBuf struct {
	r, w uint32           // seqno
	p    [ringN][]byte    // indexed by seqno mod ringN
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
	j := ringBuf.r & (ringN - 1)
	val = ringBuf.p[j]
	// ringBuf.p[j] = []byte{} // for benefit of garbage collection   TODO confirm this
	ringBuf.r++
	return val, true
}

// Check if oldest retransmit deadline has expired and, if so, resend all.
func (p *PuckFS) retransmit() {
	t, expired := p.snd.timeout()
	if expired {
		if p.sec.DEBUG {
			log.Printf("retransmit seqno=%d..%d", p.snd.r, p.snd.w-1)
		}
		for j := p.snd.r; j < p.snd.w; j++ {
			jj := j & (ringN - 1)
			if p.write(p.snd.p[jj]) != nil {
				return
			}
		}
		*t = time.Now().Add(sendTimeout)
	}
}

// Return data, timeout slot, and status for oldest packet in ringBuf.
func (ringBuf *ringBuf) timeout() (t *time.Time, expired bool) {
	if ringBuf.empty() {
		return nil, false
	}
	now := time.Now()
	j := ringBuf.r & (ringN - 1)
	return &ringBuf.t[j], now.After(ringBuf.t[j])
}
