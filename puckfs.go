// Copyright © 2020 Eric Grosse n2vi.com/0BSD

/*
	Package puckfs provides a primitive network file server and client,
	atop Go-Back-N retransmission and transport encryption, atop udp.
*/
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"time"
)

// Type secretFile describes the secret file on local disk, mode 0600.
type secretFile struct {
	DEBUG          bool
	SndW, RcvW     uint32 // packet sequence numbers this side sent or is awaiting
	MTU            int    // largest payload size we will send
	KeyID          uint32 // unique to (client,server)-pair
	Secret         string // "ascon80pq:"+base64.StdEncoding.EncodeToString(secret)
	ServerAddr     string // host:port on network "udp"
}

// PuckFS holds the parsed secretFile and ring buffers for the network connection.
type PuckFS struct {
	snd            ringBuf // unack'd packets   snd.val=ciphertext including nonce
	rcv            ringBuf // undeliv'd packets   rcv.val=plaintext cmd+data
	mtu            int // largest payload size we will send
	keyID          uint32
	secret         []byte // base64.StdEncoding.DecodeString(Secret[10:])
	sec            *secretFile
	secretF       *os.File // "puck-secret" or "broker-secret", held to enable unveil() someday
	caller         *net.UDPAddr // for client, caller==nil; for server, init &unsetCaller
	udp            *net.UDPConn // handle for reading and writing packets
}

// The client API follows; the server API is at the bottom of the file.

// Dial calls the puckfs server and checks clocks for consistency.
func Dial(secretfile string) (p *PuckFS, err error) {
	var addr *net.UDPAddr
	var f *os.File
	log.SetFlags(log.Ldate|log.Ltime|log.Lmicroseconds)
	if f, err = os.OpenFile(secretfile, os.O_RDWR, 0600); err != nil {
		return p, err
	}
	if addr, p, err = readSecretFile(f); err != nil {
		return p, err
	}
	if p.keyID&1 != 0 { // can't happen except by catastrophic blunder
		return p, errors.New("wanted keyID for client, got server")
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

// ReadFile fetches file contents, similar to ioutil.
func (p *PuckFS) ReadFile(path string) (data []byte, err error) {
	cmd, data := p.clientRPC(cReadfile, []byte(path))
	return data, expect(cReadfile, cmd, data)
}

// WriteFile writes file contents, similar to ioutil,
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
	datalines := linesplit(data)
	fi = make([]fs.FileInfo, len(datalines))
	for i, s := range datalines {
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

// TimeToRekey is an error indication that the secretFile needs updating.
var TimeToRekey = errors.New("puckfs: secret is becoming stale; time to rekey!")

// Close saves sequence numbers and returns TimeToRekey if secret is due for refresh.
func (p *PuckFS) Close() (err error) {
	if p.sec.DEBUG {
		log.Printf("Close")
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
		p.snd.pop() // We won't be getting an ack for the Bye, but pretend we did.
		p.caller = &unsetCaller
	}
	if (p.snd.w+p.rcv.w)*uint32(p.mtu) >= maxKeyCount {
		err = TimeToRekey
		log.Printf("%s", err) // Just in case caller ignores this critical err.
	}
	writeSecretFile(p)
	if !p.snd.empty() || !p.rcv.empty() {
		log.Print("Buffers not empty. Check file *-secret on puck and broker!!!")
		// discard any pending packets
		p.snd.r = p.snd.w
		p.rcv.r = p.rcv.w
	}
	return
}

func Keygen() string {
	r := make([]byte, 20)
	n, err := rand.Read(r)
	if n != 20 || err != nil {
		log.Fatalf("can't happen: crypto random fail: %s", err)
	}
	return "ascon80pq:"+base64.StdEncoding.EncodeToString(r)
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

// ------ The client API ends here. For server API, see functions at bottom of file. ------
// Here are the network and crypto internal mechanisms. For context,
// first read the "Hotline Networking" doc at github.com/n2vi/hotline/.
// A sketch of packets as encoded on the wire:
// (~40 bytes) ether, IP, UDP header bytes which we ignore.
// (16) nonce  =  (4) keyID, (4) this packet sequence number, (8) random
// (4) ack, ASCON-enciphered
// (2) cmd, ASCON-enciphered
// (n) data, ASCON-enciphered
// (16) authentication tag; if ASCON-decrypt fails, packet is discarded.
//
// Packet sequence numbers, "seqno", are independent for sender and receiver,
// and we rekey long before the integer overflow of uint32.
// Seqno start at 0 and increment by 1, even across program restarts.
// Yes, this implies we need to take care saving the counter.
// It is not a catastrophic failure if we miss, but let's try hard not to.
// There is not enough cryptographic research yet to say how often we
// need to rekey with ascon80pq. We conjecture that limiting the number
// of encrypted bytes to maxKeyCount is safe.
//
// The first byte of keyID (which is the high order byte since we adopt
// BigEndian network byte order) is also used as a protocol version number
// to ensure that anytime a protocol change is made, all systems update
// keys as well as software. A client keyID has low bit zero and the matching
// server keyID has low bit one, ensuring that keyID+seqno is unique
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
// Someday clients may be mobile, so perhaps best identified by keyID, with
// IP addr regarded as a hint of where to reply. But leave that for later.
//
// We assume a reasonably low latency, low error network. The timeouts in
// readPacket are intended to recover from rare glitches. If they fire
// frequently, it is likely time to redesign.

const (
	puckfsVERSION = 1
	maxKeyCount   = 1<<28
	maxPayload = 1500 // Largest mtu that the other side might have chosen.
	ringN = 1<<12 // max cmd payload < mtu*ringN
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
		log.Printf("sendCmd %s[%d] seqno=%d", cmdNames[cmd], len(data), p.snd.w)
	}
	if len(data) > p.mtu * ringN / 2 {
		log.Printf("implausibly large transfer size %d, likely to fail or hang", len(data))
	}
	for {
		for p.snd.full() {
			if err = p.readPacket(); err != nil {
				log.Printf("sendCmd %s can't push any more; giving up!!!", cmdNames[cmd])
				return
			}
		}
		var plaintext []byte
		plaintext, data = p.marshal(cmd, data)
		ciphertext := make([]byte, len(plaintext)+16) // add room for auth tag
		asconEncrypt(ciphertext, plaintext, []byte{}, p.secret)
		err = p.write(ciphertext)
		if err != nil {
			return
		}
		if ok := p.snd.push(ciphertext, time.Now().Add(sendTimeout)); !ok {
			log.Fatal("can't happen; send ring buffer overflow") // we checked above
		}
		if p.sec.DEBUG {
			log.Printf("  put {%d} %s", len(plaintext)-22, p.packetCounters())
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
func (p *PuckFS) readPacket() (err error) {
	var caller *net.UDPAddr
	var seqno uint32
	var ack uint32
	var cmd uint16
	ciphertext := make([]byte, maxPayload)
	plaintext := make([]byte, maxPayload-16) //  Auth tag is included in ciphertext but not in plaintext.

	if !p.snd.empty() { // only useful to timeout if we have something to retransmit
		p.udp.SetReadDeadline(time.Now().Add(5 * time.Second))
	}
	retry := 0
	for {
		retry++
		if ciphertext, caller, err = p.read(ciphertext); err != nil {
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
			return
		}
		if binary.BigEndian.Uint32(ciphertext[:4]) != p.keyID^1 {
			log.Printf("wrong keyID %d, expected %d!!!",
				binary.BigEndian.Uint32(ciphertext[:4]), p.keyID^1)
			if retry < 2 {
				continue // Ignore one packet with wrong keyID.
			}
			return errKey // configuration error or DoS attack; give up
		}
		n := len(ciphertext)
		plaintext = plaintext[:n-16]
		if err = asconDecrypt(plaintext, ciphertext, []byte{}, p.secret); err != nil {
			log.Printf("decryption failed %s; giving up!!!", err)
			return
		}
		break
	}
	p.udp.SetReadDeadline(noDeadline)
	seqno = binary.BigEndian.Uint32(plaintext[4:8])
	ack = binary.BigEndian.Uint32(plaintext[16:20])
	cmd = binary.BigEndian.Uint16(plaintext[20:22])
	if p.sec.DEBUG {
		log.Printf("  readPacket seqno=%d ack=%d %s[%d]", seqno, ack, cmdNames[cmd], len(plaintext)-22)
	}
	p.callerSet(cmd, caller)
	if ack > p.snd.w {
		log.Printf("got ack %d for packet never sent; wanted at most %d", ack, p.snd.w)
		return p.bail(seqno, ack)
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
		if cmd == cBye {
			log.Printf("out-of-sequence Bye %d %s", seqno, p.packetCounters())
			return p.bail(seqno, ack)
		}
		log.Printf("dropping out-of-sequence packet %d %s", seqno, p.packetCounters())
		return
	}
	if ok := p.rcv.push(plaintext[20:], noDeadline); !ok { // Ignore if we don't have room to save.
		log.Printf("Other side should wait for acks. %d %s", seqno, p.packetCounters())
		return
	}
	return
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
func (p *PuckFS) read(ciphertext []byte) ([]byte, *net.UDPAddr, error) {
	var err error
	var n int
	var caller *net.UDPAddr
	ciphertext = ciphertext[:maxPayload] // undo any previous trimming
	if p.caller == nil {
		n, err = p.udp.Read(ciphertext)
	} else {
		n, caller, err = p.udp.ReadFromUDP(ciphertext)
	}
	ciphertext = ciphertext[:n]
	if err != nil {
		return ciphertext, caller, err
	}
	if n < 38 {
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

// Copy (part of) msg into plaintext, prefixed by 22 bytes of nonce+ack+cmd.
func (p *PuckFS) marshal(cmd uint16, msg []byte) (plaintext, unread []byte) {
	plaintext = appendUint32(make([]byte, 0, p.mtu), p.keyID)
	plaintext = appendUint32(plaintext, p.snd.w) // seqno
	var random [8]byte
	nn, err := rand.Read(random[:])
	if nn != 8 || err != nil {
		log.Fatalf("can't happen; crypto rand fail: %d %s", nn, err)
	}
	plaintext = append(plaintext, random[:]...) // completes the 16 byte nonce
	plaintext = appendUint32(plaintext, p.rcv.w) // ack
	n := len(msg)
	if n > p.mtu - len(plaintext) - 18 { // Is there room for msg and cmd and auth tag?
		cmd = cPartial
		n = p.mtu - len(plaintext) - 18
	}
	plaintext = appendUint16(plaintext, cmd)
	plaintext = append(plaintext, msg[:n]...)
	return plaintext, msg[n:]
}

// Try to recover from presumed stale SecretFile.
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
	// TODO   Confirm we don't need this, because done in p.Close():   writeSecretFile(p)
	p.Close()
	return errBye
}

func readSecretFile(f *os.File) (addr *net.UDPAddr, p *PuckFS, err error) {
	var data []byte
	sec := secretFile{}
	if data, err = ioutil.ReadAll(f); err != nil {
		return addr, p, err
	}
	if err = json.Unmarshal(data, &sec); err != nil {
		return addr, p, err
	}
	if (sec.KeyID >> 24) != puckfsVERSION {
		return addr, p, fmt.Errorf("KeyID puckfsVERSION %d, wanted %d", sec.KeyID>>24, puckfsVERSION)
	}
	if sec.Secret[:10] != "ascon80pq:" {
		return addr, p, fmt.Errorf("unsupported key type in secretfile: %s", sec.Secret[:10])
	}
	if (sec.SndW+sec.RcvW)*uint32(sec.MTU) >= maxKeyCount/2 {
		return addr, p, fmt.Errorf("way past time to rekey; you were warned! %d", (sec.SndW+sec.RcvW)*uint32(sec.MTU))
	}
	if addr, err = net.ResolveUDPAddr("udp", sec.ServerAddr); err != nil {
		return addr, p, fmt.Errorf("unable to resolve udp %s %w", sec.ServerAddr, err)
	}
	snd := ringBuf{sec.SndW, sec.SndW, [ringN][]byte{}, [ringN]time.Time{}}
	rcv := ringBuf{sec.RcvW, sec.RcvW, [ringN][]byte{}, [ringN]time.Time{}}
	secret, err := base64.StdEncoding.DecodeString(sec.Secret[10:])
	if err != nil {
		return addr, p, err
	}
	puckfs := PuckFS{snd, rcv, sec.MTU, sec.KeyID, secret, &sec, f, nil, nil}
	return addr, &puckfs, nil
}

func writeSecretFile(p *PuckFS) {
	var data []byte
	var err error
	if p.snd.r != p.snd.w || p.rcv.r != p.rcv.w {
		log.Printf("writeSecretFile snd.r,w=%d,%d rcv.r,w=%d,%d", p.snd.r, p.snd.w, p.rcv.r, p.rcv.w)
	}
	p.sec.SndW = p.snd.w
	p.sec.RcvW = p.rcv.w
	if data, err = json.MarshalIndent(p.sec, "", "\t"); err != nil {
		// can't happen?
		log.Fatalf("%v", err)
	}
	data = append(data, '\n')
	if err = p.secretF.Truncate(0); err != nil {
		log.Printf("unable to truncate in writeSecretFile, but plunging ahead; check the result!\n")
	}
	if _, err = p.secretF.WriteAt(data, 0); err != nil {
		log.Printf("snd.r,w=%d,%d rcv.r,w=%d,%d", p.snd.r, p.snd.w, p.rcv.r, p.rcv.w)
		log.Fatalf("%v", err)
	}
	return
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

// ------ The server API starts here. ------

// Server listens on a fixed port from a single client with a predetermined secret.
func Listen(secretfile string) (p *PuckFS, err error) {
	var addr *net.UDPAddr
	var f *os.File
	log.SetFlags(log.Ldate|log.Ltime|log.Lmicroseconds)
	if f, err = os.OpenFile(secretfile, os.O_RDWR, 0600); err != nil {
		return p, err
	}
	if addr, p, err = readSecretFile(f); err != nil {
		return p, err
	}
	p.caller = &unsetCaller
	if p.keyID&1 != 1 { // can't happen except by catastrophic blunder
		return p, errors.New("wanted keyID for server, got client")
	}
	if p.udp, err = net.ListenUDP("udp", addr); err != nil {
		return p, err
	}
	return
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
			now := time.Now().UTC()
			there, err := time.Parse(time.RFC3339, string(req))
			delta := now.Sub(there).Seconds()
			if math.Abs(delta) > 10. {
				reject(p, cHello, "computer clocks can surely be better calibrated than 10sec?")
				continue
			}
			if math.Abs(delta) > 2. {
				resp = []byte(fmt.Sprintf("%.0f", delta))
			}
			if err = p.sendCmd(cHello, resp); err != nil {
				log.Printf("cHello err %v", err)
				p.Close()
				return
			}
		case cReadfile:
			if file, req, err = extractFilename(req); err != nil {
				reject(p, cError, "bad filename")
				continue
			}
			if resp, err = ioutil.ReadFile(file); err != nil { // open file under local directory
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
			if err = ioutil.WriteFile(file, req, 0660); err != nil { // create under local directory
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
			if file, req, err = extractFilename(req); err != nil {
				reject(p, cError, "bad filename")
				continue
			}
			var fi []fs.FileInfo
			if fi, err = ioutil.ReadDir(file); err != nil {
				reject(p, cError, err.Error())
				continue
			}
			for _, f := range fi {
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
		case cChtime:
			var t int64
			if file, req, err = extractFilename(req); err != nil {
				reject(p, cError, "bad filename")
				continue
			}
			if t, err = strconv.ParseInt(string(req), 10, 64); err != nil {
				reject(p, cError, err.Error())
				continue
			}
			mtime := time.Unix(t, 0)
			if err = os.Chtimes(file, mtime, mtime); err != nil {
				reject(p, cError, err.Error())
				continue
			}
			resp = []byte{}
			if err = p.sendCmd(cWritefile, resp); err != nil {
				log.Printf("cWritefile sendCmd err %v", err)
				p.Close()
				return
			}
		case cBye:
			p.Close()
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
			log.Printf("------------- %d", p.snd.w-p.snd.r)
		}
	}
}

// Extract zero-byte terminated file name (or entire input).
func extractFilename(req  []byte) (file string, remainder []byte, err error) {
		j := bytes.IndexByte(req, 0)
		if j < 0 {
			file = string(req)
			remainder = []byte{}
		} else {
			file = string(req[:j])
			remainder = req[j+1:]
		}
		
		if fs.ValidPath(file) == false {
			return "", req, errBye
		}
		return file, remainder, nil
}

// myFileInfo implements fs.FileInfo
type myFileInfo struct {
	name string
	size int64
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

func (fi myFileInfo) Sys() interface{} {
	return nil
}

// Linesplit separates byte array at newlines.
func linesplit(data []byte) (lines [][]byte) {
	// lines = make([][]byte, 0, 100)
	for len(data) > 0 {
		j := bytes.IndexByte(data, '\n')
		if j < 0 {
			log.Fatal("can't happen; no trailing newline")
		}
		lines = append(lines, data[:j])
		data = data[j+1:]
	}
	return lines
}

// Reject sends error message, else fatal.
func reject(p *PuckFS, cmd uint16, mess string) {
	var err error
	log.Printf("rejected %x %s", cmd, mess)
	if err = p.sendCmd(cmd, []byte(mess)); err != nil {
		log.Fatalf("unable to even send rejection %v", err)
	}
}

