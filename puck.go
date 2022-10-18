// Copyright (c) 2020,2022 Eric Grosse n2vi.com/0BSD

/*
	Command hotline implements hotline cryptography.
	This version implements a command line interface,
	which I use with the acme editor as GUI.

	A message is delivered by writing files named "recipient/keycount"
	on the sender's broker via the "puckfs" network protocol. In theory,
	that broker would have a set of heuristics for how to deliver to the
	recipient's broker through the high-resilience ROCCS network,
	though in our current simulator that is merely moving the (end-to-
	end encrypted) message file from one directory to another.

	If you're a fellow hotline developer, I will have already emailed you
	a "puck-secret" file to install in your puck working directory to talk to
	the broker/ROCCS-simulator that I run. Go install the hotline
	executable. Then:
		echo '{"Me": randomintIemailedyou, "Peers": []}' > PrincipalsDB
		echo '{}' > keyCount
		mkdir archiveDB; chmod go-rw PrincipalsDB archiveDB
		hotline introduction 1446134797 eric
		hotline rekey eric randomstringIEmailedandSignaledyou

	Just working out ideas here; don't consider this final.
	Comments welcome to grosse@gmail.com.
*/
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	VERSION         = 0x484f5431 // "HOT1"
	AES256GCMkeyalg = 1 // the default here, but expect others
)

type ID uint32          // static, globally-unique identifier of a principal
type MessageType string // "UTF8", "JPEG", "ACK1", "QACK"
var JPEGmagic [3]byte = [3]byte{0xff, 0xd8, 0xff}
var unmatchedError = errors.New("unmatched")

type PrincipalsDB struct {
	Me    ID // my (puck's) identity
	Peers []*Principal
}

type Principal struct {
	Id        ID     // my peer's identity
	Nick      string // private, local reminder of who this is
	Note      string // updated where, when, how, by whom
	My, Their Key
	// myRouting, theirRouting Routing
}

type Key struct {
	KeyID  uint32 // changes when algorithm or secret changes
	KeyAlg uint32 // enough bits for per-country parameterized ciphers
	Secret []byte
}

type Message struct {
	Date     int64
	From     ID
	To       []ID
	MsgType  MessageType
	Indirect bool // body is filename, not contents
	Body     []byte
	fn       string // local filename for storing the message
}

var db PrincipalsDB
var nick map[ID]string
var nickP map[string]*Principal
var keyCount map[uint32]uint32
var Messages []Message
var MessageCounter int
var puckfs *PuckFS

// Send to (nicks) the (text) of form (msgtype), interpreting as filename if (indirect).
// Return the Message struct or error.
func sendTo(nicks []string, text string, msgtype MessageType, indirect bool) (Message, error) {
	var m Message
	var ovfl error
	var err error

	m.Date = time.Now().Unix()
	m.From = db.Me
	nr := len(nicks)
	if nr > 100 {
		return m, fmt.Errorf("implausibly large number of recipients %d", nr)
	}
	m.To = make([]ID, nr)
	for i := 0; i < nr; i++ {
		r, ok := nickP[nicks[i]]
		if !ok {
			return m, fmt.Errorf("unrecognized recipient %s", nicks[i])
		}
		m.To[i] = r.Id
	}
	m.MsgType = msgtype
	if len(msgtype) != 4 {
		log.Fatalf("invalid MessageType %s", msgtype)
	}
	m.Indirect = indirect
	m.Body = []byte(text)
	body := m.Body
	if indirect {
		body, err = ioutil.ReadFile(strings.TrimSuffix(text, "\n"))
		if err != nil {
			log.Fatalf("unable to read %q: %s", text, err)
		}
	}

	//    4   magic
	//    4   msgtype
	//    8   unixtime
	//    4   sender
	//    2   nr
	//  4*nr recipients
	//  len  body
	n := 22 + 4*nr + len(body)
	plaintext := make([]byte, n)
	binary.BigEndian.PutUint32(plaintext[0:], VERSION)
	copy(plaintext[4:], []byte(m.MsgType))
	binary.BigEndian.PutUint64(plaintext[8:], uint64(m.Date))
	binary.BigEndian.PutUint32(plaintext[16:], uint32(m.From))
	binary.BigEndian.PutUint16(plaintext[20:], uint16(nr))
	for i := 0; i < nr; i++ {
		binary.BigEndian.PutUint32(plaintext[22+i*4:], uint32(m.To[i]))
	}
	copy(plaintext[22+4*nr:], body)

	for i := 0; i < nr; i++ {
		r := nickP[nicks[i]]
		if uint32(n) >= math.MaxUint32/4-keyCount[r.My.KeyID] {
			ovfl = fmt.Errorf("key counter overflow for %s", r.Nick)
		}
		nonce := make([]byte, 12)
		binary.BigEndian.PutUint32(nonce[0:], random())
		binary.BigEndian.PutUint32(nonce[4:], r.My.KeyID)
		binary.BigEndian.PutUint32(nonce[8:], keyCount[r.My.KeyID])
		block, err := aes.NewCipher(r.My.Secret)
		if err != nil {
			return m, fmt.Errorf("aes.NewCipher failed: %s", err)
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return m, fmt.Errorf("cipher.NewGCM failed: %s", err)
		}
		ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
		keyCount[r.My.KeyID] = keyCount[r.My.KeyID] + uint32(n)
		file := fmt.Sprintf("%s/%08x", nicks[i], keyCount[r.My.KeyID])
		nonce = append(nonce, ciphertext...)
		if puckfs != nil {
			if puckfs.sec.DEBUG {
				fmt.Printf("WriteFile %s\n", file)
			}
			if err = puckfs.WriteFile(file, nonce); err != nil {
				return m, fmt.Errorf("failed delivery to %s: %s", nicks[i], err)
			}
		}
		saveKeyCount() // somewhat wasteful but safest
	}
	return m, ovfl
	// If ovfl, messages were sent but exceeded key counter limit.
	// This is a soft fail; don't ignore it, but don't panic.
}

// We received an encrypted message with (keyID); let's figure out who it is from.
func peerLookup(keyID uint32) (p *Principal, err error) {
	for _, peer := range db.Peers {
		if peer.Their.KeyID == keyID {
			return peer, nil
		}
	}
	return p, fmt.Errorf("no peer found for keyID %0x", keyID)
}

// We received (data) which may be malicious. Either return parsed Message struct or error.
func validateMessage(data []byte) (m Message, err error) {
	var sender *Principal
	nonce := data[:12]
	ciphertext := data[12:]
	var plaintext []byte
	keyID := binary.BigEndian.Uint32(nonce[4:8])
	if sender, err = peerLookup(keyID); err != nil {
		return m, err
	}
	kc := binary.BigEndian.Uint32(nonce[8:12])
	if kc < keyCount[keyID] {
		log.Fatalf("keyID %0x keyCount inconsistency %d %d", keyID, kc, keyCount[keyID])
	}
	block, err := aes.NewCipher(sender.Their.Secret)
	if err != nil {
		return m, fmt.Errorf("aes.NewCipher failed: %s", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return m, fmt.Errorf("cipher.NewGCM failed: %s", err)
	}
	if plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil); err != nil {
		return m, err
	}
	ver := binary.BigEndian.Uint32(plaintext[0:4])
	if ver != VERSION {
		return m, fmt.Errorf("mismatched VERSION; got %x, want %x", ver, VERSION)
	}
	m.MsgType = MessageType(plaintext[4:8])
	m.Date = int64(binary.BigEndian.Uint64(plaintext[8:16]))
	m.From = ID(binary.BigEndian.Uint32(plaintext[16:20]))
	nr := int(binary.BigEndian.Uint16(plaintext[20:22]))
	if nr > 100 {
		return m, fmt.Errorf("implausibly large number of recipients %d", nr)
	}
	m.To = make([]ID, nr)
	for i := 0; i < nr; i++ {
		m.To[i] = ID(binary.BigEndian.Uint32(plaintext[22+i*4 : 26+i*4]))
	}
	m.Indirect = false
	m.Body = plaintext[22+nr*4:]
	m.fn = "unset"
	keyCount[keyID] = kc
	return m, nil
}

// Convert Message file contents (b) from file (fn) to Message struct.
// Message files have the following format, intended for anyone to be able to read
// even if they have never seen any documentation or source code.
// date nnnnnnnnnn local time including zone
// from hhhhhhhh me
// to hhhhhhhh Bob
// to hhhhhhhh Carol
// msgtype UTF8 or JPEG or whatever   (if not the default, which is UTF8)
// indirect  (if not the default, which is that body includes message contents)
// {empty line}
// {remaining bytes of file}    {or local filename if indirect}
func unmarshalMessage(fn string, b []byte) (Message, error) {
	b, date, err := hdrInt64(b, "date ")
	if err != nil {
		return Message{}, fmt.Errorf("%s bad date %s", fn, err)
	}

	b, u32, err := hdrUint32Hex(b, "from ")
	if err != nil {
		return Message{}, fmt.Errorf("%s bad from %s", fn, err)
	}
	from := ID(u32)

	to := make([]ID, 0, 5)
	for {
		b, u32, err = hdrUint32Hex(b, "to ")
		if err == unmatchedError && len(to) > 0 {
			break // finished all the to lines
		}
		if err != nil {
			return Message{}, fmt.Errorf("%s bad to %s", fn, err)
		}
		to = append(to, ID(u32))
	}

	typ := "UTF8"
	b, v, err := keyval(b, "msgtype")
	if err == nil {
		typ = v
	}
	if typ != "UTF8" && typ != "JPEG" {
		return Message{}, fmt.Errorf("unrecognized msgtype %s", typ)
	}

	indirect := false
	b, _, err = keyval(b, "indirect")
	if err == nil {
		indirect = true
	}

	if len(b) == 0 || b[0] != '\n' {
		return Message{}, fmt.Errorf("missing separating newline %s", b)
	}
	return Message{date, from, to, MessageType(typ), indirect, b[1:], fn}, nil
}

// parseDraft is very similar to unmarshalMessage, but for human-created input.
// Specifically, it expects (b) of the form
//    to nicks
//
//    some text
// or perhaps
//    to nicks
//    msgtype JPEG
//    indirect
//
//    foo.jpg
func parseDraft(b []byte) ([]byte, MessageType, bool, []string, error) {
	var v string
	var err error
	nicks := make([]string, 0)
	for {
		b, v, err = keyval(b, "to")
		if err == unmatchedError {
			break
		}
		if err != nil {
			return nil, "", false, nil, fmt.Errorf("bad to")
		}
		nicks = append(nicks, v)
	}
	typ := "UTF8"
	b, v, err = keyval(b, "msgtype")
	if err == nil {
		typ = v
	}
	if typ != "UTF8" && typ != "JPEG" {
		return nil, "", false, nil, fmt.Errorf("unrecognized msgtype %s", typ)
	}
	indirect := false
	b, _, err = keyval(b, "indirect")
	if err == nil {
		indirect = true
	}
	if len(b) == 0 || b[0] != '\n' {
		return nil, "", false, nil, fmt.Errorf("missing separating newline %s", b)
	}
	return b[1:], MessageType(typ), indirect, nicks, nil
}

// At command startup, load all the messages.
// Decrypted messages are locally stored as individual files "m/aa/bb".
func readMessages() {
	md, err := ioutil.ReadDir("m")
	if err != nil || len(md) < 1 {
		log.Fatalf("missing messages directory? %d %s", len(md), err)
	}
	mdf := md[0].Name()
	messno := 0
	for {
		mf := filenameMessage(messno)
		if mf[2:4] != mdf {
			// As a performance optimization, don't try reading non-existent directory.
			if mf[2:4] < mdf { // only expected if message subdirs were archived
				messno++
				continue
			} // else mf[2:4] > mdf
			if len(md) == 1 {
				break // exit loop, there are no more stored messages
			}
			md = md[1:] // advance to next subdir
			mdf = md[0].Name()
			continue
		}
		b, err := ioutil.ReadFile(mf)
		if os.IsNotExist(err) {
			messno++
			continue
		}
		if err != nil {
			log.Fatalf("unable to read '%s': %s", mf, err)
		}
		mess, err := unmarshalMessage(mf, b)
		if err != nil {
			log.Fatalf("unable to parse %s: %s", mf, err)
		}
		Messages = append(Messages, mess)
		MessageCounter = messno
		messno++
	}
	if MessageCounter > 400000 {
		log.Fatalf("past time for a new Message database!")
	}
	if MessageCounter > 40000 {
		log.Printf("time for a new Message database design %d", messno)
	}
}

// When sending a message, archive locally. Try not to drop anything without warning.
func storeMessage(mess Message) error {
	MessageCounter++
	bb := filenameMessage(MessageCounter)
	err := os.MkdirAll(path.Dir(bb), 0700)
	if err != nil {
		return fmt.Errorf("unable to create message directory %s: %s", path.Dir(bb), err)
	}
	f, err := os.Open(bb)
	if err == nil {
		_ = f.Close()
		return fmt.Errorf("Yikes! refuse to store over existing %s", bb)
	}
	f, err = os.OpenFile(bb, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("unable to create %s: %s", bb, err)
	}

	hdr := fmt.Sprintf("date %d %s\nfrom %x %s\n",
		mess.Date, time.Unix(mess.Date, 0).Local().Format("2006-01-02 15:04:05 -0700"),
		mess.From, nick[mess.From])
	for _, t := range mess.To {
		hdr += fmt.Sprintf("to %x %s\n", t, nick[t])
	}
	hdr += fmt.Sprintf("msgtype %s\n", mess.MsgType)
	if mess.Indirect {
		hdr += fmt.Sprintf("indirect\n")
	}
	hdr += "\n"
	_, err = f.Write([]byte(hdr))
	if err != nil {
		return fmt.Errorf("error writing hdr %s: %s", bb, err)
	}
	_, err = f.Write(mess.Body)
	if err != nil {
		return fmt.Errorf("error writing body %s: %s", bb, err)
	}

	err = f.Chmod(0400) // read-only to prevent accidents; owner can override
	if err != nil {
		return fmt.Errorf("error from Chmod() %s: %s", bb, err)
	}
	err = f.Sync()
	if err != nil {
		return fmt.Errorf("error from Sync() %s: %s", bb, err)
	}
	err = f.Close()
	if err != nil {
		return fmt.Errorf("error closing %s: %s", bb, err)
	}
	return nil
}

func random() uint32 {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		log.Fatalf("crypto random fail: %s", err)
	}
	return binary.BigEndian.Uint32(buf[:])
}

func newKey() (k Key) {
	k.KeyID = random()
	k.KeyAlg = AES256GCMkeyalg
	k.Secret = make([]byte, 32) // 32 is the key length for AES-256
	_, err := rand.Read(k.Secret)
	if err != nil {
		log.Fatalf("random fail: %s", err)
	}
	return k
}

// Convert integer to base-26 m/aa/bb.
func filenameMessage(m int) string {
	b := []byte("m/aa/bb")
	r := m % 26
	b[6] = 'a' + byte(r)
	m = (m - r) / 26
	r = m % 26
	b[5] = 'a' + byte(r)
	m = (m - r) / 26
	r = m % 26
	b[3] = 'a' + byte(r)
	m = (m - r) / 26
	r = m % 26
	b[2] = 'a' + byte(r)
	m -= r
	if m != 0 {
		log.Fatalf("MessageCounter overflow")
	}
	return string(b)
}

func saveKeyCount() {
	x, err := json.Marshal(keyCount)
	if err != nil {
		log.Fatalf("keyCount marshal failed: %s", err)
	}
	err = ioutil.WriteFile("keyCount", x, 0)
	if err != nil {
		log.Fatalf("keyCount write failed: %s", err)
	}
}

func hdrInt64(b []byte, prefix string) ([]byte, int64, error) {
	n := len(prefix)
	if bytes.HasPrefix(b, []byte(prefix)) {
		i := bytes.IndexByte(b[n:], byte(' '))
		val, err := strconv.ParseInt(string(b[n:n+i]), 10, 64)
		if err != nil {
			return b, 0, err
		}
		j := bytes.IndexByte(b[n+i:], byte('\n'))
		if j < 0 {
			return b, 0, fmt.Errorf("unterminated line")
		}
		return b[n+i+j+1:], val, nil
	}
	return b, 0, unmatchedError
}

func hdrUint32Hex(b []byte, prefix string) ([]byte, uint32, error) {
	n := len(prefix)
	if bytes.HasPrefix(b, []byte(prefix)) {
		i := bytes.IndexByte(b[n:], byte(' '))
		val, err := strconv.ParseUint(string(b[n:n+i]), 16, 32)
		if err != nil {
			return b, 0, err
		}
		j := bytes.IndexByte(b[n+i:], byte('\n'))
		if j < 0 {
			return b, 0, fmt.Errorf("unterminated line")
		}
		return b[n+i+j+1:], uint32(val), nil
	}
	return b, 0, unmatchedError
}

func keyval(b []byte, k string) ([]byte, string, error) {
	if bytes.HasPrefix(b, []byte(k)) != true {
		return b, "", unmatchedError
	}
	b = b[len(k):]
	if b[0] != ' ' && b[0] != '\t' && b[0] != '\n' { // unsure whether to allow other unicode space
		return b, "", fmt.Errorf("missing space after %s", k)
	}
	val := b
	j := bytes.IndexByte(b, '\n')
	if j < 0 {
		b = b[:0]
	} else {
		val = b[:j]
		b = b[j+1:]
	}
	return b, string(bytes.TrimSpace(val)), nil
}

func initialLoad() {
	x, err := ioutil.ReadFile("PrincipalsDB")
	if err != nil {
		log.Fatalf("PrincipalsDB read failed: %s", err)
	}
	err = json.Unmarshal(x, &db)
	if err != nil {
		log.Fatalf("PrincipalsDB unmarshal failed: %s", err)
	}
	np := len(db.Peers)
	nick = make(map[ID]string, np+1)
	nickP = make(map[string]*Principal, np)
	nick[db.Me] = "me"
	for _, p := range db.Peers {
		nick[p.Id] = p.Nick
		nickP[p.Nick] = p
	}

	keyCount = make(map[uint32]uint32, 2*np)
	x, err = ioutil.ReadFile("keyCount")
	if err != nil {
		log.Fatalf("keyCount read failed: %s", err)
	}
	err = json.Unmarshal(x, &keyCount)
	if err != nil {
		log.Fatalf("keyCount unmarshal failed: %s", err)
	}

	readMessages()

}

// Puck is a command line tool for sending, receiving, and storing messages.
// It takes one argument, as shown in the switch below, corresponding to a single operation.
// It wastefully reads the full database each time, but that is expected to be fast and
// we prefer not to have the complexity of an interactive application.
// Use your favorite text editor and file browser; invoke this from inside.
func main() {
	var err error
	if err = main2(); err != nil {
		os.Stderr.WriteString(err.Error()+"\n")
		os.Exit(2)
	}
}

func main2() (err error){
	var data []byte
	if len(os.Args) < 2 {
		return errors.New("missing subcommand")
	}
	defer brokerClose()

	switch os.Args[1] {
	case "broker-key": // new puck - broker key, an expert-level tool for prototype puck setup
		id := (random() & 0x00fffffe) | (puckfsVERSION << 24)
		sec := &secretFile{false, 0, 0, 1200, id, Keygen(), ":9901"}
		if data, err = json.MarshalIndent(sec, "", "\t"); err != nil {
			return fmt.Errorf("%v", err)
		}
		data = append(data, '\n')
		if _, err = fmt.Printf("%s\n", data); err != nil {
			return fmt.Errorf("%v", err)
		}
	case "f", "fetch": // Retrieve any pending traffic from broker.
		var fi []fs.FileInfo
		var mess Message
		initialLoad()
		brokerOpen()
		if fi, err = puckfs.ReadDir("in"); err != nil {
			return fmt.Errorf("broker: in: %v", err)
		}
		for _, file := range fi {
			fn := file.Name()
			if file.IsDir() {
				return fmt.Errorf("unexpected directory in/%s", fn)
			}
			if data, err = puckfs.ReadFile("in/"+fn); err != nil {
				return fmt.Errorf("read err on message: %v", err)
			}
			if mess, err = validateMessage(data); err != nil {
				return fmt.Errorf("unable to validate mess: %s", err)
				// Eventually, report and skip, maybe also delete from broker.
				//    But for now, we want to study each case and deal with it manually.
			}
			// TODO skip duplicates
			// TODO split out image or other indirect
			Messages = append(Messages, mess)
			if err = storeMessage(mess); err != nil {
				return fmt.Errorf("storeMessage failed: %s", err)
			}
			if err = puckfs.Remove("in/"+fn); err != nil {
				return fmt.Errorf("unable to remove in/%s: %s", fn, err)
			}
		}
	case "introduction":
		if len(os.Args) < 4 {
			return errors.New("usage: hotline introduction 12345 eric")
		}
		var id uint64
		id, err = strconv.ParseUint(os.Args[2], 10, 32)
		if err != nil {
			return fmt.Errorf("unexpected Id format %s: %s", os.Args[2], err)
		}
		var p Principal
		p.Id = ID(uint32(id))
		p.Nick = os.Args[3]
		p.Note = "introduction " + time.Now().Format(time.RFC3339)
		p.My = newKey() // random values just to prevent accidents
		p.Their = newKey()
		initialLoad()
		if ex, ok := nick[p.Id]; ok {
			return fmt.Errorf("Id %d already in use by %s", p.Id, ex)
		}
		if pex, ok := nickP[p.Nick]; ok {
			return fmt.Errorf("nickname %s already in use with Id %d", p.Nick, pex.Id)
		}
		db.Peers = append(db.Peers, &p)
		nick[p.Id] = p.Nick
		nickP[p.Nick] = &p
		err = saveDB()
		// next step will be face-to-face "rekey" to overwrite the random values
	case "l", "list": // Show all saved messages, sent or received.
		initialLoad()
		for _, msg := range Messages {
			t := time.Unix(msg.Date, 0).Format("2006-01-02 15:04:05")
			dir := ">"
			correspondent := nick[msg.To[0]]
			if msg.From != db.Me {
				dir = "<"
				correspondent = nick[msg.From]
			}
			ellipsis := ""
			if len(msg.To) > 1 {
				ellipsis = ".."
			}
			j := bytes.IndexByte(msg.Body, '\n')
			if j < 0 {
				j = len(msg.Body)
			}
			if j > 40 {
				j = 40
			}
			fmt.Printf("%s %s %s%s%s %q\n", msg.fn, t, dir, correspondent, ellipsis, msg.Body[:j])
		}
	case "puckfs-share":
		// This is for prototype testing only. The real puckfs server is part of broker, not puck.
		if len(os.Args) < 3 {
			return errors.New("usage: hotline puckfs-share dir")
		}
		if puckfs, err = Listen("broker-secret"); err != nil {
			return fmt.Errorf("Listen with broker-secret: %v", err)
		}
		if err = os.Chdir(os.Args[2]); err != nil {
			return fmt.Errorf("chdir %s: %v", os.Args[2], err)
		}
		// TODO  unveil(".","rwc")
		chanSignal := make(chan os.Signal, 1)
		signal.Notify(chanSignal, os.Interrupt)
		go func() {
			sighandler( <-chanSignal )
		}()
		puckfs.HandleRPC()
		// puckfs = nil // TODO not needed?
		log.Fatal("broker shutting down")
	case "rekey":
		// This is an experiment in how to set or reset the keys for a pair of
		// principals. It has the advantage that the Puck never needs to listen
		// on a port, unlike face-to-face ethernet. But it is not a general solution
		// because random strings are awkward to type and not really random
		// and the system is specific to AES keylength.
		// TODO Rekey should also reset snd.w, rcv.w in *-secret.
		initialLoad()
		if len(os.Args) != 4 {
			return errors.New("usage: hotline rekey eric 'random string'")
		}
		p, ok := nickP[os.Args[2]]
		if !ok {
			return fmt.Errorf("unrecognized nickname %s", os.Args[2])
		}
		r := os.Args[3]
		if len(r) < 16 {
			return fmt.Errorf("implausibly short: %s", r)
		}
		p.Note = "rekey " + time.Now().Format(time.RFC3339)
		b := make([]byte, 4+len(r))
		// My.Key
		binary.BigEndian.PutUint32(b[0:], uint32(db.Me))
		copy(b[4:], []byte(r))
		sum := sha512.Sum384(b)
		p.My.KeyID = binary.BigEndian.Uint32(sum[0:4])
		p.My.KeyAlg = AES256GCMkeyalg
		p.My.Secret = make([]byte, 32)
		copy(p.My.Secret, sum[4:36])
		// Their.Key
		binary.BigEndian.PutUint32(b[0:], uint32(p.Id))
		copy(b[4:], []byte(r))
		sum = sha512.Sum384(b)
		p.Their.KeyID = binary.BigEndian.Uint32(sum[0:4])
		p.Their.KeyAlg = AES256GCMkeyalg
		p.Their.Secret = make([]byte, 32)
		copy(p.Their.Secret, sum[4:36])
		err = saveDB()
	case "s", "send":
		initialLoad()
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed read stdin: %s", err)
		}
		b, msgtyp, indirect, recipients, err := parseDraft(b)
		if err != nil {
			return fmt.Errorf("failed parsing draft message: %s", err)
		}
		brokerOpen()
		mess, err := sendTo(recipients, string(b), msgtyp, indirect)
		if err != nil {
			return fmt.Errorf("sendTo: %s", err)
		}
		Messages = append(Messages, mess)
		err = storeMessage(mess)
		if err != nil {
			return fmt.Errorf("storeMessage failed: %s", err)
		}
	case "v", "version":
		fmt.Printf("puck magic 0x%x\n", VERSION)
	default:
		return fmt.Errorf("unrecognized subcommand %s\n", os.Args[1])
	}
	return
}

func saveDB() (err error){
	var x []byte
	x, err = json.MarshalIndent(db, "", " ")
	if err != nil {
		return fmt.Errorf("json.Marshal failed: %s", err)
	}
	x = append(x, '\n')
	sav := fmt.Sprintf("archiveDB/%d", time.Now().Unix())
	err = os.Rename("PrincipalsDB", sav)
	if err != nil {
		return fmt.Errorf("archiving PrincipalsDB failed: %s", err)
	}
	err = ioutil.WriteFile("PrincipalsDB", x, 0400)
	if err != nil {
		return fmt.Errorf("Yikes! writing PrincipalsDB failed: %s", err)
	}
	return
}

func sighandler(sig os.Signal) {
	if sig == syscall.SIGINT {
		// This has a data race, but usually gets manually invoked during a quiet time.
		writeSecretFile(puckfs)
		log.Fatalf("caught %s; tried to save packet counters", sig)
	} else {
		log.Printf("ignoring signal %s", sig)
	}
}

func brokerOpen() {
	var err error
	if puckfs != nil {
		return
	}
	if puckfs, err = Dial("puck-secret"); err != nil {
		log.Fatalf("unable to Dial broker: %s", err)
	}
}

func brokerClose() {
	if puckfs != nil {
		puckfs.Close()
		puckfs = nil
	}
}

