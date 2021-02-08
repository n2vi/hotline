// Copyright (c) 2020 Eric Grosse n2vi.com/0BSD

// Command puck implements hotline cryptography.
// This version implements a command line interface, which I use with the
// acme editor as GUI.
//
// Just working out ideas; don't consider this anywhere near finished.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	VERSION         = 0x484f5431 // "HOT1"
	AES256GCMkeyalg = 1
)

type ID uint32          // static, globally-unique identifier of a principal
type MessageType string // "UTF8", "JPEG", "ACK1", "QACK"
var JPEGmagic [3]byte = [3]byte{0xff, 0xd8, 0xff}
var unmatchedError = errors.New("unmatched")

type PrincipalsDB struct {
	Me    ID // my (puck's) identity
	Peers []Principal
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
var nickP map[string]Principal
var keyCount map[uint32]uint32
var Messages []Message
var MessageCounter int
var roccs *PuckFS

func sendTo(nicks []string, text string, msgtype MessageType, indirect bool) (Message, error) {
	var m Message
	var ovfl error
	var err error

	if roccs == nil {
		if roccs, err = Dial("clientdemo"); err != nil {
			log.Fatalf("unable to Dial roccs")
		}
	}

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
		file := fmt.Sprintf("%0x/%0x", r.Id, keyCount[r.My.KeyID])
		nonce = append(nonce, ciphertext...)
		if roccs != nil {
			if err = roccs.WriteFile(file, nonce); err != nil {
				return m, fmt.Errorf("failed attempting delivery to %s: %s", nicks[i], err)
			}
		}
		saveKeyCount() // somewhat wasteful but safest
	}
	return m, ovfl
	// If ovfl, messages were sent but exceeded key counter limit.
	// This is a soft fail; don't ignore it, but don't panic.
}

func peerLookup(keyID uint32) (p *Principal, err error) {
	for _, peer := range db.Peers {
		if peer.Their.KeyID == keyID {
			return &peer, nil
		}
	}
	return p, fmt.Errorf("no peer found for keyID %0x", keyID)
}

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
	copy(plaintext[4:8], m.MsgType)
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

// Decrypted messages are stored as individual files "m/aa/bb".
func readMessages() {
	md, err := ioutil.ReadDir("m")
	if err != nil || len(md) < 1 {
		log.Fatalf("missing messages directory? %s", err)
	}
	mdf := md[0].Name()
	candidate := 0
	for {
		mf := filenameMessage(candidate)
		if mf[2:4] != mdf {
			// As a performance optimization, don't try reading non-existent directory.
			if mf[2:4] < mdf { // only expected if message subdirs were archived
				candidate++
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
			candidate++
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
		MessageCounter = candidate
		candidate++
	}
	if MessageCounter > 400000 {
		log.Fatalf("past time for a new Message database!")
	}
	if MessageCounter > 40000 {
		log.Printf("time for a new Message database design %d", candidate)
	}
}

func storeMessage(mess Message) error {
	MessageCounter++
	bb := filenameMessage(MessageCounter)
	err := os.MkdirAll(path.Dir(bb), 0700)
	if err != nil {
		log.Fatalf("unable to create message directory %s: %s", path.Dir(bb), err)
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

// TODO  We need a parallel set of structs and files for recording acks.

func random() uint32 {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		log.Fatalf("crypto random fail: %s", err)
	}
	return binary.BigEndian.Uint32(buf[:])
}

func newPeer(nick string) (p Principal) {
	p.Id = ID(random())
	p.Nick = nick
	p.My = newKey()
	p.Their = newKey()
	return p
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
			log.Fatalf("unterminated line")
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
			log.Fatalf("unterminated line")
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
	if np == 0 {
		log.Fatalf("PrincipalsDB unmarshal found no peers")
	}
	nick = make(map[ID]string, np+1)
	nickP = make(map[string]Principal, np)
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

func main() {
	var err error
	if len(os.Args) < 2 {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatalf("Can't win; can't break even; can't even leave the game. %s", err)
		}
		fmt.Printf("missing subcommand in %s\n", wd)
		os.Exit(2)
	}
	initialLoad()
	defer roccsClose()

	switch os.Args[1] {
	case "f", "fetch":
		var data []byte
		var mess Message
		if roccs == nil {
			if roccs, err = Dial("clientdemo"); err != nil {
				log.Fatalf("unable to Dial roccs")
			}
		}
		// TODO read more than one
		if data, err = roccs.ReadFile("in/aa"); err != nil {
			log.Printf("no mess")
			os.Exit(4)
		}
		if mess, err = validateMessage(data); err != nil {
			roccsClose()
			log.Fatalf("unable to validate mess: %s", err)
		}
		// TODO skip duplicates
		// TODO implement JPEG indirect
		Messages = append(Messages, mess)
		MessageCounter++
	case "l", "list":
		for _, msg := range Messages {
			t := time.Unix(msg.Date, 0).Format("2006-01-02 15:04:05")
			dir := "<"
			if msg.From == db.Me {
				dir = ">"
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
			fmt.Printf("%s %s %s%s%s %q\n", msg.fn, t, dir, nick[msg.To[0]], ellipsis, msg.Body[:j])
		}
	case "n", "newpeer":
		// placeholder until we adopt the face-to-face key exchange protocol
		db.Peers = append(db.Peers, newPeer("newFriend"))
		x, err := json.MarshalIndent(db, "", " ")
		if err != nil {
			roccsClose()
			log.Fatalf("json.Marshal failed: %s", err)
		}
		sav := fmt.Sprintf("archiveDB/%d", time.Now().Unix())
		err = os.Rename("PrincipalsDB", sav)
		if err != nil {
			roccsClose()
			log.Fatalf("archiving PrincipalsDB failed: %s", err)
		}
		err = ioutil.WriteFile("PrincipalsDB", x, 0400)
		if err != nil {
			roccsClose()
			log.Fatalf("Yikes! writing PrincipalsDB failed: %s", err)
		}
		// now exit and let user edit the Nick and Note entries in PrincipalsDB
	case "puckfs-share":
		// This is for testing only. The real puckfs server is part of ROCCS, not puck.
		var p *PuckFS
		if err = os.Chdir("puckfs-share"); err != nil {
			roccsClose()
			log.Fatalf("%v", err)
		}
		if p, err = Listen("../serverdemo"); err != nil {
			roccsClose()
			log.Fatalf("%v", err)
		}
		p.HandleRPC()
	case "s", "send":
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			roccsClose()
			log.Fatalf("failed read stdin: %s", err)
		}
		b, msgtyp, indirect, recipients, err := parseDraft(b)
		if err != nil {
			roccsClose()
			log.Fatalf("failed parsing draft message: %s", err)
		}
		mess, err := sendTo(recipients, string(b), msgtyp, indirect)
		if err != nil {
			roccsClose()
			log.Fatalf("sendTo failed: %s", err)
		}
		Messages = append(Messages, mess)
		err = storeMessage(mess)
		if err != nil {
			roccsClose()
			log.Fatalf("storeMessage failed: %s", err)
		}
	case "v", "version":
		fmt.Printf("puck magic 0x%x\n", VERSION)
	default:
		fmt.Printf("unrecognized subcommand %s\n", os.Args[1])
		os.Exit(3)
	}
}

func roccsClose() {
	if roccs != nil {
		roccs.Close()
	}
	roccs = nil
}
