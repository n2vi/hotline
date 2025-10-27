// Copyright (c) 2020,2022,2025 Eric Grosse n2vi.com/0BSD

/*
Command hotline implements a simple e2e encrypted chat.
This version implements a command line interface,
which I use with the acme editor as GUI.

A message is delivered by writing files named "recipient/nanosec"
on the sender's broker via the "puckfs" network protocol. In theory,
that broker would have a set of heuristics for how to deliver to the
recipient's broker through the high-resilience ROCCS network,
though in our current simulator that is merely moving the (end-to-
end encrypted) message file from one directory to another.

If you're a fellow hotline developer, I will have already sent you a secret
file to install in $HOME/.ssh/.puckfs to talk to the broker/ROCCS-simulator
that I run. Also "echo 0 0 > $HOME/.puckfs" for the initial packet counters.
If you haven't already, download the hotline source and "go install".
Then create a directory such as $HOME/puck for your end-to-end secrets
and messages and inside that directory:

	tar xf yourpuck.tar
	hotline rekey eric randomstringwepick

Just working out ideas here; don't consider this final.
Comments welcome to grosse@gmail.com.
*/
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/n2vi/hotline/puckfs"
	"golang.org/x/crypto/chacha20poly1305"
)

type PrincipalsDB struct {
	Me    ID // my (puck's) identity
	Peers []*Principal
}
type ID uint32 // static, globally-unique identifier of a principal

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
	Date    int64
	From    ID
	To      []ID
	MsgType MessageType
	Body    []byte
	fn      string // local filename for storing the message
}
type MessageType string // "UTF8", "ACK1", "QACK"

var db PrincipalsDB
var nick map[ID]string
var nickP map[string]*Principal
var keyP map[ /*KeyID*/ uint32]*Principal
var Messages []Message
var MessageCounter int
var pfs *puckfs.PuckFS
var VERSION [4]byte = [4]byte{0x48, 0x4f, 0x54, 0x33} // "HOT3"
var errUnmatched = errors.New("unmatched")

// Send to (nicks) the (text) of form (msgtype).
// Return the Message struct or error.
func sendTo(nicks []string, text string, msgtype MessageType) (Message, error) {
	var m Message
	m.Date = time.Now().Unix()
	m.From = db.Me
	nr := len(nicks)
	if nr > 100 {
		return m, fmt.Errorf("implausibly large number of recipients %d", nr)
	}
	m.To = make([]ID, nr)
	for i := range nr {
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
	m.Body = []byte(text)
	body := m.Body

	//    4   magic
	//    4   msgtype
	//    8   unixtime
	//    4   sender
	//    2   nr
	//  4*nr recipients
	//  len  body
	n := 22 + 4*nr + len(body)
	plaintext := make([]byte, n)
	copy(plaintext[0:4], VERSION[:])
	copy(plaintext[4:8], []byte(m.MsgType))
	binary.BigEndian.PutUint64(plaintext[8:16], uint64(m.Date))
	binary.BigEndian.PutUint32(plaintext[16:20], uint32(m.From))
	binary.BigEndian.PutUint16(plaintext[20:22], uint16(nr))
	for i := range nr {
		binary.BigEndian.PutUint32(plaintext[22+i*4:], uint32(m.To[i]))
	}
	copy(plaintext[22+4*nr:], body)
	dst := make([]byte, 4+24+len(plaintext)+16)

	for i := range nr {
		r := nickP[nicks[i]]
		aead, err := chacha20poly1305.NewX(r.My.Secret)
		if err != nil {
			return m, fmt.Errorf("chacha20poly1305.NewX: %s", err)
		}
		binary.BigEndian.PutUint32(dst[0:4], r.My.KeyID) // associatedData
		rand.Read(dst[4:28])                             // nonce
		dst = aead.Seal(dst[:28], dst[4:28], plaintext, dst[0:4])
		file := fmt.Sprintf("%s/%x", nicks[i], time.Now().UnixNano())
		if pfs != nil {
			fmt.Printf("WriteFile %s\n", file)
			if err = pfs.WriteFile(file, dst); err != nil {
				return m, fmt.Errorf("failed delivery to %s: %s", nicks[i], err)
			}
		}
	}
	return m, nil
}

// We received (data) which may be malicious. Either return parsed Message struct or error.
func validateMessage(data []byte) (m Message, err error) {
	keyID := binary.BigEndian.Uint32(data[0:4])
	sender, ok := keyP[keyID]
	if !ok {
		log.Printf("validateMessage %v", data)
		return m, fmt.Errorf("no peer found for keyID %0x", keyID)
	}
	log.Printf("keyID %x=%d", data[0:4], keyID) // TODO
	aead, err := chacha20poly1305.NewX(sender.Their.Secret)
	if err != nil {
		return m, fmt.Errorf("chacha20poly1305.NewX: %s", err)
	}
	log.Printf("nonce %x ad %x ciphertext %x", data[4:28], data[0:4], data[28:]) // TODO
	plaintext, err := aead.Open(nil, data[4:28], data[28:], data[0:4])
	if err != nil {
		return m, err
	}
	if !bytes.Equal(plaintext[0:4], VERSION[:]) {
		return m, fmt.Errorf("VERSION: got %x, want %x", plaintext[0:4], VERSION)
	}
	m.MsgType = MessageType(plaintext[4:8])
	m.Date = int64(binary.BigEndian.Uint64(plaintext[8:16]))
	m.From = ID(binary.BigEndian.Uint32(plaintext[16:20]))
	nr := int(binary.BigEndian.Uint16(plaintext[20:22]))
	if nr > 100 {
		return m, fmt.Errorf("implausibly large number of recipients %d", nr)
	}
	m.To = make([]ID, nr)
	for i := range nr {
		m.To[i] = ID(binary.BigEndian.Uint32(plaintext[22+i*4 : 26+i*4]))
	}
	m.Body = plaintext[22+nr*4:]
	m.fn = "unset"
	return m, nil
}

// Convert Message file contents (b) from local file (fn) to Message struct.
// Message files have the following format, intended for anyone to be able to read
// even if they have never seen any documentation or source code.
// date nnnnnnnnnn local time including zone
// from hhhhhhhh me
// to hhhhhhhh Bob
// to hhhhhhhh Carol
// msgtype UTF8 or whatever   (default is UTF8)
// {empty line}
// {remaining bytes of file}
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
		if err == errUnmatched && len(to) > 0 {
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
	if typ != "UTF8" {
		return Message{}, fmt.Errorf("unrecognized msgtype %s", typ)
	}

	if len(b) == 0 || b[0] != '\n' {
		return Message{}, fmt.Errorf("missing separating newline %s", b)
	}
	return Message{date, from, to, MessageType(typ), b[1:], fn}, nil
}

// parseDraft is very similar to unmarshalMessage, but for human-created input.
// Specifically, it expects (b) of the form
//
//	to nicks
//
//	some text
func parseDraft(b []byte) ([]byte, MessageType, []string, error) {
	var v string
	var err error
	nicks := make([]string, 0)
	for {
		b, v, err = keyval(b, "to")
		if err == errUnmatched {
			break
		}
		if err != nil {
			return nil, "", nil, fmt.Errorf("bad to")
		}
		nicks = append(nicks, v)
	}
	typ := "UTF8"
	b, v, err = keyval(b, "msgtype")
	if err == nil {
		typ = v
	}
	if typ != "UTF8" {
		return nil, "", nil, fmt.Errorf("unrecognized msgtype %s", typ)
	}
	if len(b) == 0 || b[0] != '\n' {
		return nil, "", nil, fmt.Errorf("missing separating newline %s", b)
	}
	return b[1:], MessageType(typ), nicks, nil
}

// At command startup, load all the locally-saved messages, which are stored
// as individual cleartext files "m/aa/bb". The puck is assumed to be whole-disk encrypted.
func readMessages() {
	md, err := os.ReadDir("m")
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
		b, err := os.ReadFile(mf)
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
	if MessageCounter > 40000 {
		log.Print("past time for a new Message database!")
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
		return fmt.Errorf("yikes! refuse to store over existing %s", bb)
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

func newKey() (k Key) {
	var buf [4]byte
	rand.Read(buf[:])
	k.KeyID = binary.BigEndian.Uint32(buf[:])
	k.KeyAlg = 2 // xchacha20poly1305
	k.Secret = make([]byte, 32)
	rand.Read(k.Secret)
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
	return b, 0, errUnmatched
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
	return b, 0, errUnmatched
}

func keyval(b []byte, k string) ([]byte, string, error) {
	if !bytes.HasPrefix(b, []byte(k)) {
		return b, "", errUnmatched
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
	x, err := os.ReadFile("PrincipalsDB")
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
	keyP = make(map[uint32]*Principal, np)
	nick[db.Me] = "me"
	for _, p := range db.Peers {
		nick[p.Id] = p.Nick
		nickP[p.Nick] = p
		keyP[p.Their.KeyID] = p
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
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(2)
	}
}

func main2() (err error) {
	var data []byte
	if len(os.Args) < 2 {
		return errors.New("missing subcommand")
	}

	switch os.Args[1] {
	case "f", "fetch": // Retrieve any pending traffic from broker.
		var fi []fs.FileInfo
		var mess Message
		initialLoad()
		brokerOpen()
		defer pfs.Close()
		if fi, err = pfs.ReadDir("in"); err != nil {
			return fmt.Errorf("broker: in: %v", err)
		}
		for _, file := range fi {
			fn := file.Name()
			if file.Mode()&fs.ModeType != 0 {
				continue
			}
			if data, err = pfs.ReadFile("in/" + fn); err != nil {
				return fmt.Errorf("read err on message: %v", err)
			}
			if mess, err = validateMessage(data); err != nil {
				return fmt.Errorf("unable to validate mess: %s", err)
				// Eventually, report and skip, maybe also delete from broker.
				//    But for now, we want to study each case and deal with it manually.
			}
			Messages = append(Messages, mess)
			if err = storeMessage(mess); err != nil {
				return fmt.Errorf("storeMessage failed: %s", err)
			}
			if err = pfs.Remove("in/" + fn); err != nil {
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
			return fmt.Errorf("p.Id %d already in use by %s", p.Id, ex)
		}
		if pex, ok := nickP[p.Nick]; ok {
			return fmt.Errorf("nickname %s already in use with Id %d", p.Nick, pex.Id)
		}
		db.Peers = append(db.Peers, &p)
		nick[p.Id] = p.Nick
		nickP[p.Nick] = &p
		keyP[p.Their.KeyID] = &p
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
	case "rekey":
		// This is an experiment in how to set or reset the keys for a pair of
		// principals. It has the advantage that the Puck never needs to listen
		// on a port, unlike face-to-face ethernet. But it is not a general solution
		// because random strings are awkward to type and not really random.
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
		p.My.KeyAlg = 2 // xchacha20poly1305
		copy(p.My.Secret, sum[4:36])
		// Their.Key
		binary.BigEndian.PutUint32(b[0:], uint32(p.Id))
		copy(b[4:], []byte(r))
		sum = sha512.Sum384(b)
		p.Their.KeyID = binary.BigEndian.Uint32(sum[0:4])
		p.Their.KeyAlg = 2 // xchacha20poly1305
		copy(p.Their.Secret, sum[4:36])
		err = saveDB()
	case "s", "send":
		initialLoad()
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed read stdin: %s", err)
		}
		b, msgtyp, recipients, err := parseDraft(b)
		if err != nil {
			return fmt.Errorf("failed parsing draft message: %s", err)
		}
		brokerOpen()
		defer pfs.Close()
		mess, err := sendTo(recipients, string(b), msgtyp)
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
		return fmt.Errorf("unrecognized subcommand %s", os.Args[1])
	}
	return
}

func saveDB() (err error) {
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
	err = os.WriteFile("PrincipalsDB", x, 0400)
	if err != nil {
		return fmt.Errorf("yikes! writing PrincipalsDB failed: %s", err)
	}
	return
}

func brokerOpen() {
	if pfs != nil {
		return
	}
	secretfile, err := os.UserHomeDir()
	if err != nil {
		log.Print("unable to get UserHomeDir, using .")
		secretfile = "."
	}
	secretfile = filepath.Join(secretfile, ".ssh", ".puckfs")
	if pfs, err = puckfs.Dial(secretfile); err != nil {
		log.Fatalf("unable to Dial broker: %s", err)
	}
}
