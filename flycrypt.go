package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/tchajed/wordenc"
	"golang.org/x/crypto/nacl/box"
)

func init() {
	log.SetFlags(0)
	log.SetPrefix("flycrypt: ")
}

func main() {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("[k]ey  [e]nc  [d]ec: ")
		line, _ := reader.ReadString('\n')
		if len(line) == 0 {
			continue
		}
		switch strings.ToLower(line)[0] {
		case 'k':
			key()
			return
		case 'e':
			encrypt(reader)
			return
		case 'd':
			decrypt(reader)
			return
		}
	}
}

func key() {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("box.GenerateKey error: %s", err)
	}
	pubStr := base32.EncodeToString(public[:])
	pubWordEncoded := wordenc.EncodeToString(public[:])
	privStr := base32.EncodeToString(private[:])
	fmt.Println()
	fmt.Printf(" Public key: %s\n", pubStr)
	fmt.Println(pubWordEncoded)
	fmt.Println()
	fmt.Printf("Private key: %s (SAVE THIS)\n", privStr)
}

func encrypt(reader *bufio.Reader) {
	fmt.Printf("Public key: ")
	line, _ := reader.ReadString('\n')
	if len(line) == 0 {
		log.Fatalf("unable to read key")
	}

	data, err := wordenc.DecodeString(line)
	if err != nil || len(data) != 32 {
		data, err = base32.DecodeString(strings.TrimSpace(line))
		if err != nil || len(data) != 32 {
			log.Fatalf("failed to decode key")
		}
	}
	theirPublic := new([32]byte)
	copy(theirPublic[:], data)

	fmt.Printf(">> Message (^D to finish):\n")
	message, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Fatalf("error reading input: %s", err)
	}

	myPublic, myPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("box.GenerateKey error: %s", err)
	}

	// users shouldn't reuse keys, but use a 64-bit nonce, just in case
	nonce := new([24]byte)
	if n, _ := rand.Read(nonce[0:8]); n != 8 {
		log.Fatalf("failed to generate randomness")
	}

	out := append(myPublic[:], nonce[0:8]...)
	out = box.Seal(out, message, nonce, theirPublic, myPrivate)

	outStr := base32.EncodeToString(out)
	fmt.Printf("\n-- Ciphertext --\n%s\n", outStr)
}

func decrypt(reader *bufio.Reader) {
	fmt.Printf("Private key: ")
	line, _ := reader.ReadString('\n')
	if len(line) == 0 {
		log.Fatalf("unable to read key")
	}

	data, err := base32.DecodeString(strings.TrimSpace(line))
	if err != nil || len(data) != 32 {
		log.Fatalf("failed to decode key")
	}
	myPrivate := new([32]byte)
	copy(myPrivate[:], data)

	fmt.Printf(">> Ciphertext (^D to finish):\n")
	ctxtData, err := ioutil.ReadAll(reader)
	if err != nil {
		log.Fatalf("error reading input: %s", err)
	}

	ctxtStr := filter(ctxtData)
	ctxt, err := base32.DecodeString(ctxtStr)
	if err != nil {
		log.Fatalf("error decoding ciphertext: %s", err)
	}
	if len(ctxt) < 40+box.Overhead {
		log.Fatalf("invalid ciphertext")
	}

	theirPublic := new([32]byte)
	nonce := new([24]byte)
	copy(theirPublic[:], ctxt[0:32])
	copy(nonce[0:8], ctxt[32:40])

	msg, ok := box.Open(nil, ctxt[40:], nonce, theirPublic, myPrivate)
	if !ok {
		log.Fatalf("ciphertext authentication failed")
	}

	fmt.Println("\n-- Message --")
	fmt.Println(string(msg))
}

func filter(data []byte) string {
	clean := make([]byte, 0, len(data))
	for _, b := range data {
		if (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			clean = append(clean, b)
		}
	}
	return strings.ToLower(string(clean))
}
