package main

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"log"
	"os"

	"golang.org/x/crypto/nacl/box"

	"github.com/benburkert/lockbox"
)

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "g", "gen", "generate":
		generate()
	case "e", "encrypt":
		encrypt()
	case "d", "decrypt":
		decrypt()
	case "h", "help":
		help()
	default:
		help()
		os.Exit(1)
	}
}

func generate() {
	filename := os.Args[2]

	pkf, err := os.Create(filename + ".ekey")
	if err != nil {
		log.Fatal(err)
	}
	skf, err := os.Create(filename + ".dkey")
	if err != nil {
		log.Fatal(err)
	}

	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	pkb := pem.Block{
		Type:  "LOCKBOX ENCRYPTION KEY",
		Bytes: pk[:],
	}
	skb := pem.Block{
		Type:  "LOCKBOX DECRYPTION KEY",
		Bytes: sk[:],
	}

	if err := pem.Encode(pkf, &pkb); err != nil {
		log.Fatal(err)
	}
	if err := pem.Encode(skf, &skb); err != nil {
		log.Fatal(err)
	}
}

func encrypt() {
	filename := os.Args[2]
	if _, err := os.Stat(filename); err != nil {
		log.Fatal(err)
	}

	e, err := lockbox.LoadEncryptor(filename)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(os.Stdin); err != nil {
		log.Fatal(err)
	}

	data, err := e.Encrypt(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	os.Stdout.Write(data)
}

func decrypt() {
	filename := os.Args[2]
	if _, err := os.Stat(filename); err != nil {
		log.Fatal(err)
	}

	d, err := lockbox.LoadDecryptor(filename)
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(os.Stdin); err != nil {
		log.Fatal(err)
	}

	data, err := d.Decrypt(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	os.Stdout.Write(data)
}

func help() {
}
