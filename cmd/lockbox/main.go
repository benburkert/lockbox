package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"

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
	if len(os.Args) != 3 {
		help()
		os.Exit(1)
	}

	filename := os.Args[2]
	ekey, dkey, err := lockbox.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	if err := ioutil.WriteFile(filename+".ekey", ekey, 0644); err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile(filename+".dkey", dkey, 0644); err != nil {
		log.Fatal(err)
	}
}

func encrypt() {
	if len(os.Args) != 3 {
		help()
		os.Exit(1)
	}

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
	if len(os.Args) != 3 {
		help()
		os.Exit(1)
	}

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
	fmt.Println(`lockbox - encryption/decryption tool built on NaCl

usage: lockbox <command> [<args>...]

Commands:

  generate NAME       Generate new keypair files: NAME.ekey, NAME.dkey
  encrypt EKEY        Encrypt the contents of STDIN with EKEY to STDOUT
  decrypt DKEY        Decrypt the contents of STDIN with DKEY to STDOUT
`)
}
