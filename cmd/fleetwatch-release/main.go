// Command fleetwatch-release makes the signing key and signs a release
// directory. It runs on the release machine only.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"fleetwatch/internal/release"
	"fleetwatch/internal/release/pubkey"
)

// checkAgainstBuiltInKey fails a release that the agents would refuse: they
// verify with the public key compiled into them, not with the one beside
// the private key.
func checkAgainstBuiltInKey(dir string) error {
	sums, err := os.ReadFile(filepath.Join(dir, release.SumsFile))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(dir, release.SigFile))
	if err != nil {
		return err
	}
	if release.Verify(pubkey.PEM, sums, sig) != nil {
		return errors.New("the signing key does not belong to internal/release/pubkey/pubkey.pem; agents would refuse this release")
	}
	return nil
}

const usage = "usage: fleetwatch-release keygen --key FILE --pub FILE | sign --key FILE --dir DIR"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	key := fs.String("key", "", "private key file")
	pub := fs.String("pub", "", "public key file to write")
	dir := fs.String("dir", "", "release directory")
	fs.Parse(os.Args[2:])
	var err error
	switch {
	case os.Args[1] == "keygen" && *key != "" && *pub != "":
		if err = release.WriteKey(*key, *pub); err == nil {
			fmt.Printf("private key: %s (keep it secret, keep a copy)\npublic key:  %s\n", *key, *pub)
		}
	case os.Args[1] == "sign" && *key != "" && *dir != "":
		if err = release.SignDir(*key, *dir); err == nil {
			err = checkAgainstBuiltInKey(*dir)
		}
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "fleetwatch-release: %v\n", err)
		os.Exit(1)
	}
}
