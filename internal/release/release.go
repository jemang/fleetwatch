// Package release signs and verifies the agent files a Hub hands out.
package release

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	SumsFile    = "SHA256SUMS"
	SigFile     = "SHA256SUMS.sig"
	VersionFile = "VERSION"
)

// AgentFile is the name of the agent file for one processor type.
func AgentFile(arch string) string { return "fleetwatch-agent-linux-" + arch }

// Files are the signed files of a release.
var Files = []string{AgentFile("amd64"), AgentFile("arm64"), VersionFile}

var ErrBadSignature = errors.New("release: the signature does not match")

// GenerateKey makes a signing key pair, both PEM encoded.
func GenerateKey() (privPEM, pubPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), nil
}

// Sign returns the signature in the form `openssl dgst -sha256 -verify` reads.
func Sign(privPEM, data []byte) ([]byte, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("release: the private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("release: private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("release: the private key is not an ECDSA key")
	}
	sum := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, key, sum[:])
}

func Verify(pubPEM, data, sig []byte) error {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return errors.New("release: the public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("release: public key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("release: the public key is not an ECDSA key")
	}
	sum := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(key, sum[:], sig) {
		return ErrBadSignature
	}
	return nil
}

// Sums lists the checksums in the format of the sha256sum program.
func Sums(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return []byte(b.String())
}

// SumFor finds the checksum of one file in a checksum list.
func SumFor(sums []byte, name string) (string, bool) {
	for _, line := range strings.Split(string(sums), "\n") {
		sum, file, ok := strings.Cut(line, "  ")
		if ok && file == name && len(sum) == sha256.Size*2 {
			return sum, true
		}
	}
	return "", false
}

// Check reports whether content is what the checksum list names.
func Check(sums []byte, name string, content []byte) error {
	want, ok := SumFor(sums, name)
	if !ok {
		return fmt.Errorf("release: %s is not in the checksum list", name)
	}
	got := sha256.Sum256(content)
	if hex.EncodeToString(got[:]) != want {
		return fmt.Errorf("release: %s does not match its checksum", name)
	}
	return nil
}

// WriteKey makes a key pair and writes both files. It never replaces a key.
func WriteKey(keyPath, pubPath string) error {
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("release: %s exists; a signing key is never replaced", keyPath)
	}
	priv, pub, err := GenerateKey()
	if err != nil {
		return err
	}
	for _, p := range []string{keyPath, pubPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		return err
	}
	return os.WriteFile(pubPath, pub, 0o644)
}

// SignDir writes the checksum list of a release directory and its signature.
func SignDir(keyPath, dir string) error {
	priv, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	files := map[string][]byte{}
	for _, name := range Files {
		if files[name], err = os.ReadFile(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	sums := Sums(files)
	sig, err := Sign(priv, sums)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, SumsFile), sums, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SigFile), sig, 0o644)
}
