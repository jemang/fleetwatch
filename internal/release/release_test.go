package release

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abc  fleetwatch-agent-linux-arm64\n")
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, data, sig); err != nil {
		t.Fatalf("a good signature was refused: %v", err)
	}
	if Verify(pub, append([]byte("x"), data...), sig) == nil {
		t.Error("changed data was accepted")
	}
	bad := bytes.Clone(sig)
	bad[len(bad)-1] ^= 1
	if Verify(pub, data, bad) == nil {
		t.Error("a changed signature was accepted")
	}
	if Verify(pub, data, nil) == nil {
		t.Error("an empty signature was accepted")
	}
	_, otherPub, _ := GenerateKey()
	if Verify(otherPub, data, sig) == nil {
		t.Error("a signature from another key was accepted")
	}
	if Verify([]byte("not a key"), data, sig) == nil {
		t.Error("a broken public key was accepted")
	}
	if _, err := Sign([]byte("not a key"), data); err == nil {
		t.Error("a broken private key was accepted")
	}
}

func TestSumsMatchesSha256sumFormat(t *testing.T) {
	sums := Sums(map[string][]byte{"b.bin": []byte("abc"), "a.bin": nil})
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  a.bin\n" +
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  b.bin\n"
	if string(sums) != want {
		t.Errorf("Sums =\n%s\nwant\n%s", sums, want)
	}
	if got, ok := SumFor(sums, "b.bin"); !ok || got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("SumFor(b.bin) = %q, %v", got, ok)
	}
	if _, ok := SumFor(sums, "bin"); ok {
		t.Error("SumFor must match the whole name")
	}
	if _, ok := SumFor([]byte("short  b.bin\n"), "b.bin"); ok {
		t.Error("SumFor must refuse a value that is not a SHA-256 checksum")
	}
	if Check(sums, "b.bin", []byte("abc")) != nil || Check(sums, "b.bin", []byte("abd")) == nil || Check(sums, "c.bin", nil) == nil {
		t.Error("Check must accept only the listed content")
	}
}

// The installer verifies with the openssl program, so the two must agree.
func TestOpenSSLAcceptsTheSignature(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
	dir := t.TempDir()
	priv, pub, _ := GenerateKey()
	data := []byte("some checksums\n")
	sig, _ := Sign(priv, data)
	for name, b := range map[string][]byte{"pub.pem": pub, "SHA256SUMS": data, "SHA256SUMS.sig": sig} {
		os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	verify := func() (string, error) {
		out, err := exec.Command("openssl", "dgst", "-sha256", "-verify", filepath.Join(dir, "pub.pem"),
			"-signature", filepath.Join(dir, "SHA256SUMS.sig"), filepath.Join(dir, "SHA256SUMS")).CombinedOutput()
		return string(out), err
	}
	if out, err := verify(); err != nil || !strings.Contains(out, "Verified OK") {
		t.Fatalf("openssl refused a good signature: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("other checksums\n"), 0o600)
	if out, err := verify(); err == nil {
		t.Fatalf("openssl accepted changed data: %s", out)
	}
}

func TestWriteKeyRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	key, pub := filepath.Join(dir, "k", "signing-key.pem"), filepath.Join(dir, "p", "pubkey.pem")
	if err := WriteKey(key, pub); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(key)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("private key: %v, mode %v", err, st.Mode())
	}
	before, _ := os.ReadFile(key)
	if err := WriteKey(key, pub); err == nil {
		t.Error("an existing key must not be replaced")
	}
	if after, _ := os.ReadFile(key); !bytes.Equal(before, after) {
		t.Error("the key changed")
	}
}

func TestSignDir(t *testing.T) {
	dir := t.TempDir()
	key, pubPath := filepath.Join(dir, "signing-key.pem"), filepath.Join(dir, "pubkey.pem")
	WriteKey(key, pubPath)
	out := filepath.Join(dir, "dl")
	os.Mkdir(out, 0o755)
	if err := SignDir(key, out); err == nil {
		t.Error("a release without its files must be refused")
	}
	for _, name := range Files {
		os.WriteFile(filepath.Join(out, name), []byte("content of "+name), 0o644)
	}
	if err := SignDir(key, out); err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(pubPath)
	sums, _ := os.ReadFile(filepath.Join(out, SumsFile))
	sig, _ := os.ReadFile(filepath.Join(out, SigFile))
	if err := Verify(pub, sums, sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	for _, name := range Files {
		if Check(sums, name, []byte("content of "+name)) != nil {
			t.Errorf("%s is missing from the checksums", name)
		}
	}
}
