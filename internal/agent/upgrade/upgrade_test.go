package upgrade

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fleetwatch/internal/release"
)

type rel struct {
	files map[string][]byte
	pub   []byte
}

// newRelease signs a release whose arm64 agent file is content.
func newRelease(t *testing.T, version, content string) *rel {
	t.Helper()
	priv, pub, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		release.AgentFile("amd64"): []byte("amd64 " + content), release.AgentFile("arm64"): []byte(content),
		release.VersionFile: []byte(version + "\n"),
	}
	sums := release.Sums(files)
	sig, _ := release.Sign(priv, sums)
	files[release.SumsFile], files[release.SigFile] = sums, sig
	return &rel{files: files, pub: pub}
}

func (r *rel) fetch(_ context.Context, name string) ([]byte, error) {
	b, ok := r.files[name]
	if !ok {
		return nil, errors.New("not found: " + name)
	}
	return b, nil
}

func installed(t *testing.T, content string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "fleetwatch-agent")
	if err := os.WriteFile(exe, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

func TestUpgradeReplacesTheFile(t *testing.T) {
	r := newRelease(t, "0.2.0", "new agent")
	exe := installed(t, "old agent")
	res, err := Run(context.Background(), Options{Fetch: r.fetch, PublicKey: r.pub, Arch: "arm64", Current: "0.1.0", Exe: exe})
	if err != nil || !res.Changed || res.From != "0.1.0" || res.To != "0.2.0" {
		t.Fatalf("Run = %+v, %v", res, err)
	}
	b, _ := os.ReadFile(exe)
	st, _ := os.Stat(exe)
	if string(b) != "new agent" || st.Mode().Perm() != 0o755 {
		t.Errorf("installed file = %q, mode %v", b, st.Mode())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), "*")); len(left) != 1 {
		t.Errorf("no temporary file may stay behind: %v", left)
	}
}

func TestUpgradeRefusesWhatTheKeyDidNotSign(t *testing.T) {
	cases := map[string]func(r *rel){
		"changed agent file": func(r *rel) { r.files[release.AgentFile("arm64")] = []byte("evil") },
		"changed checksum list": func(r *rel) {
			r.files[release.SumsFile] = release.Sums(map[string][]byte{release.AgentFile("arm64"): []byte("evil")})
		},
		"changed signature":      func(r *rel) { r.files[release.SigFile][4] ^= 1 },
		"changed version":        func(r *rel) { r.files[release.VersionFile] = []byte("9.9.9\n") },
		"missing signature":      func(r *rel) { delete(r.files, release.SigFile) },
		"signed by another key":  func(r *rel) { _, r.pub, _ = release.GenerateKey() },
		"no file for this arch":  func(r *rel) { delete(r.files, release.AgentFile("arm64")) },
		"version is not numbers": func(r *rel) { *r = *resign(t, r, "latest") },
	}
	for name, breakIt := range cases {
		r := newRelease(t, "0.2.0", "new agent")
		breakIt(r)
		exe := installed(t, "old agent")
		res, err := Run(context.Background(), Options{Fetch: r.fetch, PublicKey: r.pub, Arch: "arm64", Current: "0.1.0", Exe: exe})
		if err == nil || res.Changed {
			t.Errorf("%s: accepted (%+v)", name, res)
		}
		if b, _ := os.ReadFile(exe); string(b) != "old agent" {
			t.Errorf("%s: the installed file was changed to %q", name, b)
		}
	}
}

func resign(t *testing.T, r *rel, version string) *rel {
	t.Helper()
	return newRelease(t, version, string(r.files[release.AgentFile("arm64")]))
}

func TestUpgradeVersionRules(t *testing.T) {
	older := newRelease(t, "0.1.9", "older agent")
	exe := installed(t, "current agent")
	_, err := Run(context.Background(), Options{Fetch: older.fetch, PublicKey: older.pub, Arch: "arm64", Current: "0.2.0", Exe: exe})
	if err == nil || !strings.Contains(err.Error(), "older") {
		t.Errorf("an older version must be refused: %v", err)
	}
	res, err := Run(context.Background(), Options{Fetch: older.fetch, PublicKey: older.pub, Arch: "arm64", Current: "0.2.0", Exe: exe, AllowDowngrade: true})
	if err != nil || !res.Changed {
		t.Errorf("with AllowDowngrade: %+v, %v", res, err)
	}

	same := newRelease(t, "0.2.0", "current agent")
	exe = installed(t, "current agent")
	res, err = Run(context.Background(), Options{Fetch: same.fetch, PublicKey: same.pub, Arch: "arm64", Current: "0.2.0", Exe: exe})
	if err != nil || res.Changed {
		t.Errorf("the same file must change nothing: %+v, %v", res, err)
	}
}

func TestOlder(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"0.1.0", "0.2.0", true}, {"0.2.0", "0.1.9", false}, {"0.10.0", "0.9.0", false}, {"1.0.0", "1.0.0", false}, {"0.9.9", "1.0.0", true}}
	for _, c := range cases {
		got, err := older(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("older(%s, %s) = %v, %v; want %v", c.a, c.b, got, err, c.want)
		}
	}
	if _, err := older("1.0", "1.0.0"); err == nil {
		t.Error("a version without three numbers must be an error")
	}
}
