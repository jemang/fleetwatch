package dist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/release"
)

var now = time.Unix(1_790_000_000, 0)

type env struct {
	t   *testing.T
	st  *store.Store
	mux *http.ServeMux
	dir string
}

func setup(t *testing.T, publicURL string, withFiles bool) *env {
	t.Helper()
	e := &env{t: t, mux: http.NewServeMux(), dir: t.TempDir()}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e.st = st
	if withFiles {
		for _, name := range append([]string{release.SumsFile, release.SigFile}, release.Files...) {
			content := "content of " + name
			if name == release.VersionFile {
				content = "0.9.0\n"
			}
			os.WriteFile(filepath.Join(e.dir, name), []byte(content), 0o644)
		}
	}
	New(st, func() time.Time { return now }, publicURL, e.dir, []byte("-----BEGIN PUBLIC KEY-----\nTESTKEY\n-----END PUBLIC KEY-----\n")).Routes(e.mux)
	return e
}

func (e *env) get(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func (e *env) token() string {
	plain, _ := store.NewToken()
	if err := e.st.CreateEnrollmentToken(context.Background(), store.HashToken(plain), now, now.Add(15*time.Minute)); err != nil {
		e.t.Fatal(err)
	}
	return plain
}

func bashCheck(t *testing.T, script string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the script has a syntax error: %v\n%s", err, out)
	}
}

func TestInstallScript(t *testing.T) {
	e := setup(t, "https://hub.example.com", true)
	tok := e.token()
	w := e.get("/install/" + tok)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/x-shellscript") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d, headers %v", w.Code, w.Header())
	}
	for _, want := range []string{
		"#!/usr/bin/env bash\n", "set -euo pipefail", "HUB='https://hub.example.com'", "TOKEN='" + tok + "'", "ALLOW_HTTP=0", "0.9.0",
		"TESTKEY", `"$HUB/dl/$name"`, "openssl dgst -sha256 -verify", "sha256sum -c",
		"x86_64|amd64) arch=amd64", "aarch64|arm64) arch=arm64", "/etc/os-release", "useradd --system",
		"User=fleetwatch", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=read-only", "ProtectSystem=strict",
		"ProtectKernelTunables=true", "ProtectKernelModules=true", "ProtectControlGroups=true", "RestrictSUIDSGID=true",
		"MemoryMax=64M", "CPUQuota=10%", "Restart=always", `"$BIN" status`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the script is missing %q", want)
		}
	}
	// A download that stops half-way must run nothing: all work is in main,
	// which is called on the last line.
	if !strings.HasSuffix(body, "\nmain \"$@\"\n") {
		t.Errorf("the script must end with the call of main, ends with %q", body[len(body)-40:])
	}
	// The signature is checked before the checksum, and both before the install.
	sig, sum, inst := strings.Index(body, "openssl dgst"), strings.Index(body, "sha256sum -c"), strings.Index(body, `install -m 0755`)
	if !(sig > 0 && sig < sum && sum < inst) {
		t.Errorf("order: signature %d, checksum %d, install %d", sig, sum, inst)
	}
	// The clean-up runs when the script ends, after main has returned: a
	// variable that is local to main is gone by then.
	if regexp.MustCompile(`local [^\n]*\btmp\b`).MatchString(body) || !strings.Contains(body, `trap 'rm -rf "$tmp"' EXIT`) {
		t.Error("the temporary directory must be a global variable, or the clean-up fails with \"unbound variable\"")
	}
	bashCheck(t, body)
	if _, usable, _ := e.st.EnrollmentTokenHost(context.Background(), store.HashToken(tok), now); !usable {
		t.Error("serving the script must not use up the token")
	}
}

// pveTokenRun runs the installer's pve_token with stand-ins for pvesh and
// uname, and returns its output and the calls pvesh received.
func pveTokenRun(t *testing.T, script string, userExists, tokenFails bool) (out, calls string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not installed")
	}
	bin := t.TempDir()
	os.WriteFile(filepath.Join(bin, "uname"), []byte("#!/bin/sh\necho pve+1.example.com\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "pvesh"), []byte(`#!/bin/sh
echo "$*" >> "$LOG"
case "$1 $2" in
"get /access/users/fleetwatch@pve") [ "$USER_EXISTS" = 1 ] || { echo "no such user ('fleetwatch@pve')" >&2; exit 2; } ;;
"delete /access/users/fleetwatch@pve/token/"*) echo "no such token" >&2; exit 2 ;;
"create /access/users/fleetwatch@pve/token/"*)
  [ "$TOKEN_FAILS" = 1 ] && { echo "cluster not ready - no quorum? (500)" >&2; exit 2; }
  printf '{"full-tokenid":"fleetwatch@pve!x","info":{"privsep":"0"},\n "value" : "87672d09-0afc-4557-af63-18abe0ac98c5"}\n' ;;
esac
`), 0o755)
	log := filepath.Join(t.TempDir(), "calls")
	driver := strings.TrimSuffix(script, "main \"$@\"\n") + `tmp=$(mktemp -d)
if pve_token; then echo "ok id=$FLEETWATCH_PVE_TOKEN_ID secret=$FLEETWATCH_PVE_TOKEN_SECRET"; bash -c 'echo "child sees $FLEETWATCH_PVE_TOKEN_ID"'; else echo "failed: $pve_err"; fi
`
	cmd := exec.Command("bash")
	cmd.Stdin = strings.NewReader(driver)
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "LOG="+log, "USER_EXISTS="+flag(userExists), "TOKEN_FAILS="+flag(tokenFails))
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("driver: %v\n%s", err, b)
	}
	c, _ := os.ReadFile(log)
	return string(b), string(c)
}

func TestInstallScriptCreatesProxmoxToken(t *testing.T) {
	e := setup(t, "https://hub.example.com", true)
	script := e.get("/install/" + e.token()).Body.String()

	out, calls := pveTokenRun(t, script, false, false)
	want := "ok id=fleetwatch@pve!agent-pve-1 secret=87672d09-0afc-4557-af63-18abe0ac98c5\nchild sees fleetwatch@pve!agent-pve-1\n"
	if out != want {
		t.Errorf("output %q, want %q", out, want)
	}
	for _, c := range []string{
		"get /access/users/fleetwatch@pve", "create /access/users --userid fleetwatch@pve",
		"set /access/acl --path / --users fleetwatch@pve --roles PVEAuditor",
		"delete /access/users/fleetwatch@pve/token/agent-pve-1",
		"create /access/users/fleetwatch@pve/token/agent-pve-1 --privsep 0",
	} {
		if !strings.Contains(calls, c) {
			t.Errorf("pvesh was not called with %q; calls:\n%s", c, calls)
		}
	}

	_, calls = pveTokenRun(t, script, true, false)
	if strings.Contains(calls, "create /access/users --userid") {
		t.Errorf("an existing user must not be created again; calls:\n%s", calls)
	}

	out, _ = pveTokenRun(t, script, true, true)
	if !strings.HasPrefix(out, "failed: ") || !strings.Contains(out, "no quorum") {
		t.Errorf("a failed token must report the reason from pvesh: %q", out)
	}
}

func TestInstallScriptForPlainHTTPHub(t *testing.T) {
	e := setup(t, "http://192.168.1.5:8080", true)
	body := e.get("/install/" + e.token()).Body.String()
	if !strings.Contains(body, "HUB='http://192.168.1.5:8080'") || !strings.Contains(body, "ALLOW_HTTP=1") {
		t.Error("a plain-HTTP Hub must make the agent accept http://")
	}
}

func TestInstallScriptRefusesBadTokens(t *testing.T) {
	e := setup(t, "https://hub.example.com", true)
	used := e.token()
	e.st.Enroll(context.Background(), store.EnrollParams{EnrollTokenHash: store.HashToken(used), Hostname: "x", AgentTokenHash: "a", ProtocolVersion: 1, Now: now})
	for _, tok := range []string{"unknown", used, "$(reboot)", "a'b"} {
		w := e.get("/install/" + strings.ReplaceAll(tok, "'", "%27"))
		body := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, "not valid any more") || !strings.Contains(body, "exit 1") {
			t.Errorf("token %q: status %d body %q", tok, w.Code, body)
		}
		if strings.Contains(body, "reboot") || strings.Contains(body, "useradd") || strings.Contains(body, "TESTKEY") {
			t.Errorf("token %q: the refusal must carry neither the token nor the installer", tok)
		}
		bashCheck(t, body)
	}
	cmd := exec.Command("bash")
	cmd.Stdin = strings.NewReader(e.get("/install/unknown").Body.String())
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 || !strings.Contains(string(out), "Add Server") {
		t.Errorf("running the refusal: %v, output %q", err, out)
	}
}

func TestTooManyBadTokensAreSlowedDown(t *testing.T) {
	e := setup(t, "https://hub.example.com", true)
	for i := 0; i < 5; i++ {
		e.get("/install/unknown")
	}
	if w := e.get("/install/unknown"); w.Code != http.StatusTooManyRequests {
		t.Errorf("sixth bad token: %d, want 429", w.Code)
	}
}

func TestInstallWithoutAgentFiles(t *testing.T) {
	e := setup(t, "https://hub.example.com", false)
	body := e.get("/install/" + e.token()).Body.String()
	if !strings.Contains(body, "has no agent files") || !strings.Contains(body, "exit 1") || strings.Contains(body, "useradd") {
		t.Errorf("a Hub without agent files must say so: %q", body)
	}
}

func TestDownloads(t *testing.T) {
	e := setup(t, "https://hub.example.com", true)
	for _, name := range append([]string{release.SumsFile, release.SigFile}, release.Files...) {
		w := e.get("/dl/" + name)
		if w.Code != http.StatusOK || (name != release.VersionFile && w.Body.String() != "content of "+name) {
			t.Errorf("%s: %d %q", name, w.Code, w.Body)
		}
	}
	os.WriteFile(filepath.Join(e.dir, "secret.txt"), []byte("secret"), 0o644)
	for _, path := range []string{"/dl/secret.txt", "/dl/..%2Fx", "/dl/", "/dl/fleetwatch-agent-linux-riscv"} {
		if w := e.get(path); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, w.Code)
		}
	}
	if w := setup(t, "https://hub.example.com", false).get("/dl/" + release.SumsFile); w.Code != http.StatusNotFound {
		t.Errorf("a missing file: %d, want 404", w.Code)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"https://a.b": "'https://a.b'", "it's": `'it'\''s'`, "": "''"} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
