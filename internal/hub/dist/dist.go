// Package dist hands out the agent: the signed files and the install script.
package dist

import (
	"bytes"
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"fleetwatch/internal/hub/limit"
	"fleetwatch/internal/hub/store"
	"fleetwatch/internal/release"
)

//go:embed install.sh.tmpl
var installText string

var installTmpl = template.Must(template.New("install").Parse(installText))

// Unit is the service definition the installer writes. ProtectHome is
// read-only, not true: true hides /home behind an empty directory, and a
// separate /home file system would then report wrong sizes.
const Unit = `[Unit]
Description=FleetWatch agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/fleetwatch-agent run
User=fleetwatch
Group=fleetwatch
Restart=always
RestartSec=5
Environment=GOMEMLIMIT=48MiB
MemoryMax=64M
CPUQuota=10%
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
`

// refusal is served instead of the installer, so the one-line command fails
// with a message a person can read.
const refusal = "#!/usr/bin/env bash\necho \"%s\" >&2\nexit 1\n"

const (
	msgBadToken = "This install link is not valid any more: it was used, it expired or it was revoked. Choose Add Server in the FleetWatch dashboard for a new one."
	msgNoFiles  = "This Hub has no agent files to hand out. Build the Hub image as the README describes."
)

var tokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)

// served are the only names /dl/ answers for.
var served = append([]string{release.SumsFile, release.SigFile}, release.Files...)

type Dist struct {
	st        *store.Store
	now       func() time.Time
	publicURL string
	dir       string
	pubPEM    []byte
	limit     *limit.Limiter
}

// New serves the release files in dir. pubPEM is the release public key the
// installer verifies them with.
func New(st *store.Store, now func() time.Time, publicURL, dir string, pubPEM []byte) *Dist {
	return &Dist{st: st, now: now, publicURL: strings.TrimRight(publicURL, "/"), dir: dir, pubPEM: pubPEM,
		limit: limit.New(5, time.Minute, now)}
}

func (d *Dist) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /install/{token}", d.install)
	mux.HandleFunc("GET /dl/{name}", d.download)
}

// Missing lists the release files the directory lacks.
func (d *Dist) Missing() []string {
	var missing []string
	for _, name := range served {
		if st, err := os.Stat(filepath.Join(d.dir, name)); err != nil || st.IsDir() {
			missing = append(missing, name)
		}
	}
	return missing
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func script(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(body))
}

func (d *Dist) install(w http.ResponseWriter, r *http.Request) {
	ip := limit.RemoteIP(r)
	if !d.limit.Allow(ip) {
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	token := r.PathValue("token")
	usable := false
	if tokenShape.MatchString(token) {
		_, usable, _ = d.st.EnrollmentTokenHost(r.Context(), store.HashToken(token), d.now())
	}
	if !usable {
		d.limit.Fail(ip)
		script(w, strings.Replace(refusal, "%s", msgBadToken, 1))
		return
	}
	if len(d.Missing()) > 0 {
		script(w, strings.Replace(refusal, "%s", msgNoFiles, 1))
		return
	}
	version, _ := os.ReadFile(filepath.Join(d.dir, release.VersionFile))
	var buf bytes.Buffer
	err := installTmpl.Execute(&buf, map[string]any{
		"HubURL": d.publicURL, "HubQuoted": shellQuote(d.publicURL), "Token": token,
		"AllowHTTP": strings.HasPrefix(d.publicURL, "http://"), "Version": strings.TrimSpace(string(version)),
		"PublicKey": string(d.pubPEM), "Unit": Unit,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	script(w, buf.String())
}

func (d *Dist) download(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !slices.Contains(served, name) {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(d.dir, name)
	if st, err := os.Stat(path); err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, path)
}
