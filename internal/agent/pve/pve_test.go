package pve

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const resources = `{"data":[
 {"id":"qemu/110","type":"qemu","vmid":110,"name":"app-server","node":"pve-01","status":"running","maxcpu":4,"cpu":0.125,"mem":2147483648,"maxmem":8589934592,"disk":0,"maxdisk":53687091200,"uptime":86400,"template":0},
 {"id":"lxc/101","type":"lxc","vmid":101,"name":"nginx","node":"pve-01","status":"running","maxcpu":2,"cpu":0.01,"mem":134217728,"maxmem":536870912,"disk":1073741824,"maxdisk":8589934592,"uptime":3600,"template":0},
 {"id":"lxc/115","type":"lxc","vmid":"115","name":"ocrmypdf","node":"pve-01","status":"stopped","maxcpu":1,"cpu":0,"mem":0,"maxmem":"536870912","disk":0,"maxdisk":8589934592,"uptime":0,"template":0},
 {"id":"qemu/900","type":"qemu","vmid":900,"name":"debian-template","node":"pve-01","status":"stopped","maxcpu":2,"template":1},
 {"id":"qemu/200","type":"qemu","vmid":200,"name":"on-another-node","node":"pve-02","status":"running","maxcpu":2,"template":0},
 {"id":"storage/pve-01/local","type":"storage","storage":"local","node":"pve-01","status":"available","plugintype":"dir","disk":42949672960,"maxdisk":107374182400,"shared":0},
 {"id":"storage/pve-01/nas","type":"storage","storage":"nas","node":"pve-01","status":"unknown","plugintype":"nfs","disk":0,"maxdisk":0,"shared":1},
 {"id":"storage/pve-02/local","type":"storage","storage":"local","node":"pve-02","status":"available","plugintype":"dir","disk":1,"maxdisk":2},
 {"id":"node/pve-01","type":"node","node":"pve-01","status":"online","maxcpu":8}
]}`

type fakeAPI struct {
	srv      *httptest.Server
	calls    map[string]*atomic.Int32
	status   atomic.Int32 // when non-zero, every call answers this status
	lastAuth atomic.Value
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{calls: map[string]*atomic.Int32{}}
	replies := map[string]string{
		"/api2/json/version":                                            `{"data":{"version":"8.2.4","release":"8.2","repoid":"faa83925"}}`,
		"/api2/json/cluster/status":                                     `{"data":[{"type":"cluster","name":"lab","nodes":2,"quorate":1},{"type":"node","name":"pve-02","local":0,"online":1},{"type":"node","name":"pve-01","local":1,"online":1,"ip":"192.168.10.10"}]}`,
		"/api2/json/cluster/resources":                                  resources,
		"/api2/json/nodes/pve-01/lxc/101/interfaces":                    `{"data":[{"name":"lo","inet":"127.0.0.1/8","inet6":"::1/128"},{"name":"eth0","hwaddr":"BC:24:11:00:00:01","inet":"192.168.10.21/24","inet6":"fe80::be24:11ff:fe00:1/64"},{"name":"eth1","inet6":"2001:db8::21/64"}]}`,
		"/api2/json/nodes/pve-01/qemu/110/agent/network-get-interfaces": `{"data":{"result":[{"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8}]},{"name":"ens18","ip-addresses":[{"ip-address":"192.168.10.30","ip-address-type":"ipv4","prefix":24},{"ip-address":"fe80::1","ip-address-type":"ipv6","prefix":64}]}]}}`,
	}
	for path := range replies {
		f.calls[path] = new(atomic.Int32)
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.lastAuth.Store(r.Header.Get("Authorization"))
		if c, ok := f.calls[r.URL.Path]; ok {
			c.Add(1)
		}
		if code := int(f.status.Load()); code != 0 {
			http.Error(w, "no", code)
			return
		}
		body, ok := replies[r.URL.Path]
		if !ok {
			http.Error(w, `{"data":null,"message":"QEMU guest agent is not running"}`, http.StatusInternalServerError)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) caFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o600)
	return p
}

func (f *fakeAPI) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(Config{APIURL: f.srv.URL, TokenID: "fleetwatch@pve!agent", TokenSecret: "secret", CAFile: f.caFile(t)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pveRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc/pve"), 0o755)
	return root
}

func TestClientSendsTokenAndTrustsOnlyTheGivenCA(t *testing.T) {
	f := newFakeAPI(t)
	var v struct{ Version string }
	if err := f.client(t).get(context.Background(), "/version", &v); err != nil || v.Version != "8.2.4" {
		t.Fatalf("version = %q, %v", v.Version, err)
	}
	if got := f.lastAuth.Load(); got != "PVEAPIToken=fleetwatch@pve!agent=secret" {
		t.Errorf("Authorization = %q", got)
	}
	// Every httptest TLS server shares one certificate, so a different CA must be made by hand.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "another CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	otherCA := filepath.Join(t.TempDir(), "other-ca.pem")
	os.WriteFile(otherCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	bad, err := NewClient(Config{APIURL: f.srv.URL, TokenID: "a", TokenSecret: "b", CAFile: otherCA})
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.get(context.Background(), "/version", &v); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("a certificate not signed by the given CA must be refused, err = %v", err)
	}
	if _, err := NewClient(Config{APIURL: f.srv.URL, TokenID: "a", TokenSecret: "b", CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Error("a missing CA file must be an error, not a silent fallback")
	}
}

func TestCollectStates(t *testing.T) {
	f := newFakeAPI(t)
	now := time.Unix(1_790_000_000, 0)
	clock := func() time.Time { return now }
	if got := (&Collector{Root: t.TempDir(), Client: f.client(t), Now: clock}).Collect(context.Background()); got != nil {
		t.Errorf("no /etc/pve: nothing must be reported, got %+v", got)
	}
	got := (&Collector{Root: pveRoot(t), Now: clock}).Collect(context.Background())
	if got == nil || !got.Detected || got.Configured || got.Guests != nil {
		t.Errorf("detected without a token = %+v", got)
	}
	got = (&Collector{Root: pveRoot(t), Problem: "pve: CA file: permission denied", Now: clock}).Collect(context.Background())
	if got == nil || !got.Configured || got.Error != "pve: CA file: permission denied" {
		t.Errorf("a token whose client could not be made must report why, not ask for a token: %+v", got)
	}
	f.status.Store(http.StatusUnauthorized)
	got = (&Collector{Root: pveRoot(t), Client: f.client(t), Now: clock}).Collect(context.Background())
	if got == nil || !got.Detected || !got.Configured || !strings.Contains(got.Error, "401") || got.Guests != nil {
		t.Errorf("rejected token = %+v", got)
	}
}

func TestCollectMapsNodeGuestsAndStorage(t *testing.T) {
	f := newFakeAPI(t)
	now := time.Unix(1_790_000_000, 0)
	got := (&Collector{Root: pveRoot(t), Client: f.client(t), Now: func() time.Time { return now }}).Collect(context.Background())
	if got == nil || got.Error != "" {
		t.Fatalf("collect = %+v", got)
	}
	if got.Version != "8.2.4" || got.Node != "pve-01" || got.Cluster != "lab" || got.Quorate == nil || !*got.Quorate {
		t.Errorf("node info = %+v", got)
	}
	if len(got.Guests) != 3 {
		t.Fatalf("guests of the local node without templates: got %d, want 3: %+v", len(got.Guests), got.Guests)
	}
	lxc, vm, stopped := got.Guests[0], got.Guests[1], got.Guests[2] // ordered by ID: 101, 110, 115
	if lxc.ID != 101 || lxc.Type != "lxc" || lxc.Name != "nginx" || lxc.Status != "running" || lxc.CPUs != 2 || lxc.CPUPct != 1 ||
		lxc.MemUsed != 134217728 || lxc.MemMax != 536870912 || lxc.DiskUsed != 1073741824 || lxc.DiskMax != 8589934592 || lxc.UptimeS != 3600 {
		t.Errorf("lxc = %+v", lxc)
	}
	if !reflect.DeepEqual(lxc.IPs, []string{"192.168.10.21", "2001:db8::21"}) {
		t.Errorf("lxc addresses = %q; loopback and link-local are left out, IPv4 first", lxc.IPs)
	}
	if stopped.ID != 115 || stopped.Status != "stopped" || stopped.MemMax != 536870912 || stopped.IPs != nil {
		t.Errorf("stopped guest (numbers sent as strings must still be read, no address lookup) = %+v", stopped)
	}
	if vm.ID != 110 || vm.Type != "qemu" || vm.CPUPct != 12.5 || !reflect.DeepEqual(vm.IPs, []string{"192.168.10.30"}) {
		t.Errorf("vm = %+v", vm)
	}
	if len(got.Storage) != 2 || got.Storage[0].Name != "local" || !got.Storage[0].Active || got.Storage[0].Total != 107374182400 || got.Storage[0].Used != 42949672960 ||
		got.Storage[1].Name != "nas" || got.Storage[1].Active || got.Storage[1].Type != "nfs" {
		t.Errorf("storage = %+v", got.Storage)
	}
}

func TestGuestAddressesAreCachedAndUnknownWhenTheAgentCallFails(t *testing.T) {
	f := newFakeAPI(t)
	now := time.Unix(1_790_000_000, 0)
	c := &Collector{Root: pveRoot(t), Client: f.client(t), Now: func() time.Time { return now }}
	lxcPath := "/api2/json/nodes/pve-01/lxc/101/interfaces"
	c.Collect(context.Background())
	now = now.Add(30 * time.Second)
	got := c.Collect(context.Background())
	if n := f.calls[lxcPath].Load(); n != 1 {
		t.Errorf("addresses are looked up every 5 minutes, not every cycle: %d calls", n)
	}
	if !reflect.DeepEqual(got.Guests[0].IPs, []string{"192.168.10.21", "2001:db8::21"}) {
		t.Errorf("cached addresses must still be reported: %q", got.Guests[0].IPs)
	}
	now = now.Add(5 * time.Minute)
	c.Collect(context.Background())
	if n := f.calls[lxcPath].Load(); n != 2 {
		t.Errorf("after 5 minutes the addresses are looked up again: %d calls", n)
	}

	// A VM without a working guest agent has no known address.
	delete(f.calls, "/api2/json/nodes/pve-01/qemu/110/agent/network-get-interfaces")
	g := newFakeAPI(t)
	g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/agent/") {
			http.Error(w, `{"data":null}`, http.StatusInternalServerError)
			return
		}
		f.srv.Config.Handler.ServeHTTP(w, r)
	})
	got = (&Collector{Root: pveRoot(t), Client: g.client(t), Now: func() time.Time { return now }}).Collect(context.Background())
	if got.Error != "" || got.Guests[1].ID != 110 || got.Guests[1].IPs != nil {
		t.Errorf("a failing guest agent call must leave the address unknown and nothing else: %+v", got.Guests[1])
	}
}
