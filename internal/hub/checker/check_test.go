package checker

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fleetwatch/internal/hub/store"
)

func service(url string) store.Service {
	return store.Service{ID: 1, Name: "s", URL: url, IntervalS: 60, TimeoutS: 2, Enabled: true}
}

func check(sv store.Service) Result { return Check(context.Background(), sv, time.Now) }

func TestStatusRules(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ok", http.StatusFound) })
	mux.HandleFunc("/broken", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", http.StatusFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	if r := check(service(srv.URL + "/ok")); !r.OK || r.Code != 200 || r.Reason != "" {
		t.Errorf("200: %+v", r)
	}
	if r := check(service(srv.URL + "/moved")); !r.OK || r.Code != 200 {
		t.Errorf("302 then 200: %+v", r)
	}
	if r := check(service(srv.URL + "/broken")); r.OK || r.Code != 503 || r.Reason != "HTTP 503" {
		t.Errorf("503: %+v", r)
	}
	if r := check(service(srv.URL + "/login")); r.OK || r.Reason != "HTTP 401" {
		t.Errorf("401 without an expected status: %+v", r)
	}
	sv := service(srv.URL + "/login")
	sv.ExpectedStatus = 401
	if r := check(sv); !r.OK {
		t.Errorf("401 expected: %+v", r)
	}
	sv = service(srv.URL + "/ok")
	sv.ExpectedStatus = 204
	if r := check(sv); r.OK || r.Reason != "HTTP 200" {
		t.Errorf("200 when 204 is expected: %+v", r)
	}
	if r := check(service(srv.URL + "/loop")); r.OK || r.Reason != "too many redirects" {
		t.Errorf("loop: %+v", r)
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	sv := service(srv.URL)
	sv.TimeoutS = 1
	start := time.Now()
	if r := check(sv); r.OK || r.Reason != "timeout" {
		t.Errorf("hanging server: %+v", r)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
}

// A server that sends headers fast but keeps the body open does not hold the
// check past its timeout.
func TestSlowBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	sv := service(srv.URL)
	sv.TimeoutS = 1
	start := time.Now()
	check(sv)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestConnectionAndDNSFailures(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if r := check(service("http://" + addr)); r.OK || r.Reason != "connection refused" {
		t.Errorf("closed port: %+v", r)
	}
	if r := check(service("http://fleetwatch-test.invalid")); r.OK || r.Reason != "DNS lookup failed" {
		t.Errorf("unknown name: %+v", r)
	}
}

func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestTLS(t *testing.T) {
	expires := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	srv := tlsServer(t, selfSigned(t, expires))
	if r := check(service(srv.URL)); r.OK || r.Reason != "TLS: unknown certificate authority" {
		t.Errorf("self-signed without the switch: %+v", r)
	}
	sv := service(srv.URL)
	sv.AcceptSelfSigned = true
	if r := check(sv); !r.OK || !r.CertExpires.Equal(expires) {
		t.Errorf("self-signed with the switch: %+v, want cert expiry %v", r, expires)
	}
	old := tlsServer(t, selfSigned(t, time.Now().Add(-time.Hour)))
	if r := check(service(old.URL)); r.OK || r.Reason != "TLS: certificate expired" {
		t.Errorf("expired: %+v", r)
	}
}

func TestReasonNeverHasTheURL(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	r := check(service("http://" + addr + "/x?token=s3cret"))
	if strings.Contains(r.Reason, "s3cret") || strings.Contains(r.Reason, addr) {
		t.Errorf("reason = %q", r.Reason)
	}
}

func TestResponseTimeAndAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(50 * time.Millisecond) }))
	defer srv.Close()
	at := time.Unix(1_790_000_000, 0)
	r := Check(context.Background(), service(srv.URL), func() time.Time { return at })
	if r.Ms < 50 || r.Ms > 2000 || !r.At.Equal(at) {
		t.Errorf("ms %d at %v", r.Ms, r.At)
	}
}
