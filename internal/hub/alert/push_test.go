package alert

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fleetwatch/internal/hub/push"
	"fleetwatch/internal/hub/store"
)

// phone is a browser with notifications on, behind a fake push service.
type phone struct {
	t    *testing.T
	priv *ecdh.PrivateKey
	auth []byte
	srv  *httptest.Server
	mu   sync.Mutex
	code int
	got  []map[string]string // opened payloads
	hdr  []http.Header
}

func newPhone(t *testing.T) *phone {
	p := &phone{t: t, code: http.StatusCreated}
	p.priv, _ = ecdh.P256().GenerateKey(rand.Reader)
	p.auth = make([]byte, 16)
	rand.Read(p.auth)
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		if p.code == http.StatusCreated {
			var msg map[string]string
			json.Unmarshal(p.open(b), &msg)
			p.got = append(p.got, msg)
			p.hdr = append(p.hdr, r.Header)
		}
		w.WriteHeader(p.code)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *phone) open(body []byte) []byte {
	salt, idlen := body[:16], int(body[20])
	asPub, ct := body[21:21+idlen], body[21+idlen:]
	pub, _ := ecdh.P256().NewPublicKey(asPub)
	shared, _ := p.priv.ECDH(pub)
	prkKey, _ := hkdf.Extract(sha256.New, shared, p.auth)
	ikm, _ := hkdf.Expand(sha256.New, prkKey, "WebPush: info\x00"+string(p.priv.PublicKey().Bytes())+string(asPub), 32)
	prk, _ := hkdf.Extract(sha256.New, ikm, salt)
	cek, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		p.t.Fatal(err)
	}
	return plain[:len(plain)-1]
}

func (p *phone) subscribe(t *testing.T, st *store.Store, label string) {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	if err := st.SavePushSubscription(context.Background(), store.PushSubscription{Endpoint: p.srv.URL + "/send/secret-" + label,
		P256dh: enc(p.priv.PublicKey().Bytes()), Auth: enc(p.auth), Label: label}, t0); err != nil {
		t.Fatal(err)
	}
}

func pushSettings(t *testing.T, st *store.Store) map[string]string {
	t.Helper()
	if _, err := st.PushKey(context.Background(), push.NewKey); err != nil {
		t.Fatal(err)
	}
	s, _ := st.Settings(context.Background())
	return s
}

func TestPushPayload(t *testing.T) {
	var p map[string]string
	json.Unmarshal(pushPayload(Message{Event: "firing", AlertID: 7, Service: "Grafana", Kind: KindSvcDown, Detail: "timeout"}), &p)
	if p["title"] != "Service DOWN · Grafana" || p["body"] != "timeout" || p["url"] != "/alerts/7" || p["tag"] != "alert-7" {
		t.Errorf("firing: %v", p)
	}
	json.Unmarshal(pushPayload(Message{Event: "resolved", AlertID: 7, Service: "Grafana", Kind: KindSvcDown, Since: t0, At: t0.Add(4 * time.Minute)}), &p)
	if p["title"] != "Service recovered · Grafana" || p["body"] != "After 4m" || p["tag"] != "alert-7" {
		t.Errorf("resolved: %v", p)
	}
	json.Unmarshal(pushPayload(Message{Event: "firing", AlertID: 3, Host: "pve-2", Kind: KindOffline, HostServices: []string{"A", "B"}}), &p)
	if p["title"] != "Agent disconnected · pve-2" || p["body"] != "Services on this host: A, B" {
		t.Errorf("offline: %v", p)
	}
	json.Unmarshal(pushPayload(Message{Event: "test", Hub: "h"}), &p)
	if p["title"] != "FleetWatch test" || p["body"] != "Notifications work on this device." || p["url"] != "/settings" || p["tag"] != "test" {
		t.Errorf("test: %v", p)
	}
	many := make([]string, 400)
	for i := range many {
		many[i] = strings.Repeat("ü", 20)
	}
	if b := pushPayload(Message{Event: "firing", AlertID: 1, Host: "h", Kind: KindOffline, HostServices: many}); len(b)+17 > 4096 || !strings.Contains(string(b), "…") {
		t.Errorf("a long payload must be cut to fit one record: %d bytes", len(b))
	}
}

func TestPushTarget(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	if pt, err := PushTarget(ctx, w.st, map[string]string{}, "mailto:x@y", t0, nil); pt != nil || err != nil {
		t.Fatalf("no key, no device: %v %v", pt, err)
	}
	settings := pushSettings(t, w.st)
	if pt, _ := PushTarget(ctx, w.st, settings, "mailto:x@y", t0, nil); pt != nil {
		t.Fatal("no device: no target")
	}
	good, gone := newPhone(t), newPhone(t)
	gone.code = http.StatusGone
	good.subscribe(t, w.st, "Chrome on Android")
	gone.subscribe(t, w.st, "Old phone")
	var logged []string
	logf := func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	pt, err := PushTarget(ctx, w.st, settings, "mailto:x@y", t0, logf)
	if err != nil || pt == nil || pt.Name != "Push" {
		t.Fatalf("target: %v %v", pt, err)
	}
	if err := pt.Send(ctx, Message{Event: "firing", AlertID: 5, Service: "Grafana", Kind: KindSvcDown, Detail: "timeout"}); err != nil {
		t.Errorf("one gone device must not fail the message: %v", err)
	}
	if len(good.got) != 1 || good.got[0]["title"] != "Service DOWN · Grafana" || good.hdr[0].Get("Urgency") != "high" {
		t.Errorf("good phone got %v", good.got)
	}
	subs, _ := w.st.PushSubscriptions(ctx)
	if len(subs) != 1 || subs[0].Label != "Chrome on Android" || !subs[0].LastOKAt.Equal(t0) {
		t.Errorf("the gone device must be removed and the good one marked: %+v", subs)
	}
	for _, l := range logged {
		if strings.Contains(l, "secret") {
			t.Errorf("a log line shows the endpoint: %q", l)
		}
	}
	if !strings.Contains(strings.Join(logged, "\n"), "Old phone") {
		t.Errorf("the removal is logged by label: %q", logged)
	}
	good.code = http.StatusInternalServerError
	err = pt.Send(ctx, Message{Event: "resolved", AlertID: 5, Service: "Grafana", Kind: KindSvcDown})
	if err == nil || strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "Chrome on Android") {
		t.Errorf("all devices failing is an error that names the device, not the endpoint: %v", err)
	}
}

// TestEngineSendsPush runs the real deliver path: an alert that fires
// reaches the phone with its alert page and tag.
func TestEngineSendsPush(t *testing.T) {
	w := newWorld(t)
	w.eng.Send = nil
	w.eng.PushSubject = "mailto:x@y"
	pushSettings(t, w.st)
	p := newPhone(t)
	p.subscribe(t, w.st, "Chrome on Android")
	id := w.service("Grafana", "https://grafana.lan")
	w.check(id, "https://grafana.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(15 * time.Second)
	alerts, _ := w.st.Alerts(context.Background(), 100)
	if len(p.got) != 1 || len(alerts) != 1 || p.got[0]["url"] != fmt.Sprintf("/alerts/%d", alerts[0].ID) || p.got[0]["tag"] != fmt.Sprintf("alert-%d", alerts[0].ID) {
		t.Fatalf("pushed %v for %+v", p.got, alerts)
	}
}

// TestRetryResendsOnlyToFailedTargets: while the webhook fails, the message
// stays owed, but the phone that already got it must not buzz on every tick.
func TestRetryResendsOnlyToFailedTargets(t *testing.T) {
	w := newWorld(t)
	w.eng.Send = nil
	w.eng.PushSubject = "mailto:x@y"
	pushSettings(t, w.st)
	hookCode := http.StatusBadGateway
	hooks := 0
	hook := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { hooks++; rw.WriteHeader(hookCode) }))
	defer hook.Close()
	w.st.SetSettings(context.Background(), map[string]string{"webhook_url": hook.URL})
	p := newPhone(t)
	p.subscribe(t, w.st, "Chrome on Android")
	id := w.service("Grafana", "https://grafana.lan")
	w.check(id, "https://grafana.lan", store.CheckState{State: "down", Since: w.now.Unix(), Error: "timeout"})
	w.tick(15 * time.Second)
	w.tick(15 * time.Second)
	w.tick(15 * time.Second)
	if len(p.got) != 1 || hooks != 3 {
		t.Fatalf("phone got %d (want 1), webhook tried %d times (want 3)", len(p.got), hooks)
	}
	hookCode = http.StatusOK
	w.tick(15 * time.Second)
	w.tick(15 * time.Second)
	if len(p.got) != 1 || hooks != 4 {
		t.Errorf("after the webhook recovers: phone %d, webhook %d", len(p.got), hooks)
	}
}

func TestPushPayloadFitsWhenEscaped(t *testing.T) {
	many := make([]string, 300)
	for i := range many {
		many[i] = "<&> "
	}
	b := pushPayload(Message{Event: "firing", AlertID: 1, Host: "h", Kind: KindOffline, Detail: strings.Repeat("&", 3000), HostServices: many})
	if len(b)+17 > 4096 {
		t.Fatalf("payload of %d bytes does not fit one record", len(b))
	}
	var p map[string]string
	if err := json.Unmarshal(b, &p); err != nil || !strings.HasPrefix(p["body"], "&&&") {
		t.Errorf("payload must stay valid JSON with the text as is: %v %.20q", err, p["body"])
	}
}

// Devices are sent to at the same time: slow push services must not add up
// and stall the alert tick.
func TestPushTargetSendsInParallel(t *testing.T) {
	w := newWorld(t)
	settings := pushSettings(t, w.st)
	for i := 0; i < 3; i++ {
		p := newPhone(t)
		inner := p.srv.Config.Handler
		p.srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			time.Sleep(700 * time.Millisecond)
			inner.ServeHTTP(rw, r)
		})
		p.subscribe(t, w.st, fmt.Sprintf("phone %d", i))
	}
	var mu sync.Mutex
	var logged []string
	pt, _ := PushTarget(context.Background(), w.st, settings, "mailto:x@y", t0, func(f string, a ...any) {
		mu.Lock()
		logged = append(logged, fmt.Sprintf(f, a...))
		mu.Unlock()
	})
	start := time.Now()
	if err := pt.Send(context.Background(), Message{Event: "test"}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("3 devices of 0.7 s each took %v; they must be sent to in parallel", d)
	}
}
