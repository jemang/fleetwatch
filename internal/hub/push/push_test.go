package push

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSealRFC8291 is the example of RFC 8291 appendix A.
func TestSealRFC8291(t *testing.T) {
	as, err := ecdh.P256().NewPrivateKey(b64(t, "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := seal([]byte("When I grow up, I want to be a watermelon"),
		b64(t, "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"),
		b64(t, "BTBZMqHH6r4Tts7J_aSIgg"), as, b64(t, "DGv6ra1nlYgDCS1FRnbzlw"))
	if err != nil {
		t.Fatal(err)
	}
	want := append(b64(t, "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"),
		b64(t, "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ")...)
	if !bytes.Equal(got, want) {
		t.Errorf("seal:\n got %x\nwant %x", got, want)
	}
}

// receiver is a browser: its keys, and opening what the Hub sealed for it.
type receiver struct {
	priv *ecdh.PrivateKey
	auth []byte
}

func newReceiver(t *testing.T) receiver {
	t.Helper()
	p, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	rand.Read(auth)
	return receiver{p, auth}
}

func (r receiver) keys() (string, string) {
	return base64.RawURLEncoding.EncodeToString(r.priv.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(r.auth)
}

func (r receiver) open(t *testing.T, body []byte) []byte {
	t.Helper()
	salt, rs, idlen := body[:16], binary.BigEndian.Uint32(body[16:20]), int(body[20])
	asPub, ct := body[21:21+idlen], body[21+idlen:]
	if rs != 4096 || idlen != 65 {
		t.Fatalf("header: rs %d idlen %d", rs, idlen)
	}
	pub, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := r.priv.ECDH(pub)
	prkKey, _ := hkdf.Extract(sha256.New, shared, r.auth)
	ikm, _ := hkdf.Expand(sha256.New, prkKey, "WebPush: info\x00"+string(r.priv.PublicKey().Bytes())+string(asPub), 32)
	prk, _ := hkdf.Extract(sha256.New, ikm, salt)
	cek, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	nonce, _ := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain[len(plain)-1] != 2 {
		t.Fatalf("missing the last-record delimiter: %x", plain)
	}
	return plain[:len(plain)-1]
}

func TestSealRoundTrip(t *testing.T) {
	r := newReceiver(t)
	p256dh, auth := r.keys()
	if !ValidSubscription(p256dh, auth) {
		t.Fatal("a real browser key must be valid")
	}
	msg := []byte(`{"title":"Service DOWN · Grafana"}`)
	body, err := Seal(msg, p256dh, auth)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.open(t, body); !bytes.Equal(got, msg) {
		t.Errorf("opened %q", got)
	}
	if _, err := Seal(msg, "AAAA", auth); err == nil {
		t.Error("a broken browser key must fail")
	}
	for _, bad := range [][2]string{{"", auth}, {p256dh, ""}, {p256dh, "AAAA"}, {"BAAA", auth}} {
		if ValidSubscription(bad[0], bad[1]) {
			t.Errorf("ValidSubscription(%q, %q) = true", bad[0], bad[1])
		}
	}
}

func TestKeysAndAuthorization(t *testing.T) {
	s, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if pub := b64(t, k.Public()); len(pub) != 65 || pub[0] != 4 {
		t.Fatalf("public key: %x", pub)
	}
	if _, err := ParseKey("not-a-key"); err == nil {
		t.Error("a broken key must fail to parse")
	}
	now := time.Unix(1_800_000_000, 0)
	h, err := k.Authorization("https://fcm.googleapis.com/fcm/send/abc", "https://monitor.example.com", now)
	if err != nil {
		t.Fatal(err)
	}
	jwt, pub, ok := strings.Cut(strings.TrimPrefix(h, "vapid t="), ", k=")
	if !strings.HasPrefix(h, "vapid t=") || !ok || pub != k.Public() {
		t.Fatalf("header: %q", h)
	}
	parts := strings.Split(jwt, ".")
	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}
	json.Unmarshal(b64(t, parts[1]), &claims)
	if string(b64(t, parts[0])) != `{"typ":"JWT","alg":"ES256"}` || claims.Aud != "https://fcm.googleapis.com" || claims.Exp != now.Add(12*time.Hour).Unix() || claims.Sub != "https://monitor.example.com" {
		t.Errorf("jwt: %s %+v", b64(t, parts[0]), claims)
	}
	sig := b64(t, parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&k.priv.PublicKey, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("the JWT signature does not verify with the public key")
	}
	if Subject("https://monitor.example.com/") != "https://monitor.example.com" || Subject("http://10.0.0.2:8080") != "mailto:fleetwatch@localhost" {
		t.Error("Subject")
	}
}

func TestSend(t *testing.T) {
	r := newReceiver(t)
	p256dh, auth := r.keys()
	s, _ := NewKey()
	k, _ := ParseKey(s)
	var got *http.Request
	var body []byte
	code := http.StatusCreated
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got = req
		body, _ = io.ReadAll(req.Body)
		w.WriteHeader(code)
	}))
	defer srv.Close()
	sub := Subscription{Endpoint: srv.URL + "/push/secret-token", P256dh: p256dh, Auth: auth}
	status, err := Send(context.Background(), srv.Client(), k, "mailto:x@y", sub, []byte("hi"), "high", time.Now())
	if err != nil || status != 201 {
		t.Fatalf("send: %d %v", status, err)
	}
	if got.Method != "POST" || got.URL.Path != "/push/secret-token" || got.Header.Get("Content-Encoding") != "aes128gcm" || got.Header.Get("TTL") != "86400" ||
		got.Header.Get("Urgency") != "high" || !strings.HasPrefix(got.Header.Get("Authorization"), "vapid t=") {
		t.Errorf("request: %s %s %v", got.Method, got.URL, got.Header)
	}
	if string(r.open(t, body)) != "hi" {
		t.Error("the receiver cannot open the body")
	}
	code = http.StatusGone
	if status, err := Send(context.Background(), srv.Client(), k, "mailto:x@y", sub, []byte("hi"), "normal", time.Now()); status != 410 || err == nil {
		t.Errorf("410: %d %v", status, err)
	}
	srv.Close()
	status, err = Send(context.Background(), srv.Client(), k, "mailto:x@y", sub, []byte("hi"), "normal", time.Now())
	if status != 0 || err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("no answer: %d %v (the endpoint must not appear)", status, err)
	}
}
