// Package push sends Web Push messages: one message, encrypted for one
// browser (RFC 8291, aes128gcm) and signed with the Hub's key (VAPID,
// RFC 8292).
package push

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var enc = base64.RawURLEncoding

// decode reads base64url with or without padding, as browsers send it.
func decode(s string) ([]byte, error) { return enc.DecodeString(strings.TrimRight(s, "=")) }

// Keys is the Hub's VAPID key pair.
type Keys struct{ priv *ecdsa.PrivateKey }

// NewKey makes a VAPID private key: base64url of its PKCS#8 form.
func NewKey() (string, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return enc.EncodeToString(der), nil
}

func ParseKey(s string) (*Keys, error) {
	der, err := decode(s)
	if err != nil {
		return nil, errors.New("push: the stored key is not base64url")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("push: the stored key cannot be read")
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("push: the stored key is not a P-256 key")
	}
	return &Keys{ec}, nil
}

// Public is the key browsers subscribe with: the uncompressed point.
func (k *Keys) Public() string {
	e, err := k.priv.ECDH()
	if err != nil {
		return ""
	}
	return enc.EncodeToString(e.PublicKey().Bytes())
}

// Authorization is the VAPID header for one push service. The JWT lasts 12
// hours; push services refuse more than 24.
func (k *Keys) Authorization(endpoint, subject string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", errors.New("push: bad endpoint")
	}
	claims, err := json.Marshal(map[string]any{"aud": u.Scheme + "://" + u.Host, "exp": now.Add(12 * time.Hour).Unix(), "sub": subject})
	if err != nil {
		return "", err
	}
	unsigned := enc.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + unsigned + "." + enc.EncodeToString(sig) + ", k=" + k.Public(), nil
}

// Subject is the contact push services see: the Hub's address when it is
// https, else a placeholder address.
func Subject(publicURL string) string {
	if strings.HasPrefix(publicURL, "https://") {
		return strings.TrimRight(publicURL, "/")
	}
	return "mailto:fleetwatch@localhost"
}

// ValidSubscription reports whether a browser's keys have the right shape.
func ValidSubscription(p256dh, auth string) bool {
	pub, err := decode(p256dh)
	if err != nil {
		return false
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
		return false
	}
	a, err := decode(auth)
	return err == nil && len(a) == 16
}

// Seal encrypts plaintext for one browser as a single aes128gcm record.
func Seal(plaintext []byte, p256dh, auth string) ([]byte, error) {
	ua, err := decode(p256dh)
	if err != nil {
		return nil, errors.New("push: browser key is not base64url")
	}
	secret, err := decode(auth)
	if err != nil {
		return nil, errors.New("push: auth secret is not base64url")
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return seal(plaintext, ua, secret, as, salt)
}

// recordSize is the one record's size; the plaintext, its delimiter and the
// 16-byte tag must fit.
const recordSize = 4096

func seal(plaintext, uaPub, authSecret []byte, as *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(authSecret) != 16 {
		return nil, errors.New("push: auth secret must be 16 bytes")
	}
	if len(plaintext)+17 > recordSize {
		return nil, errors.New("push: message too long")
	}
	ua, err := ecdh.P256().NewPublicKey(uaPub)
	if err != nil {
		return nil, errors.New("push: browser key is not a P-256 point")
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPub := as.PublicKey().Bytes()
	prkKey, err := hkdf.Extract(sha256.New, shared, authSecret)
	if err != nil {
		return nil, err
	}
	ikm, err := hkdf.Expand(sha256.New, prkKey, "WebPush: info\x00"+string(uaPub)+string(asPub), 32)
	if err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, salt...)
	out = binary.BigEndian.AppendUint32(out, recordSize)
	out = append(out, byte(len(asPub)))
	out = append(out, asPub...)
	// 0x02 marks the last (here the only) record.
	padded := append(append([]byte{}, plaintext...), 2)
	return gcm.Seal(out, nonce, padded, nil), nil
}

// Subscription is one browser: where to post and its keys.
type Subscription struct{ Endpoint, P256dh, Auth string }

// Send posts payload to one browser. It returns the push service's status
// (0 without an answer). Errors never contain the endpoint: it works like a
// password.
func Send(ctx context.Context, c *http.Client, k *Keys, subject string, sub Subscription, payload []byte, urgency string, now time.Time) (int, error) {
	body, err := Seal(payload, sub.P256dh, sub.Auth)
	if err != nil {
		return 0, err
	}
	auth, err := k.Authorization(sub.Endpoint, subject, now)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("push: bad endpoint")
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("TTL", strconv.Itoa(86400))
	req.Header.Set("Urgency", urgency)
	req.Header.Set("Authorization", auth)
	resp, err := c.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("push service: %w", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, fmt.Errorf("push service answered HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
