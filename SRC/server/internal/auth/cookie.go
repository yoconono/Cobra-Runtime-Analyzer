package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Signer issues and verifies stateless session tokens. A token carries the
// username and an expiry, authenticated by HMAC-SHA256 over the payload with a
// server-held key — so no server-side session state is needed, and tokens remain
// valid across restarts and across multiple server instances that share the key.
//
// Token format: base64url(payload_json) "." base64url(hmac_sha256(payload_b64)).
type Signer struct {
	key []byte
}

func NewSigner(key []byte) *Signer { return &Signer{key: key} }

type claims struct {
	U   string `json:"u"`
	Exp int64  `json:"exp"`
}

func (s *Signer) mac(msg string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// Issue returns a signed token for user, valid for ttl, and its expiry time.
func (s *Signer) Issue(user string, ttl time.Duration) (string, time.Time) {
	exp := time.Now().Add(ttl)
	p, _ := json.Marshal(claims{U: user, Exp: exp.Unix()})
	pb := base64.RawURLEncoding.EncodeToString(p)
	sig := base64.RawURLEncoding.EncodeToString(s.mac(pb))
	return pb + "." + sig, exp
}

// Verify checks a token's signature and expiry, returning the username on success.
func (s *Signer) Verify(token string) (string, bool) {
	i := strings.IndexByte(token, '.')
	if i <= 0 || i == len(token)-1 {
		return "", false
	}
	pb, sb := token[:i], token[i+1:]
	gotSig, err := base64.RawURLEncoding.DecodeString(sb)
	if err != nil {
		return "", false
	}
	if !hmac.Equal(gotSig, s.mac(pb)) { // constant-time
		return "", false
	}
	p, err := base64.RawURLEncoding.DecodeString(pb)
	if err != nil {
		return "", false
	}
	var c claims
	if json.Unmarshal(p, &c) != nil {
		return "", false
	}
	if c.U == "" || time.Now().Unix() > c.Exp {
		return "", false
	}
	return c.U, true
}
