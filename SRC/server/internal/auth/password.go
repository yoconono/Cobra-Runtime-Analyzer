// Package auth provides password hashing and verification using PBKDF2-HMAC-
// SHA256 — implemented on the standard library only (crypto/hmac + crypto/sha256),
// so the server keeps its zero-external-dependency profile. Hashes are stored in
// a self-describing string: pbkdf2_sha256$<iter>$<salt_b64>$<hash_b64>.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	defaultIter = 210000 // OWASP-recommended floor for PBKDF2-HMAC-SHA256
	saltLen     = 16
	keyLen      = 32
	prefix      = "pbkdf2_sha256"
)

// pbkdf2 derives a key per RFC 8018 using HMAC-SHA256 as the PRF.
func pbkdf2(password, salt []byte, iter, dkLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (dkLen + hLen - 1) / hLen
	var dk []byte
	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:dkLen]
}

// Hash returns an encoded PBKDF2 hash for a plaintext password.
func Hash(password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2([]byte(password), salt, defaultIter, keyLen)
	return fmt.Sprintf("%s$%d$%s$%s", prefix, defaultIter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// Verify reports whether password matches an encoded hash, in constant time.
func Verify(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != prefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}
