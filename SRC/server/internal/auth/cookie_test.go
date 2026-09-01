package auth

import (
	"testing"
	"time"
)

func TestSignerRoundTrip(t *testing.T) {
	s := NewSigner([]byte("super-secret-key-of-decent-length"))
	tok, exp := s.Issue("alice", time.Hour)
	if exp.Before(time.Now()) {
		t.Fatal("expiry in the past")
	}
	u, ok := s.Verify(tok)
	if !ok || u != "alice" {
		t.Fatalf("verify failed: u=%q ok=%v", u, ok)
	}
}

func TestSignerRejectsTamperAndExpiry(t *testing.T) {
	s := NewSigner([]byte("k1"))
	tok, _ := s.Issue("bob", time.Hour)

	// Tampered payload/sig
	if _, ok := s.Verify(tok + "x"); ok {
		t.Error("tampered token verified")
	}
	if _, ok := s.Verify("garbage"); ok {
		t.Error("garbage verified")
	}
	// Different key must reject
	other := NewSigner([]byte("k2"))
	if _, ok := other.Verify(tok); ok {
		t.Error("token verified under a different key")
	}
	// Expired token
	expTok, _ := s.Issue("bob", -time.Minute)
	if _, ok := s.Verify(expTok); ok {
		t.Error("expired token verified")
	}
}

func TestSignerStableAcrossInstances(t *testing.T) {
	key := []byte("shared-key-between-instances")
	a := NewSigner(key)
	b := NewSigner(key) // simulates a second server / a restart with same key
	tok, _ := a.Issue("carol", time.Hour)
	if u, ok := b.Verify(tok); !ok || u != "carol" {
		t.Fatal("token issued by A must verify on B with the same key")
	}
}
