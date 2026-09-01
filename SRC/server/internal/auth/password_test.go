package auth

import "testing"

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("correct horse battery staple", h) {
		t.Error("correct password should verify")
	}
	if Verify("wrong password", h) {
		t.Error("wrong password must not verify")
	}
	// two hashes of the same password differ (random salt)
	h2, _ := Hash("correct horse battery staple")
	if h == h2 {
		t.Error("salted hashes should differ")
	}
	if Verify("x", "garbage") || Verify("x", "pbkdf2_sha256$bad") {
		t.Error("malformed encodings must not verify")
	}
	if _, err := Hash(""); err == nil {
		t.Error("empty password should error")
	}
}

func TestPBKDF2KnownVector(t *testing.T) {
	// RFC 6070-style check for HMAC-SHA256: password "password", salt "salt",
	// 1 iteration, dkLen 32. Expected first bytes 0x120fb6cf... (well-known).
	dk := pbkdf2([]byte("password"), []byte("salt"), 1, 32)
	want := []byte{0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c}
	for i := range want {
		if dk[i] != want[i] {
			t.Fatalf("byte %d = %#x want %#x", i, dk[i], want[i])
		}
	}
}
