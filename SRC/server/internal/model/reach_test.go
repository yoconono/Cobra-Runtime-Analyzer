package model

import "testing"

func TestReachability(t *testing.T) {
	cases := []struct {
		name     string
		running  bool
		affected []string
		used     []string
		want     string
	}{
		{"not running", false, []string{"SSL_read"}, []string{"SSL_read"}, ReachInstalled},
		{"running no symbol data", true, nil, []string{"SSL_read"}, ReachLoaded},
		{"affected symbol used", true, []string{"SSL_read"}, []string{"malloc", "SSL_read"}, ReachSymbolUsed},
		{"affected symbol not used", true, []string{"X509_verify"}, []string{"malloc", "SSL_read"}, ReachSymbolUnused},
		{"one of several affected used", true, []string{"a", "b", "SSL_read"}, []string{"SSL_read"}, ReachSymbolUsed},
		{"running affected present no used syms", true, []string{"SSL_read"}, nil, ReachSymbolUnused},
	}
	for _, c := range cases {
		if got := Reachability(c.running, c.affected, c.used); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if ReachRank(ReachSymbolUsed) <= ReachRank(ReachLoaded) {
		t.Error("symbol_used should outrank loaded")
	}
	if ReachRank(ReachSymbolUnused) >= ReachRank(ReachLoaded) {
		t.Error("loaded_unused should rank below loaded")
	}
}
