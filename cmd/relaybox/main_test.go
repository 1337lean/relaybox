package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	for _, test := range []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		ok       bool
		want     string
	}{
		{name: "release ldflags", injected: "1.2.3", want: "1.2.3"},
		{name: "prefixed ldflags", injected: "v1.2.3", want: "1.2.3"},
		{name: "go install module version", injected: "dev", info: &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, ok: true, want: "1.2.3"},
		{name: "local development", injected: "dev", info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, ok: true, want: "dev"},
		{name: "missing build info", injected: "dev", want: "dev"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveVersion(test.injected, test.info, test.ok); got != test.want {
				t.Fatalf("resolveVersion() = %q, want %q", got, test.want)
			}
		})
	}
}
