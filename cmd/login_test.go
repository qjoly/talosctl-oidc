package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenBrowserSkipsExec(t *testing.T) {
	// A command that cannot exist: openBrowser must not even try to run it.
	loginFlags.skipOpenBrowser = true
	loginFlags.browserCommand = "talosctl-oidc-no-such-browser"
	t.Cleanup(func() { loginFlags.skipOpenBrowser, loginFlags.browserCommand = false, "" })

	if err := openBrowser("https://idp.example.com/auth"); err != nil {
		t.Fatalf("openBrowser with --skip-open-browser: %v", err)
	}
}

func TestBrowserCommandOverridesPlatformDefault(t *testing.T) {
	loginFlags.browserCommand = "google-chrome"
	t.Cleanup(func() { loginFlags.browserCommand = "" })

	cmd, err := browserCommand("https://idp.example.com/auth")
	if err != nil {
		t.Fatalf("browserCommand: %v", err)
	}
	if got := filepath.Base(cmd.Path); got != "google-chrome" {
		t.Errorf("command = %q, want google-chrome", got)
	}
	if len(cmd.Args) != 2 || cmd.Args[1] != "https://idp.example.com/auth" {
		t.Errorf("args = %v, want the URL as a single argument", cmd.Args)
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}

	cases := map[string]string{
		"~/.talos/oidc.crt": filepath.Join(home, ".talos/oidc.crt"),
		"~":                 home,
		"/etc/tls/oidc.crt": "/etc/tls/oidc.crt",
		"oidc.crt":          "oidc.crt",
		"":                  "",
		// Another user's home is a shell feature we do not reimplement.
		"~other/oidc.crt": "~other/oidc.crt",
	}

	for in, want := range cases {
		if got := expandHome(in); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}
