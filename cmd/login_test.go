package cmd

import (
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
