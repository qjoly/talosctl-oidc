package main

import (
	"os"

	"github.com/qjoly/talosctl-oidc/cmd"
)

// version, commit and date are set at build time via -ldflags.
var (
	version string
	commit  string
	date    string
)

func main() {
	cmd.SetBuildInfo(version, commit, date)
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
