package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// SetBuildInfo sets the build metadata (called from main with ldflags values).
func SetBuildInfo(v, c, d string) {
	if v != "" {
		version = v
	}
	if c != "" {
		commit = c
	}
	if d != "" {
		date = d
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of talosctl-oidc",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("talosctl-oidc %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
