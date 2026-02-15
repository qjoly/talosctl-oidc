package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "talosctl-oidc",
	Short: "OIDC-gated credential plugin for talosctl",
	Long: `talosctl-oidc authenticates users via an OIDC provider and writes
pre-provisioned Talos admin client certificates into the talosconfig
upon successful authentication.

It supports any standard OIDC-compliant provider via discovery URL
and uses the Authorization Code flow with PKCE.`,
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
