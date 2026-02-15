package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "talosctl-oidc",
	Short: "OIDC-gated credential plugin for talosctl",
	Long: `talosctl-oidc authenticates users via an OIDC provider and issues
ephemeral short-lived Talos client certificates.

The 'serve' command runs a cert exchange server that holds the Talos CA
and signs ephemeral certificates for authenticated users.

The 'login' command performs the OIDC Authorization Code + PKCE flow,
exchanges the ID token with the cert exchange server, and writes the
ephemeral certificate to the talosconfig file.

It supports any standard OIDC-compliant provider via discovery URL.`,
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}
	return nil
}
