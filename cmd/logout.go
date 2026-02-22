package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/qjoly/talosctl-oidc/pkg/keychain"
	"github.com/qjoly/talosctl-oidc/pkg/talosconfig"
)

var logoutFlags struct {
	contextName string
	talosconfig string
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove OIDC credentials and clear cached tokens",
	Long: `Remove the OIDC context from the talosconfig file and delete
the cached OIDC tokens from the system keychain (or file cache).`,
	RunE: runLogout,
}

func init() {
	logoutCmd.Flags().StringVar(&logoutFlags.contextName, "context-name", "oidc", "Name of the talosconfig context to remove")
	logoutCmd.Flags().StringVar(&logoutFlags.talosconfig, "talosconfig", "", "Path to talosconfig file (default: ~/.talos/config)")

	rootCmd.AddCommand(logoutCmd)
}

func runLogout(cmd *cobra.Command, args []string) error {
	talosconfigPath := logoutFlags.talosconfig
	if talosconfigPath == "" {
		var err error
		talosconfigPath, err = talosconfig.DefaultPath()
		if err != nil {
			return err
		}
	}

	// Delete token from keychain and file cache.
	if err := keychain.Delete(logoutFlags.contextName); err != nil {
		fmt.Printf("Warning: could not clear cached token: %v\n", err)
	} else {
		fmt.Println("Cached token cleared.")
	}

	// Remove context from talosconfig.
	cfg, err := talosconfig.Load(talosconfigPath)
	if err != nil {
		return fmt.Errorf("loading talosconfig: %w", err)
	}

	if !talosconfig.HasContext(cfg, logoutFlags.contextName) {
		fmt.Printf("Context %q not found in talosconfig, nothing to remove.\n", logoutFlags.contextName)
		return nil
	}

	talosconfig.RemoveContext(cfg, logoutFlags.contextName)

	if err := talosconfig.Save(talosconfigPath, cfg); err != nil {
		return fmt.Errorf("saving talosconfig: %w", err)
	}

	fmt.Printf("Context %q removed from talosconfig.\n", logoutFlags.contextName)

	return nil
}
