package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/qjoly/talosctl-oidc/pkg/keychain"
	"github.com/qjoly/talosctl-oidc/pkg/talosconfig"
)

var statusFlags struct {
	contextName string
	talosconfig string
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display current authentication status",
	Long: `Show the current OIDC authentication status including token validity,
configured endpoints, and talosconfig context information.`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().StringVar(&statusFlags.contextName, "context-name", "oidc", "Name of the talosconfig context to check")
	statusCmd.Flags().StringVar(&statusFlags.talosconfig, "talosconfig", "", "Path to talosconfig file (default: ~/.talos/config)")

	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	talosconfigPath := statusFlags.talosconfig
	if talosconfigPath == "" {
		var err error
		talosconfigPath, err = talosconfig.DefaultPath()
		if err != nil {
			return err
		}
	}

	fmt.Printf("Context: %s\n", statusFlags.contextName)
	fmt.Println()

	// Check keychain token.
	fmt.Println("--- OIDC Token ---")
	token, err := keychain.Retrieve(statusFlags.contextName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Keychain:  error (%v)\n", err)
	} else if token == nil {
		fmt.Println("Keychain:  no cached token")
	} else {
		fmt.Printf("Issuer:    %s\n", token.Issuer)
		fmt.Printf("Client ID: %s\n", token.ClientID)
		if token.IsExpired() {
			fmt.Printf("Status:    expired (at %s)\n", token.ExpiresAt.Format(time.RFC3339))
		} else {
			remaining := time.Until(token.ExpiresAt).Round(time.Second)
			fmt.Printf("Status:    valid (expires in %s)\n", remaining)
		}
		if token.HasRefreshToken() {
			fmt.Println("Refresh:   available")
		} else {
			fmt.Println("Refresh:   not available")
		}
	}

	fmt.Println()

	// Check talosconfig.
	fmt.Println("--- Talosconfig ---")
	fmt.Printf("Path:      %s\n", talosconfigPath)

	cfg, err := talosconfig.Load(talosconfigPath)
	if err != nil {
		fmt.Printf("Status:    error loading (%v)\n", err)
		return nil
	}

	if !talosconfig.HasContext(cfg, statusFlags.contextName) {
		fmt.Printf("Status:    context %q not found\n", statusFlags.contextName)
		return nil
	}

	ctx := cfg.Contexts[statusFlags.contextName]
	fmt.Printf("Status:    context %q exists\n", statusFlags.contextName)
	fmt.Printf("Endpoints: %v\n", ctx.Endpoints)
	if cfg.Context == statusFlags.contextName {
		fmt.Println("Active:    yes (current context)")
	} else {
		fmt.Printf("Active:    no (current context is %q)\n", cfg.Context)
	}
	if ctx.Crt != "" {
		fmt.Println("Client cert: present")
	} else {
		fmt.Println("Client cert: missing")
	}

	return nil
}
