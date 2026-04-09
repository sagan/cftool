package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const Version = "v0.1.1"

var rootCmd = &cobra.Command{
	Use:     "cftool",
	Version: Version,
	Short:   "cftool is a CLI tool to manage Cloudflare DNS records.",
	Long:    `cftool is a CLI tool to manage Cloudflare DNS records.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
