package cmd

import (
	"fmt"
	"os"

	"github.com/sagan/cftool/version"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     "cftool",
	Version: version.Version,
	Short:   "cftool is a CLI tool to manage Cloudflare DNS records.",
	Long:    `cftool is a CLI tool to manage Cloudflare DNS records.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
