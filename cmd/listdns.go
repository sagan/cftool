package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

type ListDnsConfig struct {
	CfToken string
	CfZone  string
	Domain  string
	Format  string
	Align   bool
}

var listDnsConfig ListDnsConfig

var listDnsCmd = &cobra.Command{
	Use:   "listdns",
	Short: "List all DNS records of a Cloudflare zone",
	Long:  `listdns lists all DNS records of a Cloudflare zone to stdout in CSV or JSON format.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runListDns()
	},
}

func init() {
	rootCmd.AddCommand(listDnsCmd)

	listDnsCmd.Flags().StringVar(&listDnsConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	listDnsCmd.Flags().StringVar(&listDnsConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	listDnsCmd.Flags().StringVar(&listDnsConfig.Domain, "domain", os.Getenv("DOMAIN"), "Target domain prefix filter (env: DOMAIN)")
	listDnsCmd.Flags().StringVarP(&listDnsConfig.Format, "format", "f", "csv", "Output format: csv or json")
	listDnsCmd.Flags().BoolVar(&listDnsConfig.Align, "align", false, "Align CSV columns")
}

func runListDns() error {
	cfg := listDnsConfig
	if cfg.CfToken == "" || cfg.CfZone == "" {
		return fmt.Errorf("missing required configuration (cf-token, cf-zone)")
	}

	ctx := context.Background()
	cfAPI, err := cloudflare.NewWithAPIToken(cfg.CfToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare API client: %w", err)
	}

	records, err := fetchAllDNSRecords(ctx, cfAPI, cfg.CfZone)
	if err != nil {
		return fmt.Errorf("error fetching DNS records: %w", err)
	}

	filtered := filterRecordsByDomain(records, cfg.Domain)

	if strings.EqualFold(cfg.Format, "json") {
		jsonData, err := json.MarshalIndent(filtered, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling records to JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		csvOutput := formatCSV(filtered, false, cfg.Align)
		fmt.Print(csvOutput)
	}

	return nil
}
