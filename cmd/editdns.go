package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

type EditDnsConfig struct {
	CfToken string
	CfZone  string
	Domain  string
	Editor  string
	DryRun  bool
	Align   bool
}

var editDnsConfig EditDnsConfig

var editDnsCmd = &cobra.Command{
	Use:   "editdns",
	Short: "Interactively edit DNS records of a Cloudflare zone",
	Long: `editdns writes Cloudflare DNS records to a temporary file and opens it in a text editor.
When the editor exits, changes are applied to Cloudflare DNS.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEditDns()
	},
}

func init() {
	rootCmd.AddCommand(editDnsCmd)

	editDnsCmd.Flags().StringVar(&editDnsConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	editDnsCmd.Flags().StringVar(&editDnsConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	editDnsCmd.Flags().StringVar(&editDnsConfig.Domain, "domain", os.Getenv("DOMAIN"), "Target domain prefix filter (env: DOMAIN)")
	editDnsCmd.Flags().StringVar(&editDnsConfig.Editor, "editor", "", "Text editor to use for editing (defaults to VISUAL, EDITOR, or system default)")
	editDnsCmd.Flags().BoolVar(&editDnsConfig.DryRun, "dry-run", false, "Enable dry run mode (log changes without applying)")
	editDnsCmd.Flags().BoolVar(&editDnsConfig.Align, "align", false, "Align CSV columns")
}

func runEditDns() error {
	cfg := editDnsConfig
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

	filteredRecords := filterRecordsByDomain(records, cfg.Domain)

	tmpFile, err := os.CreateTemp("", "cftool-dns-*.csv")
	if err != nil {
		return fmt.Errorf("error creating temp file: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	defer os.Remove(tmpFilePath)

	csvContent := formatCSV(filteredRecords, true, cfg.Align)
	if _, err := tmpFile.WriteString(csvContent); err != nil {
		tmpFile.Close()
		return fmt.Errorf("error writing to temp file: %w", err)
	}
	tmpFile.Close()

	editorExec, editorArgs, err := getEditor(cfg.Editor)
	if err != nil {
		return fmt.Errorf("error detecting text editor: %w", err)
	}

	log.Printf("Opening DNS records file in editor (%s)...", editorExec)
	execArgs := append(editorArgs, tmpFilePath)
	cmd := exec.Command(editorExec, execArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %q exited with error: %w", editorExec, err)
	}

	updatedBytes, err := os.ReadFile(tmpFilePath)
	if err != nil {
		return fmt.Errorf("error reading edited temp file: %w", err)
	}

	editedRows, err := parseCSVRecords(string(updatedBytes))
	if err != nil {
		return fmt.Errorf("error parsing edited CSV file: %w", err)
	}

	origMap := make(map[string]cloudflare.DNSRecord)
	for _, r := range filteredRecords {
		origMap[r.ID] = r
	}

	keptIDs := make(map[string]bool)

	type UpdateItem struct {
		Params cloudflare.UpdateDNSRecordParams
		Target string
	}

	var toUpdate []UpdateItem
	var toCreate []cloudflare.CreateDNSRecordParams

	for _, er := range editedRows {
		proxied := parseProxyStatus(er.ProxyStatus)
		ttl := parseTTL(er.TTL)

		if er.ID != "" {
			if origRec, exists := origMap[er.ID]; exists {
				keptIDs[er.ID] = true
				origProxied := origRec.Proxied != nil && *origRec.Proxied

				if !strings.EqualFold(er.Name, origRec.Name) ||
					!strings.EqualFold(er.Type, origRec.Type) ||
					er.Content != origRec.Content ||
					proxied != origProxied ||
					ttl != origRec.TTL ||
					er.Comment != origRec.Comment {

					toUpdate = append(toUpdate, UpdateItem{
						Params: cloudflare.UpdateDNSRecordParams{
							ID:      er.ID,
							Type:    er.Type,
							Name:    er.Name,
							Content: er.Content,
							TTL:     ttl,
							Proxied: cloudflare.BoolPtr(proxied),
							Comment: cloudflare.StringPtr(er.Comment),
						},
						Target: er.Name,
					})
				}
				continue
			}
		}

		matchedOrigID := ""
		for _, origRec := range filteredRecords {
			if !keptIDs[origRec.ID] {
				origProxied := origRec.Proxied != nil && *origRec.Proxied
				if strings.EqualFold(er.Name, origRec.Name) &&
					strings.EqualFold(er.Type, origRec.Type) &&
					er.Content == origRec.Content &&
					proxied == origProxied &&
					ttl == origRec.TTL &&
					er.Comment == origRec.Comment {
					matchedOrigID = origRec.ID
					break
				}
			}
		}

		if matchedOrigID != "" {
			keptIDs[matchedOrigID] = true
		} else {
			toCreate = append(toCreate, cloudflare.CreateDNSRecordParams{
				Type:    er.Type,
				Name:    er.Name,
				Content: er.Content,
				TTL:     ttl,
				Proxied: cloudflare.BoolPtr(proxied),
				Comment: er.Comment,
			})
		}
	}

	var toDelete []cloudflare.DNSRecord
	for _, origRec := range filteredRecords {
		if !keptIDs[origRec.ID] {
			toDelete = append(toDelete, origRec)
		}
	}

	if len(toUpdate) == 0 && len(toCreate) == 0 && len(toDelete) == 0 {
		log.Println("No changes detected. Cloudflare DNS records were not modified.")
		return nil
	}

	dryRunPrefix := ""
	if cfg.DryRun {
		dryRunPrefix = "[Dry Run] "
		log.Println("********** DRY RUN MODE ENABLED **********")
		log.Println("No changes will be made to Cloudflare DNS records.")
		log.Println("******************************************")
	}

	log.Printf("%sChanges detected: %d to update, %d to create, %d to delete.", dryRunPrefix, len(toUpdate), len(toCreate), len(toDelete))

	rc := cloudflare.ZoneIdentifier(cfg.CfZone)

	for _, item := range toUpdate {
		log.Printf("%sUpdating DNS record %s (ID: %s)...", dryRunPrefix, item.Target, item.Params.ID)
		if !cfg.DryRun {
			_, err := cfAPI.UpdateDNSRecord(ctx, rc, item.Params)
			if err != nil {
				log.Printf("ERROR updating DNS record %s: %v", item.Target, err)
			} else {
				log.Printf("Successfully updated DNS record %s", item.Target)
			}
		}
	}

	for _, createParams := range toCreate {
		log.Printf("%sCreating DNS record %s (%s -> %s)...", dryRunPrefix, createParams.Name, createParams.Type, createParams.Content)
		if !cfg.DryRun {
			_, err := cfAPI.CreateDNSRecord(ctx, rc, createParams)
			if err != nil {
				log.Printf("ERROR creating DNS record %s: %v", createParams.Name, err)
			} else {
				log.Printf("Successfully created DNS record %s", createParams.Name)
			}
		}
	}

	for _, delRec := range toDelete {
		log.Printf("%sDeleting DNS record %s (ID: %s, %s %s)...", dryRunPrefix, delRec.Name, delRec.ID, delRec.Type, delRec.Content)
		if !cfg.DryRun {
			err := cfAPI.DeleteDNSRecord(ctx, rc, delRec.ID)
			if err != nil {
				log.Printf("ERROR deleting DNS record %s: %v", delRec.Name, err)
			} else {
				log.Printf("Successfully deleted DNS record %s", delRec.Name)
			}
		}
	}

	log.Println("DNS record editing completed.")
	return nil
}
