package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

const (
	zeroTierBaseURL = "https://my.zerotier.com/api/v1"
)

// --- Configuration Struct ---
type Config struct {
	// zerotier token
	ZtToken string
	// zerotier network id
	ZtNetwork string
	// cloudflare token
	CfToken string
	// cloudflare DNS zone id
	CfZone string
	// cloudflare target domain, e.g. "example.com" or "z.example.com"
	Domain      string
	DryRun      bool
	DeleteStale bool // New flag to control stale record deletion
}

var zt2cfConfig Config

// --- Structs for ZeroTier API Response ---
type ZeroTierMemberConfig struct {
	Authorized    bool     `json:"authorized"`
	IPAssignments []string `json:"ipAssignments"`
}

type ZeroTierMember struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	NodeID      string               `json:"nodeId"`
	Config      ZeroTierMemberConfig `json:"config"`
	Hidden      bool                 `json:"hidden"`
}

var zt2cfCmd = &cobra.Command{
	Use:   "zt2cf",
	Short: "Sync ZeroTier network members to Cloudflare DNS",
	Long:  `zt2cf fetches members from a ZeroTier network and updates Cloudflare A records to match their IPs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runZt2cf()
	},
}

func init() {
	rootCmd.AddCommand(zt2cfCmd)

	zt2cfCmd.Flags().StringVar(&zt2cfConfig.ZtToken, "zt-token", os.Getenv("ZT_TOKEN"), "ZeroTier Central API Token (env: ZT_TOKEN)")
	zt2cfCmd.Flags().StringVar(&zt2cfConfig.ZtNetwork, "zt-network", os.Getenv("ZT_NETWORK"), "ZeroTier Network ID (env: ZT_NETWORK)")
	zt2cfCmd.Flags().StringVar(&zt2cfConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	zt2cfCmd.Flags().StringVar(&zt2cfConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	zt2cfCmd.Flags().StringVar(&zt2cfConfig.Domain, "domain", os.Getenv("DOMAIN"), "Target domain (e.g., example.com or z.example.com) (env: DOMAIN)")
	zt2cfCmd.Flags().BoolVar(&zt2cfConfig.DryRun, "dry-run", false, "Enable dry run mode (log changes without applying)")
	zt2cfCmd.Flags().BoolVar(&zt2cfConfig.DeleteStale, "delete-stale", false, "Enable deletion of stale DNS records in Cloudflare")
}

// getZeroTierMembers fetches members from the ZeroTier network
func getZeroTierMembers(ctx context.Context, cfg Config) ([]ZeroTierMember, error) {
	url := fmt.Sprintf("%s/network/%s/member", zeroTierBaseURL, cfg.ZtNetwork)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ZeroTier request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.ZtToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ZeroTier request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ZeroTier API request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var members []ZeroTierMember
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		return nil, fmt.Errorf("failed to decode ZeroTier members JSON: %w", err)
	}

	log.Printf("Fetched %d members from ZeroTier network %s", len(members), cfg.ZtNetwork)
	return members, nil
}

// getCloudflareRecords fetches existing A records for the target subdomain
func getCloudflareRecords(ctx context.Context, cfAPI *cloudflare.API, cfg Config) (map[string]cloudflare.DNSRecord, error) {
	recs, _, err := cfAPI.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), cloudflare.ListDNSRecordsParams{Type: "A"})
	if err != nil {
		return nil, fmt.Errorf("failed to list Cloudflare DNS records: %w", err)
	}

	existingRecords := make(map[string]cloudflare.DNSRecord)
	targetSuffix := "." + cfg.Domain

	for _, r := range recs {
		if strings.HasSuffix(r.Name, targetSuffix) {
			existingRecords[strings.ToLower(r.Name)] = r
		}
	}
	log.Printf("Found %d existing Cloudflare A records matching suffix %s", len(existingRecords), targetSuffix)
	return existingRecords, nil
}

// isValidDNSLabel checks if a string is a valid DNS label (simple check)
func isValidDNSLabel(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	valid := true
	for i, r := range name {
		isLetterOrDigit := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		isHyphen := r == '-'
		if !isLetterOrDigit && !isHyphen {
			valid = false
			break
		}
		if isHyphen && (i == 0 || i == len(name)-1) {
			valid = false
			break
		}
	}
	return valid
}

func runZt2cf() error {
	log.Println("Starting ZeroTier -> Cloudflare DNS Sync...")

	cfg := zt2cfConfig
	cfg.Domain = strings.TrimPrefix(cfg.Domain, ".")

	// Validate required fields
	if cfg.ZtToken == "" || cfg.ZtNetwork == "" || cfg.CfToken == "" || cfg.CfZone == "" || cfg.Domain == "" {
		return fmt.Errorf("missing required configuration (check flags -h or environment variables like ZT_TOKEN, ZT_NETWORK, CF_TOKEN, CF_ZONE, DOMAIN)")
	}

	dryRunPrefix := ""
	if cfg.DryRun {
		dryRunPrefix = "[Dry Run] "
		log.Println("********** DRY RUN MODE ENABLED **********")
		log.Println("No changes will be made to Cloudflare DNS records.")
		log.Println("******************************************")
	}
	if cfg.DeleteStale {
		log.Println("INFO: Stale record deletion is ENABLED.")
	} else {
		log.Println("INFO: Stale record deletion is DISABLED.")
	}

	ctx := context.Background()

	// Initialize Cloudflare API client
	cfAPI, err := cloudflare.NewWithAPIToken(cfg.CfToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare API client: %w", err)
	}

	// 1. Get ZeroTier Members
	ztMembers, err := getZeroTierMembers(ctx, cfg)
	if err != nil {
		return fmt.Errorf("error fetching ZeroTier members: %w", err)
	}

	// 2. Get relevant existing Cloudflare DNS Records
	cfRecords, err := getCloudflareRecords(ctx, cfAPI, cfg)
	if err != nil {
		return fmt.Errorf("error fetching Cloudflare DNS records: %w", err)
	}

	// 3. Sync Logic: Process ZeroTier members -> Create/Update Cloudflare records
	processedCfRecords := make(map[string]bool) // Keep track of CF records corresponding to current ZT members

	for _, member := range ztMembers {
		if !member.Config.Authorized || member.Hidden {
			continue
		}

		var managedIP string
		for _, ip := range member.Config.IPAssignments {
			if strings.Contains(ip, ".") && !strings.Contains(ip, ":") {
				managedIP = ip
				break
			}
		}
		if managedIP == "" {
			continue
		}

		memberName := strings.ToLower(strings.TrimSpace(member.Name))
		if !isValidDNSLabel(memberName) {
			memberName = strings.ToLower(strings.TrimSpace(member.Description))
			memberName = strings.ReplaceAll(memberName, " ", "-")
			if !isValidDNSLabel(memberName) {
				log.Printf("Skipping member NodeID %s: Neither name ('%s') nor description ('%s') yield a valid DNS label.", member.NodeID, member.Name, member.Description)
				continue
			}
		}

		targetFQDN := fmt.Sprintf("%s.%s", memberName, cfg.Domain)
		targetFQDNLower := strings.ToLower(targetFQDN)

		log.Printf("Processing Member: Name='%s', NodeID=%s, Target FQDN='%s', IP=%s", member.Name, member.NodeID, targetFQDN, managedIP)

		if existingRec, exists := cfRecords[targetFQDNLower]; exists {
			processedCfRecords[targetFQDNLower] = true // Mark as processed/valid
			if existingRec.Content != managedIP {
				log.Printf("%sUpdate required for %s: %s -> %s", dryRunPrefix, targetFQDN, existingRec.Content, managedIP)
				if !cfg.DryRun {
					updateParams := cloudflare.UpdateDNSRecordParams{
						ID: existingRec.ID, Type: "A", Name: targetFQDN, Content: managedIP, TTL: existingRec.TTL, Proxied: existingRec.Proxied,
					}
					_, err = cfAPI.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), updateParams)
					if err != nil {
						log.Printf("ERROR updating DNS record %s: %v", targetFQDN, err)
					} else {
						log.Printf("Successfully updated DNS record %s", targetFQDN)
					}
				}
			} else {
				log.Printf("Record %s is already up-to-date (%s).", targetFQDN, managedIP)
			}
		} else {
			log.Printf("%sCreation required for %s -> %s", dryRunPrefix, targetFQDN, managedIP)
			if !cfg.DryRun {
				createParams := cloudflare.CreateDNSRecordParams{
					Type: "A", Name: targetFQDN, Content: managedIP, TTL: 1, Proxied: cloudflare.BoolPtr(false),
				}
				_, err = cfAPI.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), createParams)
				if err != nil {
					if strings.Contains(err.Error(), "The record already exists") {
						log.Printf("WARN: Record %s already exists (likely race condition or previous error), skipping creation.", targetFQDN)
					} else {
						log.Printf("ERROR creating DNS record %s: %v", targetFQDN, err)
					}
				} else {
					log.Printf("Successfully created DNS record %s", targetFQDN)
				}
			}
		}
	}

	// 4. Optional Stale Record Deletion Logic
	if cfg.DeleteStale {
		log.Println("Checking for stale Cloudflare records...")
		deletedCount := 0
		for fqdn, rec := range cfRecords {
			// Check if this existing Cloudflare record was processed (meaning it matched a valid ZT member)
			if _, processed := processedCfRecords[fqdn]; !processed {
				log.Printf("%sDeletion required for stale record %s (ID: %s)", dryRunPrefix, rec.Name, rec.ID)
				deletedCount++
				if !cfg.DryRun {
					err := cfAPI.DeleteDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), rec.ID)
					if err != nil {
						log.Printf("ERROR deleting stale DNS record %s: %v", rec.Name, err)
					} else {
						log.Printf("Successfully deleted stale DNS record %s", rec.Name)
					}
				}
			}
		}
		if deletedCount > 0 {
			log.Printf("%sIdentified %d stale records for deletion.", dryRunPrefix, deletedCount)
		} else {
			log.Println("No stale records found requiring deletion.")
		}
	} // End of DeleteStale check

	log.Println("DNS Sync process completed.")
	if cfg.DryRun {
		log.Println("NOTE: Dry run mode was enabled. No actual changes were made.")
	}
	return nil
}
