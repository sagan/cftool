package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"unicode/utf8"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

type WgConfig struct {
	Interface   string // e.g., "wg0"
	CfToken     string
	CfZone      string
	Domain      string
	DryRun      bool
	DeleteStale bool
}

type WgPeer struct {
	Name string
	IP   string
}

var wg2cfConfig WgConfig

var wg2cfCmd = &cobra.Command{
	Use:   "wg2cf",
	Short: "Sync WireGuard peers to Cloudflare DNS",
	Long:  `wg2cf reads a WireGuard configuration file and updates Cloudflare A records to match peer IPs based on their Name comment.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runWg2cf()
	},
}

func init() {
	rootCmd.AddCommand(wg2cfCmd)

	wg2cfCmd.Flags().StringVar(&wg2cfConfig.Interface, "interface", "wg0", "WireGuard interface name (e.g., wg0)")
	wg2cfCmd.Flags().StringVar(&wg2cfConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	wg2cfCmd.Flags().StringVar(&wg2cfConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	wg2cfCmd.Flags().StringVar(&wg2cfConfig.Domain, "domain", os.Getenv("DOMAIN"), "Target domain (e.g., example.com or z.example.com) (env: DOMAIN)")
	wg2cfCmd.Flags().BoolVar(&wg2cfConfig.DryRun, "dry-run", false, "Enable dry run mode (log changes without applying)")
	wg2cfCmd.Flags().BoolVar(&wg2cfConfig.DeleteStale, "delete-stale", false, "Enable deletion of stale DNS records in Cloudflare")
}

func parseWgConf(filename string) ([]WgPeer, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var peers []WgPeer
	var inPeer bool
	var currentName string
	var currentIP string
	var hasName bool
	var nameIsAscii bool
	var hasInvalidIP bool

	finalizePeer := func() {
		if !inPeer {
			return
		}
		if !hasName {
			log.Println("WARN: Peer doesn't have # Name comment, skipping")
		} else if !nameIsAscii {
			log.Println("WARN: Peer name contains non-ASCII characters, skipping")
		} else if hasInvalidIP || currentIP == "" {
			log.Printf("WARN: Peer %q's first AllowedIPs isn't a valid IP, skipping", currentName)
		} else {
			peers = append(peers, WgPeer{Name: currentName, IP: currentIP})
		}
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[Peer]" {
			finalizePeer()
			inPeer = true
			currentName = ""
			currentIP = ""
			hasName = false
			nameIsAscii = false
			hasInvalidIP = false
			continue
		}

		if !inPeer {
			continue
		}

		if strings.HasPrefix(line, "#") {
			commentContent := strings.TrimSpace(line[1:])
			parts := strings.SplitN(commentContent, "=", 2)
			if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "Name") {
				hasName = true
				name := strings.TrimSpace(parts[1])
				name, _, _ = strings.Cut(name, " ")

				isAscii := true
				for i := 0; i < len(name); i++ {
					if name[i] >= utf8.RuneSelf {
						isAscii = false
						break
					}
				}
				nameIsAscii = isAscii
				if isAscii {
					currentName = name
				}
			}
			continue
		}

		if strings.HasPrefix(strings.ToLower(line), "allowedips") {
			// We only want the first valid AllowedIPs directive we see per peer
			if currentIP != "" || hasInvalidIP {
				continue
			}
			line, _, _ = strings.Cut(line, "#")
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				ipsStr := strings.TrimSpace(parts[1])
				ipList := strings.Split(ipsStr, ",")
				if len(ipList) > 0 {
					firstIPWithCIDR := strings.TrimSpace(ipList[0])
					ipPart := strings.Split(firstIPWithCIDR, "/")[0]
					if parsedIP := net.ParseIP(ipPart); parsedIP == nil {
						hasInvalidIP = true
					} else {
						currentIP = parsedIP.String()
					}
				} else {
					hasInvalidIP = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	finalizePeer()

	return peers, nil
}

func getWgCloudflareRecords(ctx context.Context, cfAPI *cloudflare.API, zone, domain string) (map[string][]cloudflare.DNSRecord, error) {
	recs, _, err := cfAPI.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zone), cloudflare.ListDNSRecordsParams{Type: "A"})
	if err != nil {
		return nil, fmt.Errorf("failed to list Cloudflare DNS records: %w", err)
	}

	existingRecords := make(map[string][]cloudflare.DNSRecord)
	targetSuffix := "." + domain

	var found int
	for _, r := range recs {
		if strings.HasSuffix(r.Name, targetSuffix) {
			lowerName := strings.ToLower(r.Name)
			existingRecords[lowerName] = append(existingRecords[lowerName], r)
			found++
		}
	}
	log.Printf("Found %d existing Cloudflare A records matching suffix %s", found, targetSuffix)
	return existingRecords, nil
}

func runWg2cf() error {
	log.Println("Starting WireGuard -> Cloudflare DNS Sync...")

	cfg := wg2cfConfig
	cfg.Domain = strings.TrimPrefix(cfg.Domain, ".")

	if cfg.Interface == "" || cfg.CfToken == "" || cfg.CfZone == "" || cfg.Domain == "" {
		return fmt.Errorf("missing required configuration (check flags -h or environment variables like CF_TOKEN, CF_ZONE, DOMAIN)")
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

	cfAPI, err := cloudflare.NewWithAPIToken(cfg.CfToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare API client: %w", err)
	}

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", cfg.Interface)
	peers, err := parseWgConf(confPath)
	if err != nil {
		return fmt.Errorf("error parsing WireGuard config %s: %w", confPath, err)
	}
	log.Printf("Parsed %d valid peers from %s", len(peers), confPath)

	cfRecords, err := getWgCloudflareRecords(ctx, cfAPI, cfg.CfZone, cfg.Domain)
	if err != nil {
		return fmt.Errorf("error fetching Cloudflare DNS records: %w", err)
	}

	processedCfRecordIDs := make(map[string]bool)

	for _, peer := range peers {
		memberName := strings.ToLower(strings.TrimSpace(peer.Name))
		memberName = strings.ReplaceAll(memberName, " ", "-")
		if !isValidDNSLabel(memberName) {
			log.Printf("Skipping peer %q: Not a valid DNS label", peer.Name)
			continue
		}

		targetFQDN := fmt.Sprintf("%s.%s", memberName, cfg.Domain)
		targetFQDNLower := strings.ToLower(targetFQDN)

		log.Printf("Processing Peer: Name='%s', Target FQDN='%s', IP=%s", peer.Name, targetFQDN, peer.IP)

		existingRecs, exists := cfRecords[targetFQDNLower]
		if exists && len(existingRecs) > 0 {
			var matchedRec *cloudflare.DNSRecord
			for i := range existingRecs {
				if existingRecs[i].Content == peer.IP {
					matchedRec = &existingRecs[i]
					break
				}
			}

			if matchedRec != nil {
				processedCfRecordIDs[matchedRec.ID] = true
				log.Printf("Record %s is already up-to-date (%s).", targetFQDN, peer.IP)
			} else {
				recToUpdate := existingRecs[0]
				processedCfRecordIDs[recToUpdate.ID] = true
				log.Printf("%sUpdate required for %s: %s -> %s", dryRunPrefix, targetFQDN, recToUpdate.Content, peer.IP)
				if !cfg.DryRun {
					updateParams := cloudflare.UpdateDNSRecordParams{
						ID: recToUpdate.ID, Type: "A", Name: targetFQDN, Content: peer.IP, TTL: recToUpdate.TTL, Proxied: recToUpdate.Proxied,
					}
					_, err = cfAPI.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), updateParams)
					if err != nil {
						log.Printf("ERROR updating DNS record %s: %v", targetFQDN, err)
					} else {
						log.Printf("Successfully updated DNS record %s", targetFQDN)
					}
				}
			}
		} else {
			log.Printf("%sCreation required for %s -> %s", dryRunPrefix, targetFQDN, peer.IP)
			if !cfg.DryRun {
				createParams := cloudflare.CreateDNSRecordParams{
					Type: "A", Name: targetFQDN, Content: peer.IP, TTL: 1, Proxied: cloudflare.BoolPtr(false),
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

	if cfg.DeleteStale {
		log.Println("Checking for stale Cloudflare records...")
		deletedCount := 0
		for _, recs := range cfRecords {
			for _, rec := range recs {
				if _, processed := processedCfRecordIDs[rec.ID]; !processed {
					log.Printf("%sDeletion required for stale record %s (ID: %s, IP: %s)", dryRunPrefix, rec.Name, rec.ID, rec.Content)
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
		}
		if deletedCount > 0 {
			log.Printf("%sIdentified %d stale records for deletion.", dryRunPrefix, deletedCount)
		} else {
			log.Println("No stale records found requiring deletion.")
		}
	}

	log.Println("DNS Sync process completed.")
	if cfg.DryRun {
		log.Println("NOTE: Dry run mode was enabled. No actual changes were made.")
	}
	return nil
}
