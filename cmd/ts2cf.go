package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

// TsConfig holds configuration for ts2cf command
type TsConfig struct {
	CfToken      string
	CfZone       string
	Domain       string
	DryRun       bool
	DeleteStale  bool
	TailscaleBin string
	StatusFile   string
	IncludeSelf  bool
}

var ts2cfConfig TsConfig

// --- Structs for Tailscale status --json Response ---

type TailscaleStatus struct {
	Version      string                          `json:"Version"`
	BackendState string                          `json:"BackendState"`
	TailscaleIPs []string                        `json:"TailscaleIPs"`
	Self         *TailscalePeerStatus            `json:"Self"`
	Peer         map[string]*TailscalePeerStatus `json:"Peer"`
}

type TailscalePeerStatus struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	ShareeNode   bool     `json:"ShareeNode"`
}

type TailscaleDevice struct {
	ID       string
	Name     string
	IP       string
	HostName string
	DNSName  string
	IsSelf   bool
}

var ts2cfCmd = &cobra.Command{
	Use:   "ts2cf",
	Short: "Sync Tailscale network devices to Cloudflare DNS",
	Long:  `ts2cf fetches devices from Tailscale (via tailscale status --json) and updates Cloudflare A records to match their IPs.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTs2cf()
	},
}

func defaultTailscaleBin() string {
	if env := os.Getenv("TAILSCALE_BIN"); env != "" {
		return env
	}
	return "tailscale"
}

func init() {
	rootCmd.AddCommand(ts2cfCmd)

	ts2cfCmd.Flags().StringVar(&ts2cfConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	ts2cfCmd.Flags().StringVar(&ts2cfConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	ts2cfCmd.Flags().StringVar(&ts2cfConfig.Domain, "domain", os.Getenv("DOMAIN"), "Target domain (e.g., example.com or ts.example.com) (env: DOMAIN)")
	ts2cfCmd.Flags().BoolVar(&ts2cfConfig.DryRun, "dry-run", false, "Enable dry run mode (log changes without applying)")
	ts2cfCmd.Flags().BoolVar(&ts2cfConfig.DeleteStale, "delete-stale", false, "Enable deletion of stale DNS records in Cloudflare")
	ts2cfCmd.Flags().StringVar(&ts2cfConfig.TailscaleBin, "tailscale-bin", defaultTailscaleBin(), "Tailscale binary path or name (env: TAILSCALE_BIN)")
	ts2cfCmd.Flags().StringVar(&ts2cfConfig.StatusFile, "status-file", os.Getenv("TAILSCALE_STATUS_FILE"), "Read tailscale status JSON from file or stdin (-) instead of running tailscale CLI (env: TAILSCALE_STATUS_FILE)")
	ts2cfCmd.Flags().BoolVar(&ts2cfConfig.IncludeSelf, "include-self", true, "Include local device (Self) in DNS sync")
}

// extractDeviceName extracts a valid DNS label from DNSName or HostName
func extractDeviceName(dnsName, hostName string) string {
	// First preference: MagicDNS name from DNSName (e.g., "my-node.tailnet.ts.net." -> "my-node")
	if trimmed := strings.TrimSuffix(strings.TrimSpace(dnsName), "."); trimmed != "" {
		parts := strings.Split(trimmed, ".")
		candidate := strings.ToLower(strings.TrimSpace(parts[0]))
		if isValidDNSLabel(candidate) {
			return candidate
		}
	}

	// Second preference: HostName sanitized
	if host := strings.TrimSpace(hostName); host != "" {
		candidate := strings.ToLower(host)
		candidate = strings.ReplaceAll(candidate, " ", "-")
		if isValidDNSLabel(candidate) {
			return candidate
		}
	}

	return ""
}

// findTailscaleIPv4 returns the first valid IPv4 address from a slice of IP strings
func findTailscaleIPv4(ips []string) string {
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		ip := net.ParseIP(ipStr)
		if ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// parseTailscaleStatus parses Tailscale status JSON bytes into a list of devices
func parseTailscaleStatus(data []byte, includeSelf bool) ([]TailscaleDevice, error) {
	var status TailscaleStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, fmt.Errorf("failed to decode Tailscale status JSON: %w", err)
	}

	var devices []TailscaleDevice
	seenNames := make(map[string]string) // name -> device ID

	// 1. Process Self device if enabled and present
	if includeSelf && status.Self != nil {
		selfID := status.Self.ID
		if selfID == "" {
			selfID = "self"
		}

		selfName := extractDeviceName(status.Self.DNSName, status.Self.HostName)
		if selfName == "" {
			log.Printf("Skipping local device (Self): Neither DNSName ('%s') nor HostName ('%s') yield a valid DNS label.", status.Self.DNSName, status.Self.HostName)
		} else {
			selfIPs := status.Self.TailscaleIPs
			if len(selfIPs) == 0 {
				selfIPs = status.TailscaleIPs
			}
			managedIP := findTailscaleIPv4(selfIPs)
			if managedIP == "" {
				log.Printf("Skipping local device (Self): No IPv4 address found.")
			} else {
				devices = append(devices, TailscaleDevice{
					ID:       selfID,
					Name:     selfName,
					IP:       managedIP,
					HostName: status.Self.HostName,
					DNSName:  status.Self.DNSName,
					IsSelf:   true,
				})
				seenNames[selfName] = selfID
			}
		}
	}

	// 2. Process Peers (sorted for deterministic order)
	if len(status.Peer) > 0 {
		peerKeys := make([]string, 0, len(status.Peer))
		for k := range status.Peer {
			peerKeys = append(peerKeys, k)
		}
		sort.Strings(peerKeys)

		for _, k := range peerKeys {
			peer := status.Peer[k]
			if peer == nil {
				continue
			}

			peerID := peer.ID
			if peerID == "" {
				peerID = k
			}

			peerName := extractDeviceName(peer.DNSName, peer.HostName)
			if peerName == "" {
				log.Printf("Skipping peer NodeID %s: Neither DNSName ('%s') nor HostName ('%s') yield a valid DNS label.", peerID, peer.DNSName, peer.HostName)
				continue
			}

			managedIP := findTailscaleIPv4(peer.TailscaleIPs)
			if managedIP == "" {
				log.Printf("Skipping peer NodeID %s (%s): No IPv4 address found.", peerID, peerName)
				continue
			}

			if existingID, seen := seenNames[peerName]; seen {
				log.Printf("WARN: Duplicate device name '%s' for NodeID %s (already registered by %s), skipping.", peerName, peerID, existingID)
				continue
			}

			devices = append(devices, TailscaleDevice{
				ID:       peerID,
				Name:     peerName,
				IP:       managedIP,
				HostName: peer.HostName,
				DNSName:  peer.DNSName,
				IsSelf:   false,
			})
			seenNames[peerName] = peerID
		}
	}

	return devices, nil
}

// resolveTailscaleBinary finds the tailscale executable path if standard command fails
func resolveTailscaleBinary(bin string) string {
	if bin == "" {
		bin = "tailscale"
	}
	if _, err := exec.LookPath(bin); err == nil {
		return bin
	}

	// Check standard OS paths when defaulting to "tailscale"
	if bin == "tailscale" {
		var candidates []string
		if runtime.GOOS == "windows" {
			candidates = []string{
				`C:\Program Files\Tailscale\tailscale.exe`,
				`C:\Program Files (x86)\Tailscale\tailscale.exe`,
			}
		} else if runtime.GOOS == "darwin" {
			candidates = []string{
				"/usr/local/bin/tailscale",
				"/Applications/Tailscale.app/Contents/MacOS/Tailscale",
			}
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
	}

	return bin
}

// getTailscaleDevices retrieves devices either from status-file or tailscale status --json
func getTailscaleDevices(ctx context.Context, cfg TsConfig) ([]TailscaleDevice, error) {
	var data []byte
	var err error

	if cfg.StatusFile != "" {
		if cfg.StatusFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(cfg.StatusFile)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tailscale status file %s: %w", cfg.StatusFile, err)
		}
	} else {
		bin := resolveTailscaleBinary(cfg.TailscaleBin)
		cmd := exec.CommandContext(ctx, bin, "status", "--json")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("failed to run '%s status --json': %w (stderr: %s)", bin, err, strings.TrimSpace(stderr.String()))
		}
		data = stdout.Bytes()
	}

	return parseTailscaleStatus(data, cfg.IncludeSelf)
}

// getTsCloudflareRecords fetches existing A records for the target domain
func getTsCloudflareRecords(ctx context.Context, cfAPI *cloudflare.API, zone, domain string) (map[string]cloudflare.DNSRecord, error) {
	rc := cloudflare.ZoneIdentifier(zone)
	params := cloudflare.ListDNSRecordsParams{Type: "A"}
	var allRecs []cloudflare.DNSRecord

	for {
		recs, resultInfo, err := cfAPI.ListDNSRecords(ctx, rc, params)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cloudflare DNS records: %w", err)
		}
		allRecs = append(allRecs, recs...)
		if resultInfo == nil || !resultInfo.HasMorePages() {
			break
		}
		params.ResultInfo = resultInfo.Next()
	}

	existingRecords := make(map[string]cloudflare.DNSRecord)
	targetSuffix := "." + domain

	for _, r := range allRecs {
		if strings.HasSuffix(strings.ToLower(r.Name), strings.ToLower(targetSuffix)) {
			existingRecords[strings.ToLower(r.Name)] = r
		}
	}
	log.Printf("Found %d existing Cloudflare A records matching suffix %s", len(existingRecords), targetSuffix)
	return existingRecords, nil
}

func runTs2cf() error {
	log.Println("Starting Tailscale -> Cloudflare DNS Sync...")

	cfg := ts2cfConfig
	cfg.Domain = strings.Trim(cfg.Domain, ".")

	// Validate required fields
	if cfg.CfToken == "" || cfg.CfZone == "" || cfg.Domain == "" {
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

	// Initialize Cloudflare API client
	cfAPI, err := cloudflare.NewWithAPIToken(cfg.CfToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare API client: %w", err)
	}

	// 1. Get Tailscale Devices
	devices, err := getTailscaleDevices(ctx, cfg)
	if err != nil {
		return fmt.Errorf("error fetching Tailscale devices: %w", err)
	}
	log.Printf("Fetched %d devices from Tailscale", len(devices))

	// 2. Get relevant existing Cloudflare DNS Records
	cfRecords, err := getTsCloudflareRecords(ctx, cfAPI, cfg.CfZone, cfg.Domain)
	if err != nil {
		return fmt.Errorf("error fetching Cloudflare DNS records: %w", err)
	}

	// 3. Sync Logic: Process Tailscale devices -> Create/Update Cloudflare records
	processedCfRecords := make(map[string]bool)

	for _, device := range devices {
		targetFQDN := fmt.Sprintf("%s.%s", device.Name, cfg.Domain)
		targetFQDNLower := strings.ToLower(targetFQDN)

		log.Printf("Processing Device: Name='%s', ID=%s, Target FQDN='%s', IP=%s", device.Name, device.ID, targetFQDN, device.IP)

		if existingRec, exists := cfRecords[targetFQDNLower]; exists {
			processedCfRecords[targetFQDNLower] = true
			if existingRec.Content != device.IP {
				log.Printf("%sUpdate required for %s: %s -> %s", dryRunPrefix, targetFQDN, existingRec.Content, device.IP)
				if !cfg.DryRun {
					updateParams := cloudflare.UpdateDNSRecordParams{
						ID:       existingRec.ID,
						Type:     "A",
						Name:     targetFQDN,
						Content:  device.IP,
						TTL:      existingRec.TTL,
						Proxied:  existingRec.Proxied,
					}
					_, err = cfAPI.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), updateParams)
					if err != nil {
						log.Printf("ERROR updating DNS record %s: %v", targetFQDN, err)
					} else {
						log.Printf("Successfully updated DNS record %s", targetFQDN)
					}
				}
			} else {
				log.Printf("Record %s is already up-to-date (%s).", targetFQDN, device.IP)
			}
		} else {
			log.Printf("%sCreation required for %s -> %s", dryRunPrefix, targetFQDN, device.IP)
			if !cfg.DryRun {
				createParams := cloudflare.CreateDNSRecordParams{
					Type:    "A",
					Name:    targetFQDN,
					Content: device.IP,
					TTL:     1,
					Proxied: cloudflare.BoolPtr(false),
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
	}

	log.Println("DNS Sync process completed.")
	if cfg.DryRun {
		log.Println("NOTE: Dry run mode was enabled. No actual changes were made.")
	}
	return nil
}
