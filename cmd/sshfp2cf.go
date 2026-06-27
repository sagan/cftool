package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

// sshKeyTypeToAlgorithm maps the SSH key-type string (as it appears in the public
// key file header) to the SSHFP algorithm number defined in RFC 4255 / RFC 6594.
var sshKeyTypeToAlgorithm = map[string]int{
	"ssh-rsa":             1,
	"ssh-dss":             2,
	"ecdsa-sha2-nistp256": 3,
	"ecdsa-sha2-nistp384": 3,
	"ecdsa-sha2-nistp521": 3,
	"ssh-ed25519":         4,
}

// hostKeyFiles lists the public key files we try to publish, in preference order.
var hostKeyFiles = []string{
	"ssh_host_ed25519_key.pub",
	"ssh_host_ecdsa_key.pub",
	"ssh_host_rsa_key.pub",
}

type SshfpConfig struct {
	CfToken string
	CfZone  string
	Domains []string
	SshDir  string
	DryRun  bool
}

var sshfpConfig SshfpConfig

var updateSshfpCmd = &cobra.Command{
	Use:   "sshfp2cf",
	Short: "Publish local OpenSSH host key fingerprints as SSHFP DNS records",
	Long: `sshfp2cf reads the local OpenSSH server host public keys, computes their
SHA-256 fingerprints, and upserts SSHFP records in Cloudflare DNS.

Only SHA-256 (SSHFP fingerprint type 2) records are published.
Existing records that already match the desired fingerprint are left untouched.
Use --domain (repeatable) to publish to multiple domains.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUpdateSshfp()
	},
}

func init() {
	rootCmd.AddCommand(updateSshfpCmd)

	updateSshfpCmd.Flags().StringVar(&sshfpConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	updateSshfpCmd.Flags().StringVar(&sshfpConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	updateSshfpCmd.Flags().StringArrayVar(&sshfpConfig.Domains, "domain", nil, "Target domain (e.g., example.com). Repeatable.")
	updateSshfpCmd.Flags().StringVar(&sshfpConfig.SshDir, "sshdir", "", "OpenSSH host key directory (default: /etc/ssh on Linux, %PROGRAMDATA%\\ssh on Windows)")
	updateSshfpCmd.Flags().BoolVar(&sshfpConfig.DryRun, "dry-run", false, "Enable dry run mode (log changes without applying)")
}

// sshHostKeyDir returns the OS-appropriate directory for OpenSSH host keys.
func sshHostKeyDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		programData := os.Getenv("PROGRAMDATA")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "ssh"), nil
	default:
		return "/etc/ssh", nil
	}
}

// sshfpRecord holds the parsed information for a single SSHFP record to publish.
type sshfpRecord struct {
	algorithm   int    // RFC 4255 algorithm number
	fpType      int    // always 2 (SHA-256)
	fingerprint string // lowercase hex
	keyFile     string // source filename (for logging)
}

// loadHostKeyFingerprints reads the configured host key directory and returns
// one sshfpRecord per successfully parsed key file.
func loadHostKeyFingerprints(keyDir string) ([]sshfpRecord, error) {
	var records []sshfpRecord

	for _, filename := range hostKeyFiles {
		path := filepath.Join(keyDir, filename)
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("INFO: Host key file not found, skipping: %s", path)
				continue
			}
			return nil, fmt.Errorf("error reading %s: %w", path, err)
		}

		algo, fp, err := parsePubKeyFingerprint(data)
		if err != nil {
			log.Printf("WARN: Could not parse %s: %v", path, err)
			continue
		}

		records = append(records, sshfpRecord{
			algorithm:   algo,
			fpType:      2,
			fingerprint: fp,
			keyFile:     filename,
		})
		log.Printf("Loaded key: %s  algorithm=%d  SHA-256=%s", filename, algo, fp)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no readable host key files found in %s", keyDir)
	}
	return records, nil
}

// parsePubKeyFingerprint parses an OpenSSH public key file (the text format) and
// returns the SSHFP algorithm number and the lowercase-hex SHA-256 fingerprint of
// the raw key bytes (i.e., the base64-decoded wire format).
func parsePubKeyFingerprint(pubKeyData []byte) (algorithm int, hexFingerprint string, err error) {
	line := strings.TrimSpace(string(pubKeyData))
	// Strip any trailing comment; the format is: <type> <base64> [comment...]
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("unexpected public key format: too few fields")
	}

	keyType := strings.ToLower(parts[0])
	algo, ok := sshKeyTypeToAlgorithm[keyType]
	if !ok {
		return 0, "", fmt.Errorf("unsupported key type %q", keyType)
	}

	rawKey, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, "", fmt.Errorf("base64 decode failed: %w", err)
	}

	sum := sha256.Sum256(rawKey)
	return algo, hex.EncodeToString(sum[:]), nil
}

// fetchSSHFPRecords returns all existing SSHFP records for the given domain.
// The map key is "<algorithm>:<fpType>:<fingerprint>" for easy lookup.
func fetchSSHFPRecords(ctx context.Context, cfAPI *cloudflare.API, zoneID, domain string) (map[string]cloudflare.DNSRecord, error) {
	recs, _, err := cfAPI.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{
		Type: "SSHFP",
		Name: domain,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list SSHFP records for %s: %w", domain, err)
	}

	result := make(map[string]cloudflare.DNSRecord)
	for _, r := range recs {
		// Cloudflare returns the SSHFP content as: "<algorithm> <fpType> <fingerprint>"
		key := normalizeSSHFPContent(r.Content)
		if key != "" {
			result[key] = r
		}
	}
	log.Printf("Found %d existing SSHFP records for %s", len(recs), domain)
	return result, nil
}

// normalizeSSHFPContent normalises a Cloudflare SSHFP content string to the
// canonical form "<algorithm> <fpType> <lowercasehex>" used as map keys.
func normalizeSSHFPContent(content string) string {
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return ""
	}
	return fmt.Sprintf("%s %s %s", fields[0], fields[1], strings.ToLower(fields[2]))
}

func runUpdateSshfp() error {
	cfg := sshfpConfig

	if cfg.CfToken == "" || cfg.CfZone == "" {
		return fmt.Errorf("missing required configuration: --cf-token and --cf-zone must be provided (or set CF_TOKEN / CF_ZONE env vars)")
	}
	if len(cfg.Domains) == 0 {
		return fmt.Errorf("at least one --domain flag is required")
	}

	// Normalise domains (strip leading dots)
	for i, d := range cfg.Domains {
		cfg.Domains[i] = strings.TrimPrefix(strings.ToLower(d), ".")
	}

	if cfg.DryRun {
		log.Println("********** DRY RUN MODE ENABLED **********")
		log.Println("No changes will be made to Cloudflare DNS records.")
		log.Println("******************************************")
	}

	// 1. Discover host key directory and load fingerprints.
	keyDir := cfg.SshDir
	if keyDir == "" {
		var err error
		keyDir, err = sshHostKeyDir()
		if err != nil {
			return fmt.Errorf("could not determine SSH host key directory: %w", err)
		}
	}
	log.Printf("Reading OpenSSH host keys from: %s", keyDir)

	hostKeys, err := loadHostKeyFingerprints(keyDir)
	if err != nil {
		return err
	}

	// 2. Initialise Cloudflare client.
	cfAPI, err := cloudflare.NewWithAPIToken(cfg.CfToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare API client: %w", err)
	}
	ctx := context.Background()

	// 3. For each requested domain, upsert all SSHFP records.
	for _, domain := range cfg.Domains {
		log.Printf("--- Processing domain: %s ---", domain)

		existingRecords, err := fetchSSHFPRecords(ctx, cfAPI, cfg.CfZone, domain)
		if err != nil {
			log.Printf("ERROR: %v", err)
			continue
		}

		for _, hk := range hostKeys {
			desiredContent := fmt.Sprintf("%d %d %s", hk.algorithm, hk.fpType, hk.fingerprint)
			lookupKey := normalizeSSHFPContent(desiredContent)

			if existingRec, exists := existingRecords[lookupKey]; exists {
				log.Printf("SSHFP record already up-to-date for %s (from %s): %s", domain, hk.keyFile, desiredContent)
				_ = existingRec
				continue
			}

			// Check if there's any existing record with the same algorithm+fpType that
			// has a *different* fingerprint — if so, update it instead of creating new.
			oldRec, hasOldRec := findSSHFPByAlgoAndType(existingRecords, hk.algorithm, hk.fpType)

			if hasOldRec {
				log.Printf("Update required for %s SSHFP %d %d: %s -> %s (from %s)",
					domain, hk.algorithm, hk.fpType, oldRec.Content, desiredContent, hk.keyFile)
				if !cfg.DryRun {
					_, err := cfAPI.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), cloudflare.UpdateDNSRecordParams{
						ID:      oldRec.ID,
						Type:    "SSHFP",
						Name:    domain,
						Content: desiredContent,
						TTL:     oldRec.TTL,
						Proxied: cloudflare.BoolPtr(false),
					})
					if err != nil {
						log.Printf("ERROR updating SSHFP record for %s: %v", domain, err)
					} else {
						log.Printf("Successfully updated SSHFP record for %s: %s", domain, desiredContent)
					}
				}
			} else {
				log.Printf("Creation required for %s SSHFP: %s (from %s)", domain, desiredContent, hk.keyFile)
				if !cfg.DryRun {
					_, err := cfAPI.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(cfg.CfZone), cloudflare.CreateDNSRecordParams{
						Type:    "SSHFP",
						Name:    domain,
						Content: desiredContent,
						TTL:     1,
						Proxied: cloudflare.BoolPtr(false),
					})
					if err != nil {
						if strings.Contains(err.Error(), "The record already exists") {
							log.Printf("WARN: SSHFP record for %s already exists (race condition?), skipping.", domain)
						} else {
							log.Printf("ERROR creating SSHFP record for %s: %v", domain, err)
						}
					} else {
						log.Printf("Successfully created SSHFP record for %s: %s", domain, desiredContent)
					}
				}
			}
		}
	}

	log.Println("SSHFP update process completed.")
	if cfg.DryRun {
		log.Println("NOTE: Dry run mode was enabled. No actual changes were made.")
	}
	return nil
}

// findSSHFPByAlgoAndType searches the existing records map for any SSHFP entry
// matching the given algorithm and fingerprint type.
func findSSHFPByAlgoAndType(records map[string]cloudflare.DNSRecord, algorithm, fpType int) (cloudflare.DNSRecord, bool) {
	prefix := fmt.Sprintf("%d %d ", algorithm, fpType)
	for key, rec := range records {
		if strings.HasPrefix(key, prefix) {
			return rec, true
		}
	}
	return cloudflare.DNSRecord{}, false
}
