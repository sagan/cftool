package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync" // For concurrent CNAME resolution

	"github.com/cloudflare/cloudflare-go" // Official Cloudflare Go SDK
	"github.com/spf13/cobra"
)

const (
	HOSTS_FILE_DELIMITER_PREFIX = "# CF2HOSTS"
)

type Cf2HostsConfig struct {
	CfToken       string
	CfZone        string
	Domain        string
	ExcludeDomain string
	SaveSrvDir    string
	Identifier    string
	HostsFilePath string
	DryRun        bool
	Verbose       bool
}

var cf2HostsConfig Cf2HostsConfig

var cf2hostsCmd = &cobra.Command{
	Use:   "cf2hosts",
	Short: "Sync Cloudflare records to local hostfile & SRV ipsets",
	Long:  `cf2hosts fetches Cloudflare DNS records to keep local hostfiles up to date and exports SRV records to ipset files.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCf2Hosts()
	},
}

func init() {
	rootCmd.AddCommand(cf2hostsCmd)

	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.CfToken, "cf-token", os.Getenv("CF_TOKEN"), "Cloudflare API Token (env: CF_TOKEN)")
	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.CfZone, "cf-zone", os.Getenv("CF_ZONE"), "Cloudflare Zone ID (env: CF_ZONE)")
	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.Domain, "domain", os.Getenv("DOMAIN"), `Base domain/subdomain (or multiple comma separated domains) to manage (e.g., example.com) (env: DOMAIN). If a domain in list has a "^" prefix, only the domain itself matches, otherwise the domain and all subdomains inside it matches`)
	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.ExcludeDomain, "exclude-domain", os.Getenv("EXCLUDE_DOMAIN"), `Exclude domain/subdomain (or multiple comma separated domains) from management (e.g., exclude.example.com) (env: EXCLUDE_DOMAIN). If a domain in list has a "^" prefix, only the domain itself matches, otherwise the domain and all subdomains inside it matches`)
	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.SaveSrvDir, "save-srv-dir", os.Getenv("SAVE_SRV_DIR"), "Directory to save SRV records for ipset (optional) (env: SAVE_SRV_DIR)")
	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.Identifier, "identifier", os.Getenv("IDENTIFIER"), "Optional hosts file updating section identifier mark (env: IDENTIFIER)")
	
	defaultHosts := os.Getenv("HOSTS_FILE")
	if defaultHosts == "" {
		if path, err := getSystemHostsFilePath(); err == nil {
			defaultHosts = path
		}
	}
	cf2hostsCmd.Flags().StringVar(&cf2HostsConfig.HostsFilePath, "hosts-file", defaultHosts, `Hosts file path. If not provided, will use current OS system hosts file (env: HOSTS_FILE)`)
	cf2hostsCmd.Flags().BoolVar(&cf2HostsConfig.DryRun, "dry-run", false, "If true, no actual changes will be made")
	cf2hostsCmd.Flags().BoolVar(&cf2HostsConfig.Verbose, "verbose", false, "Enable verbose output")
}

// Inline utils
func utilToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func utilToInt(v any) int {
	if v == nil {
		return 0
	}
	switch value := v.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		i, err := strconv.Atoi(utilToString(v))
		if err != nil {
			return 0
		}
		return i
	}
}

// ----------------------
// Core Logic
// ----------------------
func runCf2Hosts() error {
	cfg := cf2HostsConfig

	if cfg.CfToken == "" || cfg.CfZone == "" || cfg.Domain == "" {
		return fmt.Errorf("error: cf-token, cf-zone, and domain must be provided")
	}

	if cfg.HostsFilePath == "" {
		var err error
		cfg.HostsFilePath, err = getSystemHostsFilePath()
		if err != nil {
			return fmt.Errorf("error getting system hosts file path: %w", err)
		}
	}
	cfg.Domain = strings.ToLower(cfg.Domain)

	if cfg.DryRun {
		fmt.Printf("--- DRY RUN MODE ENABLED ---\n")
	}
	if cfg.Verbose {
		fmt.Printf("Verbose mode enabled.\n")
		log.Printf("Using hosts file: %s", cfg.HostsFilePath)
	}

	api, err := cloudflare.NewWithAPIToken(cfg.CfToken)
	if err != nil {
		return fmt.Errorf("error creating Cloudflare client: %w", err)
	}

	if cfg.Verbose {
		log.Printf("Fetching DNS records for zone ID %q and domain %q", cfg.CfZone, cfg.Domain)
	}

	records, err := _fetchDNSRecords(api, cfg.CfZone)
	if err != nil {
		return fmt.Errorf("error fetching DNS records: %w", err)
	}
	for _, record := range records {
		record.Name = strings.ToLower(record.Name)
		record.Content = strings.ToLower(record.Content)
	}
	recordIps := resolveIps(records)

	if cfg.Verbose {
		log.Printf("Found %d DNS records.", len(records))
	}

	var cnameRecords []cloudflare.DNSRecord
	var srvRecords []cloudflare.DNSRecord

	domains := strings.Split(cfg.Domain, ",")
	excludeDomains := strings.Split(cfg.ExcludeDomain, ",")
	for i, d := range domains {
		domains[i] = strings.TrimPrefix(d, ".")
	}
	for i, d := range excludeDomains {
		excludeDomains[i] = strings.TrimPrefix(d, ".")
	}

	hostsEntries := make(map[string]string)
	failedEntries := make(map[string]bool)

	for _, r := range records {
		if !slices.ContainsFunc(domains, func(domain string) bool {
			if strings.HasPrefix(domain, "^") {
				return r.Name == domain[1:]
			}
			return r.Name == domain || strings.HasSuffix(r.Name, "."+domain)
		}) || slices.ContainsFunc(excludeDomains, func(domain string) bool {
			if strings.HasPrefix(domain, "^") {
				return r.Name == domain[1:]
			}
			return r.Name == domain || strings.HasSuffix(r.Name, "."+domain)
		}) || strings.HasPrefix(r.Name, "*.") {
			if cfg.Verbose {
				log.Printf("Ignore %q => %q record", r.Name, r.Content)
			}
			continue
		}
		switch r.Type {
		case "A":
			if r.Content == "" || r.Content == "0.0.0.0" || r.Content == "255.255.255.255" {
				log.Printf("Ignore empty or invalid %q => %q record", r.Name, r.Content)
				continue
			}
			hostsEntries[r.Name] = r.Content
			if cfg.Verbose {
				log.Printf("[A Record] %s -> %s", r.Name, r.Content)
			}
		case "CNAME":
			if ip := getDomainIp(recordIps, r.Content); ip != "" {
				hostsEntries[r.Name] = ip
				if cfg.Verbose {
					log.Printf("[self-resolved CNAME Record] %s -> %s", r.Name, ip)
				}
			} else {
				cnameRecords = append(cnameRecords, r)
			}
		case "SRV":
			srvRecords = append(srvRecords, r)
		}
	}
	if cfg.Verbose {
		log.Printf("Filtered records: %d A, %d CNAME, %d SRV", len(hostsEntries), len(cnameRecords), len(srvRecords))
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, r := range cnameRecords {
		wg.Add(1)
		go func(record cloudflare.DNSRecord) {
			defer wg.Done()
			if cfg.Verbose {
				log.Printf("Resolving CNAME: %s -> %s", record.Name, record.Content)
			}
			ips, err := net.LookupIP(record.Content)
			if err != nil {
				log.Printf("Error resolving CNAME %s (%s): %v", record.Name, record.Content, err)
				mu.Lock()
				failedEntries[record.Name] = true
				mu.Unlock()
				return
			}
			if len(ips) > 0 {
				var chosenIP string
				for _, ip := range ips {
					if ip.To4() != nil {
						chosenIP = ip.String()
						break
					}
				}
				if chosenIP == "" {
					chosenIP = ips[0].String()
				}
				mu.Lock()
				hostsEntries[record.Name] = chosenIP
				mu.Unlock()
				if cfg.Verbose {
					log.Printf("[CNAME Resolved] %s -> %s (%s)", record.Name, chosenIP, record.Content)
				}
			} else {
				log.Printf("Could not resolve CNAME %s (%s) to any IP address", record.Name, record.Content)
			}
		}(r)
	}
	wg.Wait()

	if len(hostsEntries) > 0 {
		if err := updateHostsFile(hostsEntries, failedEntries, cfg); err != nil {
			log.Printf("Error updating hosts file: %v", err)
		}
	} else if cfg.Verbose {
		log.Printf("No A or resolvable CNAME records found to update hosts file.")
	}

	if cfg.SaveSrvDir != "" && len(srvRecords) > 0 {
		if err := saveSRVRecords(srvRecords, recordIps, cfg); err != nil {
			log.Printf("Error saving SRV records: %v", err)
		}
	} else if cfg.SaveSrvDir != "" && cfg.Verbose {
		log.Printf("No SRV records found to save or 'save-srv-dir' not provided.")
	}

	if cfg.DryRun {
		fmt.Printf("--- DRY RUN COMPLETED ---\n")
	} else {
		fmt.Printf("Program completed successfully.\n")
	}

	return nil
}

func _fetchDNSRecords(api *cloudflare.API, zone string) ([]cloudflare.DNSRecord, error) {
	rc := &cloudflare.ResourceContainer{Level: cloudflare.ZoneRouteLevel, Identifier: zone}
	filter := cloudflare.ListDNSRecordsParams{
		Type: "A",
	}
	aRecords, _, err := api.ListDNSRecords(context.Background(), rc, filter)
	if err != nil && !strings.Contains(err.Error(), "Not found") {
		log.Printf("Warning: fetching A records: %v\n", err)
	}

	filter.Type = "CNAME"
	cnameRecords, _, err := api.ListDNSRecords(context.Background(), rc, filter)
	if err != nil && !strings.Contains(err.Error(), "Not found") {
		log.Printf("Warning: fetching CNAME records: %v\n", err)
	}

	filter.Type = "SRV"
	srvRecords, _, err := api.ListDNSRecords(context.Background(), rc, filter)
	if err != nil && !strings.Contains(err.Error(), "Not found") {
		log.Printf("Warning: fetching SRV records: %v\n", err)
	}

	allRecords := append(aRecords, cnameRecords...)
	allRecords = append(allRecords, srvRecords...)
	return allRecords, nil
}

func getSystemHostsFilePath() (string, error) {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts"), nil
	case "linux", "darwin":
		return "/etc/hosts", nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func updateHostsFile(entries map[string]string, failedEntries map[string]bool, cfg Cf2HostsConfig) error {
	if cfg.Verbose {
		log.Printf("Updating hosts file: %s", cfg.HostsFilePath)
	}

	file, err := os.OpenFile(cfg.HostsFilePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("could not open hosts file %q (run with sudo?): %w", cfg.HostsFilePath, err)
	}
	defer file.Close()

	var newLines []string
	scanner := bufio.NewScanner(file)
	inManagedBlock := false

	delimiter := HOSTS_FILE_DELIMITER_PREFIX
	if cfg.Identifier != "" {
		delimiter += "_" + strings.ToUpper(cfg.Identifier)
	}
	hostsFileStartDelimiter := delimiter + "_START"
	hostsFileEndDelimiter := delimiter + "_END"

	var existingRecordLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == hostsFileStartDelimiter {
			inManagedBlock = true
			continue
		}
		if strings.TrimSpace(line) == hostsFileEndDelimiter {
			inManagedBlock = false
			continue
		}
		if !inManagedBlock {
			newLines = append(newLines, line)
		} else {
			existingRecordLines = append(existingRecordLines, line)
			ip, domain, _ := strings.Cut(strings.TrimSpace(line), " ")
			if ip != "" && domain != "" && failedEntries[domain] {
				entries[domain] = ip
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading hosts file: %w", err)
	}

	domains := []string{}
	for d := range entries {
		domains = append(domains, d)
	}
	slices.Sort(domains)

	var newRecordLines []string
	for _, domain := range domains {
		ip := entries[domain]
		newRecordLines = append(newRecordLines, fmt.Sprintf("%s %s", ip, domain))
	}
	if slices.Equal(existingRecordLines, newRecordLines) {
		log.Printf("Same contents as existing hosts file, no need to update")
		return nil
	}

	if cfg.DryRun {
		fmt.Printf("[Dry Run] Would update hosts file with the following entries:\n---\n")
		for _, line := range newRecordLines {
			fmt.Printf("%s\n", line)
		}
		fmt.Printf("---\n")
		return nil
	}

	newLines = append(newLines, hostsFileStartDelimiter)
	newLines = append(newLines, newRecordLines...)
	newLines = append(newLines, hostsFileEndDelimiter)

	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("could not truncate hosts file: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("could not seek to beginning of hosts file: %w", err)
	}

	writer := bufio.NewWriter(file)
	for _, line := range newLines {
		if _, err := fmt.Fprintln(writer, line); err != nil {
			return fmt.Errorf("error writing to hosts file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("error flushing writer for hosts file: %w", err)
	}

	log.Printf("Hosts file %q updated successfully.", cfg.HostsFilePath)
	return nil
}

func resolveSRVTarget(targetHostname string, recordIps map[string]string, cfg Cf2HostsConfig) ([]string, error) {
	var ips []string
	if cfg.Verbose {
		log.Printf("Resolving SRV target: %s\n", targetHostname)
	}
	if ip := getDomainIp(recordIps, targetHostname); ip != "" {
		ips = append(ips, ip)
		if cfg.Verbose {
			log.Printf("Resolved SRV target %s to %s (via same zone records)", targetHostname, ip)
		}
	} else if resolvedIPs, err := net.LookupIP(targetHostname); err == nil {
		for _, ip := range resolvedIPs {
			ips = append(ips, ip.String())
			if cfg.Verbose {
				log.Printf("Resolved SRV target %s to %s (via net.LookupIP)", targetHostname, ip.String())
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for SRV target hostname %q", targetHostname)
	}
	return ips, nil
}

func saveSRVRecords(records []cloudflare.DNSRecord, recordIps map[string]string, cfg Cf2HostsConfig) error {
	if cfg.SaveSrvDir == "" {
		return nil
	}

	if cfg.Verbose {
		log.Printf("Processing %d SRV records for directory: %s", len(records), cfg.SaveSrvDir)
	}

	if _, err := os.Stat(cfg.SaveSrvDir); os.IsNotExist(err) {
		return fmt.Errorf("SRV save directory %q dones not exist: %w", cfg.SaveSrvDir, err)
	}

	srvDataByService := make(map[string][]string)
	srvRegex := regexp.MustCompile(`^_([^\.]+)\._([^\.]+)\.(.*)`)

	for _, r := range records {
		if r.Type != "SRV" || r.Data == nil {
			continue
		}
		data, ok := r.Data.(map[string]any)
		if !ok {
			log.Printf("Invalid srv data format")
			continue
		}

		targetHost := utilToString(data["target"])
		port := utilToInt(data["port"])
		if targetHost == "" || port == 0 {
			log.Printf("Invalid srv target %q or port %d", targetHost, port)
			continue
		}

		matches := srvRegex.FindStringSubmatch(r.Name)
		if len(matches) < 2 {
			log.Printf("Could not parse service name from SRV record: %s", r.Name)
			continue
		}
		serviceName := matches[1]
		proto := matches[2]

		if cfg.Verbose {
			log.Printf("[SRV Record] %s -> Target: %s, Proto: %s, Port: %d", r.Name, targetHost, proto, port)
		}

		targetIPs, err := resolveSRVTarget(targetHost, recordIps, cfg)
		if err != nil {
			log.Printf("Error resolving SRV target %q for service %q: %v", targetHost, serviceName, err)
			continue
		}

		for _, ip := range targetIPs {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil && parsedIP.To4() != nil {
				srvDataByService[serviceName] = append(srvDataByService[serviceName], fmt.Sprintf("%s,%s:%d", ip, proto, port))
			} else if parsedIP != nil && parsedIP.To16() != nil && parsedIP.To4() == nil {
				if cfg.Verbose {
					log.Printf("SRV target %s resolved to IPv6 %s, skipping for hash:ip,port ipset type.", targetHost, ip)
				}
			} else {
				if cfg.Verbose {
					log.Printf("SRV target %s resolved to %q which is not a valid IP, skipping.", targetHost, ip)
				}
			}
		}
	}

	for service, entries := range srvDataByService {
		if len(entries) == 0 {
			continue
		}

		fileName := filepath.Join(cfg.SaveSrvDir, service+".ipset")
		ipsetFileContent := ""
		for _, entry := range entries {
			ipsetFileContent += fmt.Sprintf("%s\n", entry)
		}

		if existingContents, err := os.ReadFile(fileName); err == nil {
			if string(existingContents) == ipsetFileContent {
				log.Printf("Same contents as existing ipset file %q, no need to update", fileName)
				continue
			}
		}

		if cfg.DryRun {
			fmt.Printf("[Dry Run] Would write to SRV ipset file %q:\n---\n%s\n---\n", fileName, strings.TrimSpace(ipsetFileContent))
			continue
		}

		err := os.WriteFile(fileName, []byte(ipsetFileContent), 0644)
		if err != nil {
			log.Printf("Error writing SRV ipset file %q: %v", fileName, err)
		} else {
			log.Printf("SRV ipset data saved to: %s\n", fileName)
		}
	}
	return nil
}

func resolveIps(records []cloudflare.DNSRecord) map[string]string {
	result := make(map[string]string)
	cnameTargets := make(map[string]string)

	for _, record := range records {
		switch record.Type {
		case "A", "AAAA":
			result[record.Name] = record.Content
		case "CNAME":
			cnameTargets[record.Name] = record.Content
		}
	}

outer:
	for name, target := range cnameTargets {
		for range 3 {
			if ip := getDomainIp(result, target); ip != "" {
				result[name] = ip
				continue outer
			}
			if nextTarget, ok := cnameTargets[target]; ok {
				target = nextTarget
			} else {
				continue outer
			}
		}
	}
	return result
}

func getDomainIp(records map[string]string, domain string) string {
	domain = strings.ToLower(domain)
	domain = strings.TrimSuffix(domain, ".")
	if ip, ok := records[domain]; ok {
		return ip
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		zone := strings.Join(parts[i:], ".")
		wildcardDomain := "*." + zone
		if ip, ok := records[wildcardDomain]; ok {
			return ip
		}
		if _, ok := records[zone]; ok {
			break
		}
	}
	return ""
}
