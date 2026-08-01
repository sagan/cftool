package cmd

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

type DNSRow struct {
	Name        string
	Type        string
	Content     string
	ProxyStatus string
	TTL         string
	Comment     string
	ID          string
}

func fetchAllDNSRecords(ctx context.Context, api *cloudflare.API, zoneID string) ([]cloudflare.DNSRecord, error) {
	rc := cloudflare.ZoneIdentifier(zoneID)
	params := cloudflare.ListDNSRecordsParams{}
	var allRecords []cloudflare.DNSRecord

	for {
		recs, resultInfo, err := api.ListDNSRecords(ctx, rc, params)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch Cloudflare DNS records: %w", err)
		}
		allRecords = append(allRecords, recs...)
		if resultInfo == nil || !resultInfo.HasMorePages() {
			break
		}
		params.ResultInfo = resultInfo.Next()
	}
	return allRecords, nil
}

func filterRecordsByDomain(records []cloudflare.DNSRecord, domainFlag string) []cloudflare.DNSRecord {
	if strings.TrimSpace(domainFlag) == "" {
		return records
	}

	domainList := strings.Split(domainFlag, ",")
	var targetDomains []string
	for _, d := range domainList {
		d = strings.TrimSpace(d)
		if d != "" {
			targetDomains = append(targetDomains, d)
		}
	}

	if len(targetDomains) == 0 {
		return records
	}

	var filtered []cloudflare.DNSRecord
	for _, r := range records {
		rName := strings.ToLower(strings.TrimSuffix(r.Name, "."))

		matches := false
		for _, rawTarget := range targetDomains {
			isExactOnly := strings.HasPrefix(rawTarget, "^")
			target := strings.ToLower(strings.TrimPrefix(rawTarget, "^"))
			target = strings.TrimSuffix(target, ".")

			if isExactOnly {
				if rName == target {
					matches = true
					break
				}
			} else {
				if rName == target || strings.HasSuffix(rName, "."+target) {
					matches = true
					break
				}
			}
		}

		if matches {
			filtered = append(filtered, r)
		}
	}

	return filtered
}

func formatCSV(records []cloudflare.DNSRecord, includeID bool, align bool) string {
	headers := []string{"Name", "Type", "Content", "Proxy status", "TTL", "Comment"}
	if includeID {
		headers = append(headers, "ID")
	}

	table := make([][]string, 0, len(records)+1)
	table = append(table, headers)

	for _, r := range records {
		proxyStr := "dns_only"
		if r.Proxied != nil && *r.Proxied {
			proxyStr = "proxied"
		}

		ttlStr := "auto"
		if r.TTL > 1 {
			ttlStr = strconv.Itoa(r.TTL)
		}

		row := []string{
			r.Name,
			r.Type,
			r.Content,
			proxyStr,
			ttlStr,
			r.Comment,
		}
		if includeID {
			row = append(row, r.ID)
		}
		table = append(table, row)
	}

	var sb strings.Builder
	if align {
		colWidths := make([]int, len(headers))
		for _, row := range table {
			for i, cell := range row {
				if len(cell) > colWidths[i] {
					colWidths[i] = len(cell)
				}
			}
		}

		for _, row := range table {
			for i, cell := range row {
				paddedCell := cell
				if i < len(row)-1 {
					paddedCell = fmt.Sprintf("%-*s", colWidths[i], cell)
				}
				sb.WriteString(paddedCell)
				if i < len(row)-1 {
					sb.WriteString(" , ")
				}
			}
			sb.WriteString("\n")
		}
	} else {
		for _, row := range table {
			for i, cell := range row {
				sb.WriteString(cell)
				if i < len(row)-1 {
					sb.WriteString(", ")
				}
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func parseCSVRecords(content string) ([]DNSRow, error) {
	r := csv.NewReader(strings.NewReader(content))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	r.Comment = '#'

	lines, err := r.ReadAll()
	if err != nil {
		return parseCSVRecordsFallback(content)
	}

	var rows []DNSRow
	headerParsed := false

	for _, fields := range lines {
		if len(fields) == 0 {
			continue
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		if !headerParsed {
			if len(fields) > 0 && strings.EqualFold(fields[0], "Name") {
				headerParsed = true
				continue
			}
		}

		if len(fields) < 3 {
			continue
		}

		row := DNSRow{
			Name:    fields[0],
			Type:    strings.ToUpper(fields[1]),
			Content: fields[2],
		}
		if len(fields) > 3 {
			row.ProxyStatus = fields[3]
		}
		if len(fields) > 4 {
			row.TTL = fields[4]
		}
		if len(fields) > 5 {
			row.Comment = fields[5]
		}
		if len(fields) > 6 {
			row.ID = fields[6]
		}

		if row.Name != "" {
			rows = append(rows, row)
		}
	}

	return rows, nil
}

func parseCSVRecordsFallback(content string) ([]DNSRow, error) {
	lines := strings.Split(content, "\n")
	var rows []DNSRow
	headerParsed := false

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}

		if !headerParsed {
			if len(fields) > 0 && strings.EqualFold(fields[0], "Name") {
				headerParsed = true
				continue
			}
		}

		if len(fields) < 3 {
			continue
		}

		row := DNSRow{
			Name:    fields[0],
			Type:    strings.ToUpper(fields[1]),
			Content: fields[2],
		}
		if len(fields) > 3 {
			row.ProxyStatus = fields[3]
		}
		if len(fields) > 4 {
			row.TTL = fields[4]
		}
		if len(fields) > 5 {
			row.Comment = fields[5]
		}
		if len(fields) > 6 {
			row.ID = fields[6]
		}

		if row.Name != "" {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func parseProxyStatus(status string) bool {
	s := strings.ToLower(strings.TrimSpace(status))
	switch s {
	case "proxied", "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

func parseTTL(ttlStr string) int {
	s := strings.ToLower(strings.TrimSpace(ttlStr))
	if s == "" || s == "auto" {
		return 1
	}
	val, err := strconv.Atoi(s)
	if err != nil || val <= 0 {
		return 1
	}
	return val
}

func getEditor(customEditor string) (string, []string, error) {
	if strings.TrimSpace(customEditor) != "" {
		fields := strings.Fields(customEditor)
		return fields[0], fields[1:], nil
	}

	for _, envVar := range []string{"VISUAL", "EDITOR"} {
		if envVal := strings.TrimSpace(os.Getenv(envVar)); envVal != "" {
			fields := strings.Fields(envVal)
			return fields[0], fields[1:], nil
		}
	}

	var candidateEditors []string
	if runtime.GOOS == "windows" {
		candidateEditors = []string{"code.cmd", "code", "notepad++.exe", "notepad++", "notepad.exe", "notepad"}
	} else {
		candidateEditors = []string{"vim", "vi", "code", "nano", "emacs", "micro", "gedit"}
	}

	for _, ed := range candidateEditors {
		if path, err := exec.LookPath(ed); err == nil {
			args := []string{}
			if strings.HasPrefix(filepath.Base(path), "code") {
				args = append(args, "--wait")
			}
			return path, args, nil
		}
	}

	if runtime.GOOS == "windows" {
		return "notepad.exe", nil, nil
	}
	return "vi", nil, nil
}
