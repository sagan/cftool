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

func formatRecordContent(r cloudflare.DNSRecord) string {
	content := r.Content
	if strings.EqualFold(r.Type, "SRV") {
		if content == "" && r.Data != nil {
			if dataMap, ok := r.Data.(map[string]interface{}); ok {
				weight, _ := dataMap["weight"]
				port, _ := dataMap["port"]
				target, _ := dataMap["target"]
				priority, hasPriority := dataMap["priority"]
				if hasPriority && fmt.Sprintf("%v", priority) != "0" {
					content = fmt.Sprintf("%v %v %v %v", priority, weight, port, target)
				} else {
					content = fmt.Sprintf("%v %v %v", weight, port, target)
				}
			}
		} else if r.Priority != nil && *r.Priority > 0 {
			fields := strings.Fields(content)
			if len(fields) == 3 {
				content = fmt.Sprintf("%d %s", *r.Priority, content)
			}
		}
	}
	return content
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
			formatRecordContent(r),
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

func parseSRVContent(content string, defaultPriority *uint16) (priority, weight, port uint16, target string, err error) {
	fields := strings.Fields(content)
	if len(fields) == 3 {
		p := uint16(0)
		if defaultPriority != nil {
			p = *defaultPriority
		}
		w, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("invalid SRV weight %q: %w", fields[0], err)
		}
		pt, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("invalid SRV port %q: %w", fields[1], err)
		}
		return p, uint16(w), uint16(pt), fields[2], nil
	} else if len(fields) == 4 {
		p, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("invalid SRV priority %q: %w", fields[0], err)
		}
		w, err := strconv.ParseUint(fields[1], 10, 16)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("invalid SRV weight %q: %w", fields[1], err)
		}
		pt, err := strconv.ParseUint(fields[2], 10, 16)
		if err != nil {
			return 0, 0, 0, "", fmt.Errorf("invalid SRV port %q: %w", fields[2], err)
		}
		return uint16(p), uint16(w), uint16(pt), fields[3], nil
	}
	return 0, 0, 0, "", fmt.Errorf("invalid SRV content %q: expected 3 or 4 fields (<weight> <port> <target> or <priority> <weight> <port> <target>)", content)
}

func parseMXContent(content string, defaultPriority *uint16) (priority uint16, target string, err error) {
	fields := strings.Fields(content)
	if len(fields) == 2 {
		p, err := strconv.ParseUint(fields[0], 10, 16)
		if err == nil {
			return uint16(p), fields[1], nil
		}
	} else if len(fields) == 1 {
		p := uint16(10)
		if defaultPriority != nil {
			p = *defaultPriority
		}
		return p, fields[0], nil
	}
	return 0, content, fmt.Errorf("invalid MX content %q", content)
}

func buildUpdateDNSRecordParams(er DNSRow, origRec *cloudflare.DNSRecord, proxied bool, ttl int) (cloudflare.UpdateDNSRecordParams, error) {
	params := cloudflare.UpdateDNSRecordParams{
		ID:      er.ID,
		Type:    er.Type,
		Name:    er.Name,
		Content: er.Content,
		TTL:     ttl,
		Proxied: cloudflare.BoolPtr(proxied),
		Comment: cloudflare.StringPtr(er.Comment),
	}

	var defaultPriority *uint16
	if origRec != nil {
		defaultPriority = origRec.Priority
	}

	if strings.EqualFold(er.Type, "SRV") {
		priority, weight, port, target, err := parseSRVContent(er.Content, defaultPriority)
		if err != nil {
			return params, err
		}
		params.Priority = &priority
		params.Data = map[string]interface{}{
			"priority": priority,
			"weight":   weight,
			"port":     port,
			"target":   target,
		}
	} else if strings.EqualFold(er.Type, "MX") {
		priority, target, err := parseMXContent(er.Content, defaultPriority)
		if err == nil {
			params.Priority = &priority
			params.Content = target
		}
	}

	return params, nil
}

func buildCreateDNSRecordParams(er DNSRow, proxied bool, ttl int) (cloudflare.CreateDNSRecordParams, error) {
	params := cloudflare.CreateDNSRecordParams{
		Type:    er.Type,
		Name:    er.Name,
		Content: er.Content,
		TTL:     ttl,
		Proxied: cloudflare.BoolPtr(proxied),
		Comment: er.Comment,
	}

	if strings.EqualFold(er.Type, "SRV") {
		priority, weight, port, target, err := parseSRVContent(er.Content, nil)
		if err != nil {
			return params, err
		}
		params.Priority = &priority
		params.Data = map[string]interface{}{
			"priority": priority,
			"weight":   weight,
			"port":     port,
			"target":   target,
		}
	} else if strings.EqualFold(er.Type, "MX") {
		priority, target, err := parseMXContent(er.Content, nil)
		if err == nil {
			params.Priority = &priority
			params.Content = target
		}
	}

	return params, nil
}

func getSRVFields(r cloudflare.DNSRecord) (priority, weight, port uint16, target string, ok bool) {
	if r.Data != nil {
		if dataMap, okMap := r.Data.(map[string]interface{}); okMap {
			var p, w, pt uint64
			if v, exists := dataMap["priority"]; exists {
				p, _ = strconv.ParseUint(fmt.Sprintf("%v", v), 10, 16)
			} else if r.Priority != nil {
				p = uint64(*r.Priority)
			}
			if v, exists := dataMap["weight"]; exists {
				w, _ = strconv.ParseUint(fmt.Sprintf("%v", v), 10, 16)
			}
			if v, exists := dataMap["port"]; exists {
				pt, _ = strconv.ParseUint(fmt.Sprintf("%v", v), 10, 16)
			}
			tgt, _ := dataMap["target"].(string)
			if tgt != "" || pt != 0 || w != 0 {
				return uint16(p), uint16(w), uint16(pt), tgt, true
			}
		}
	}
	p, w, pt, tgt, err := parseSRVContent(r.Content, r.Priority)
	if err == nil {
		return p, w, pt, tgt, true
	}
	return 0, 0, 0, "", false
}

func isRecordEqual(er DNSRow, origRec cloudflare.DNSRecord, proxied bool, ttl int) bool {
	if !strings.EqualFold(er.Name, origRec.Name) {
		return false
	}
	if !strings.EqualFold(er.Type, origRec.Type) {
		return false
	}
	origProxied := origRec.Proxied != nil && *origRec.Proxied
	if proxied != origProxied {
		return false
	}
	if ttl != origRec.TTL {
		return false
	}
	if er.Comment != origRec.Comment {
		return false
	}

	if strings.EqualFold(er.Type, "SRV") {
		erP, erW, erPt, erTgt, err := parseSRVContent(er.Content, origRec.Priority)
		if err != nil {
			return false
		}
		origP, origW, origPt, origTgt, ok := getSRVFields(origRec)
		if !ok {
			return false
		}
		return erP == origP && erW == origW && erPt == origPt && strings.EqualFold(strings.TrimSuffix(erTgt, "."), strings.TrimSuffix(origTgt, "."))
	}

	if strings.EqualFold(er.Type, "MX") {
		erP, erTgt, err := parseMXContent(er.Content, origRec.Priority)
		if err != nil {
			return false
		}
		origP := uint16(10)
		if origRec.Priority != nil {
			origP = *origRec.Priority
		}
		_, origTgt, _ := parseMXContent(origRec.Content, origRec.Priority)
		return erP == origP && strings.EqualFold(strings.TrimSuffix(erTgt, "."), strings.TrimSuffix(origTgt, "."))
	}

	return er.Content == origRec.Content
}
