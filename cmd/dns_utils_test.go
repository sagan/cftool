package cmd

import (
	"reflect"
	"strings"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

func TestFilterRecordsByDomain(t *testing.T) {
	records := []cloudflare.DNSRecord{
		{Name: "example.com", Type: "A", Content: "1.1.1.1"},
		{Name: "s.example.com", Type: "A", Content: "1.2.3.4"},
		{Name: "sub.s.example.com", Type: "CNAME", Content: "s.example.com"},
		{Name: "other.com", Type: "A", Content: "2.2.2.2"},
	}

	tests := []struct {
		name       string
		domainFlag string
		wantNames  []string
	}{
		{
			name:       "Empty domain flag returns all",
			domainFlag: "",
			wantNames:  []string{"example.com", "s.example.com", "sub.s.example.com", "other.com"},
		},
		{
			name:       "Subdomain filter s.example.com",
			domainFlag: "s.example.com",
			wantNames:  []string{"s.example.com", "sub.s.example.com"},
		},
		{
			name:       "Exact match filter ^s.example.com",
			domainFlag: "^s.example.com",
			wantNames:  []string{"s.example.com"},
		},
		{
			name:       "Multiple domains filter",
			domainFlag: "s.example.com, other.com",
			wantNames:  []string{"s.example.com", "sub.s.example.com", "other.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterRecordsByDomain(records, tt.domainFlag)
			var gotNames []string
			for _, r := range got {
				gotNames = append(gotNames, r.Name)
			}
			if !reflect.DeepEqual(gotNames, tt.wantNames) {
				t.Errorf("filterRecordsByDomain() = %v, want %v", gotNames, tt.wantNames)
			}
		})
	}
}

func TestFormatCSVAndParse(t *testing.T) {
	proxied := true
	dnsOnly := false

	records := []cloudflare.DNSRecord{
		{
			ID:      "rec1",
			Name:    "example.com",
			Type:    "A",
			Content: "1.2.3.4",
			Proxied: &proxied,
			TTL:     1,
			Comment: "Main domain",
		},
		{
			ID:      "rec2",
			Name:    "sub.example.com",
			Type:    "CNAME",
			Content: "example.com",
			Proxied: &dnsOnly,
			TTL:     300,
			Comment: "",
		},
	}

	// Test format without ID (unaligned by default)
	csvNoID := formatCSV(records, false, false)
	if !strings.Contains(csvNoID, "Name, Type, Content") || strings.Contains(csvNoID, "ID") {
		t.Errorf("formatCSV(false, false) header unexpected: %s", csvNoID)
	}

	rowsNoID, err := parseCSVRecords(csvNoID)
	if err != nil {
		t.Fatalf("parseCSVRecords(csvNoID) error: %v", err)
	}
	if len(rowsNoID) != 2 || rowsNoID[0].Name != "example.com" || rowsNoID[0].Content != "1.2.3.4" {
		t.Errorf("parseCSVRecords(csvNoID) failed, got %+v", rowsNoID)
	}

	// Test format with ID and align=true
	csvWithIDAligned := formatCSV(records, true, true)
	if !strings.Contains(csvWithIDAligned, "ID") {
		t.Errorf("formatCSV(true, true) header should contain ID: %s", csvWithIDAligned)
	}
	if !strings.Contains(csvWithIDAligned, "rec1") {
		t.Errorf("formatCSV(true, true) should contain rec1: %s", csvWithIDAligned)
	}

	// Test format with ID and align=false
	csvWithID := formatCSV(records, true, false)
	if !strings.Contains(csvWithID, "ID") {
		t.Errorf("formatCSV(true, false) header should contain ID: %s", csvWithID)
	}

	// Test parsing
	rows, err := parseCSVRecords(csvWithID)
	if err != nil {
		t.Fatalf("parseCSVRecords error: %v", err)
	}

	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}

	if rows[0].Name != "example.com" || rows[0].Type != "A" || rows[0].Content != "1.2.3.4" || rows[0].ProxyStatus != "proxied" || rows[0].TTL != "auto" || rows[0].Comment != "Main domain" || rows[0].ID != "rec1" {
		t.Errorf("row 0 mismatch: %+v", rows[0])
	}

	if rows[1].Name != "sub.example.com" || rows[1].Type != "CNAME" || rows[1].ProxyStatus != "dns_only" || rows[1].TTL != "300" || rows[1].ID != "rec2" {
		t.Errorf("row 1 mismatch: %+v", rows[1])
	}
}

func TestParseProxyStatusAndTTL(t *testing.T) {
	if !parseProxyStatus("proxied") || !parseProxyStatus("TRUE") || !parseProxyStatus("1") {
		t.Errorf("parseProxyStatus failed to recognize true values")
	}
	if parseProxyStatus("dns_only") || parseProxyStatus("false") || parseProxyStatus("") {
		t.Errorf("parseProxyStatus failed to recognize false values")
	}

	if parseTTL("auto") != 1 || parseTTL("") != 1 || parseTTL("1") != 1 {
		t.Errorf("parseTTL failed for auto values")
	}
	if parseTTL("3600") != 3600 {
		t.Errorf("parseTTL failed for 3600")
	}
}

func TestParseSRVContent(t *testing.T) {
	defaultP := uint16(5)

	// 3 fields with default priority
	p, w, pt, target, err := parseSRVContent("100 6534 nbcm.s.sagan.me", &defaultP)
	if err != nil {
		t.Fatalf("parseSRVContent failed: %v", err)
	}
	if p != 5 || w != 100 || pt != 6534 || target != "nbcm.s.sagan.me" {
		t.Errorf("got (%d, %d, %d, %s), want (5, 100, 6534, nbcm.s.sagan.me)", p, w, pt, target)
	}

	// 3 fields with nil default priority (defaults to 0)
	p, w, pt, target, err = parseSRVContent("100 6534 nbcm.s.sagan.me", nil)
	if err != nil {
		t.Fatalf("parseSRVContent failed: %v", err)
	}
	if p != 0 || w != 100 || pt != 6534 || target != "nbcm.s.sagan.me" {
		t.Errorf("got (%d, %d, %d, %s), want (0, 100, 6534, nbcm.s.sagan.me)", p, w, pt, target)
	}

	// 4 fields (explicit priority)
	p, w, pt, target, err = parseSRVContent("10 100 6534 nbcm.s.sagan.me", &defaultP)
	if err != nil {
		t.Fatalf("parseSRVContent failed: %v", err)
	}
	if p != 10 || w != 100 || pt != 6534 || target != "nbcm.s.sagan.me" {
		t.Errorf("got (%d, %d, %d, %s), want (10, 100, 6534, nbcm.s.sagan.me)", p, w, pt, target)
	}

	// Invalid fields count
	if _, _, _, _, err := parseSRVContent("6534 nbcm.s.sagan.me", nil); err == nil {
		t.Errorf("expected error for 2 fields in SRV content")
	}

	// Invalid port
	if _, _, _, _, err := parseSRVContent("100 invalid_port nbcm.s.sagan.me", nil); err == nil {
		t.Errorf("expected error for non-numeric port in SRV content")
	}
}

func TestParseMXContent(t *testing.T) {
	defaultP := uint16(20)

	// 2 fields (priority + mail host)
	p, target, err := parseMXContent("10 mail.example.com", &defaultP)
	if err != nil {
		t.Fatalf("parseMXContent failed: %v", err)
	}
	if p != 10 || target != "mail.example.com" {
		t.Errorf("got (%d, %s), want (10, mail.example.com)", p, target)
	}

	// 1 field with default priority
	p, target, err = parseMXContent("mail.example.com", &defaultP)
	if err != nil {
		t.Fatalf("parseMXContent failed: %v", err)
	}
	if p != 20 || target != "mail.example.com" {
		t.Errorf("got (%d, %s), want (20, mail.example.com)", p, target)
	}

	// 1 field with nil default priority (defaults to 10)
	p, target, err = parseMXContent("mail.example.com", nil)
	if err != nil {
		t.Fatalf("parseMXContent failed: %v", err)
	}
	if p != 10 || target != "mail.example.com" {
		t.Errorf("got (%d, %s), want (10, mail.example.com)", p, target)
	}
}

func TestBuildUpdateAndCreateDNSRecordParams(t *testing.T) {
	srvRow := DNSRow{
		ID:          "srv-id-1",
		Name:        "_nbcm-pt._tcp.s.sagan.me",
		Type:        "SRV",
		Content:     "100 6535 new.s.sagan.me",
		ProxyStatus: "dns_only",
		TTL:         "auto",
		Comment:     "test srv comment",
	}

	origRec := cloudflare.DNSRecord{
		ID:      "srv-id-1",
		Name:    "_nbcm-pt._tcp.s.sagan.me",
		Type:    "SRV",
		Content: "100 6534 nbcm.s.sagan.me",
	}

	// Update SRV params
	updateParams, err := buildUpdateDNSRecordParams(srvRow, &origRec, false, 1)
	if err != nil {
		t.Fatalf("buildUpdateDNSRecordParams SRV error: %v", err)
	}
	if updateParams.Data == nil {
		t.Fatalf("updateParams.Data should not be nil for SRV")
	}
	dataMap, ok := updateParams.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("updateParams.Data is not a map: %T", updateParams.Data)
	}
	if dataMap["port"] != uint16(6535) || dataMap["target"] != "new.s.sagan.me" || dataMap["weight"] != uint16(100) || dataMap["priority"] != uint16(0) {
		t.Errorf("unexpected SRV data map: %+v", dataMap)
	}
	if updateParams.Priority == nil || *updateParams.Priority != 0 {
		t.Errorf("unexpected SRV priority: %v", updateParams.Priority)
	}

	// Create SRV params
	createParams, err := buildCreateDNSRecordParams(srvRow, false, 1)
	if err != nil {
		t.Fatalf("buildCreateDNSRecordParams SRV error: %v", err)
	}
	if createParams.Data == nil {
		t.Fatalf("createParams.Data should not be nil for SRV")
	}
	createDataMap, ok := createParams.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("createParams.Data is not a map: %T", createParams.Data)
	}
	if createDataMap["port"] != uint16(6535) || createDataMap["target"] != "new.s.sagan.me" {
		t.Errorf("unexpected SRV create data map: %+v", createDataMap)
	}

	// Normal A record update params
	aRow := DNSRow{
		ID:          "a-id-1",
		Name:        "example.com",
		Type:        "A",
		Content:     "1.1.1.1",
		ProxyStatus: "proxied",
		TTL:         "auto",
	}
	aOrig := cloudflare.DNSRecord{
		ID:      "a-id-1",
		Name:    "example.com",
		Type:    "A",
		Content: "1.2.3.4",
	}
	aParams, err := buildUpdateDNSRecordParams(aRow, &aOrig, true, 1)
	if err != nil {
		t.Fatalf("buildUpdateDNSRecordParams A error: %v", err)
	}
	if aParams.Data != nil || aParams.Priority != nil || aParams.Content != "1.1.1.1" {
		t.Errorf("unexpected A update params: %+v", aParams)
	}
}

func TestFormatRecordContentSRV(t *testing.T) {
	priority := uint16(10)
	srvRec := cloudflare.DNSRecord{
		Type:     "SRV",
		Content:  "100 6534 nbcm.s.sagan.me",
		Priority: &priority,
	}

	formatted := formatRecordContent(srvRec)
	if formatted != "10 100 6534 nbcm.s.sagan.me" {
		t.Errorf("formatRecordContent with priority=10 got %q, want %q", formatted, "10 100 6534 nbcm.s.sagan.me")
	}

	// Priority 0 should keep 3 fields
	p0 := uint16(0)
	srvRec0 := cloudflare.DNSRecord{
		Type:     "SRV",
		Content:  "100 6534 nbcm.s.sagan.me",
		Priority: &p0,
	}
	formatted0 := formatRecordContent(srvRec0)
	if formatted0 != "100 6534 nbcm.s.sagan.me" {
		t.Errorf("formatRecordContent with priority=0 got %q, want %q", formatted0, "100 6534 nbcm.s.sagan.me")
	}

	// Empty content with Data map
	srvRecData := cloudflare.DNSRecord{
		Type:    "SRV",
		Content: "",
		Data: map[string]interface{}{
			"priority": 0,
			"weight":   100,
			"port":     6534,
			"target":   "nbcm.s.sagan.me",
		},
	}
	formattedData := formatRecordContent(srvRecData)
	if formattedData != "100 6534 nbcm.s.sagan.me" {
		t.Errorf("formatRecordContent with Data map got %q, want %q", formattedData, "100 6534 nbcm.s.sagan.me")
	}
}

func TestIsRecordEqual(t *testing.T) {
	priority0 := uint16(0)
	origSRV := cloudflare.DNSRecord{
		ID:       "srv1",
		Name:     "_nbcm-pt._tcp.s.sagan.me",
		Type:     "SRV",
		Content:  "100 6534 nbcm.s.sagan.me",
		Priority: &priority0,
		TTL:      1,
		Comment:  "test comment",
	}

	// 1. Same 3 fields -> equal
	rowSame := DNSRow{
		Name:        "_nbcm-pt._tcp.s.sagan.me",
		Type:        "SRV",
		Content:     "100 6534 nbcm.s.sagan.me",
		ProxyStatus: "dns_only",
		TTL:         "auto",
		Comment:     "test comment",
	}
	if !isRecordEqual(rowSame, origSRV, false, 1) {
		t.Errorf("expected isRecordEqual to be true for identical SRV record")
	}

	// 2. Same with 4 fields ("0 100 6534 nbcm.s.sagan.me") -> equal
	rowSame4 := DNSRow{
		Name:        "_nbcm-pt._tcp.s.sagan.me",
		Type:        "SRV",
		Content:     "0 100 6534 nbcm.s.sagan.me",
		ProxyStatus: "dns_only",
		TTL:         "auto",
		Comment:     "test comment",
	}
	if !isRecordEqual(rowSame4, origSRV, false, 1) {
		t.Errorf("expected isRecordEqual to be true for 4-field SRV record with priority 0")
	}

	// 3. Changed port -> not equal
	rowDiffPort := DNSRow{
		Name:        "_nbcm-pt._tcp.s.sagan.me",
		Type:        "SRV",
		Content:     "100 6535 nbcm.s.sagan.me",
		ProxyStatus: "dns_only",
		TTL:         "auto",
		Comment:     "test comment",
	}
	if isRecordEqual(rowDiffPort, origSRV, false, 1) {
		t.Errorf("expected isRecordEqual to be false when port changed")
	}

	// 4. Changed target -> not equal
	rowDiffTarget := DNSRow{
		Name:        "_nbcm-pt._tcp.s.sagan.me",
		Type:        "SRV",
		Content:     "100 6534 other.s.sagan.me",
		ProxyStatus: "dns_only",
		TTL:         "auto",
		Comment:     "test comment",
	}
	if isRecordEqual(rowDiffTarget, origSRV, false, 1) {
		t.Errorf("expected isRecordEqual to be false when target changed")
	}

	// 5. Changed priority -> not equal
	rowDiffPrio := DNSRow{
		Name:        "_nbcm-pt._tcp.s.sagan.me",
		Type:        "SRV",
		Content:     "10 100 6534 nbcm.s.sagan.me",
		ProxyStatus: "dns_only",
		TTL:         "auto",
		Comment:     "test comment",
	}
	if isRecordEqual(rowDiffPrio, origSRV, false, 1) {
		t.Errorf("expected isRecordEqual to be false when priority changed")
	}
}


