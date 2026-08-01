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
