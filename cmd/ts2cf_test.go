package cmd

import (
	"testing"
)

func TestExtractDeviceName(t *testing.T) {
	tests := []struct {
		name     string
		dnsName  string
		hostName string
		want     string
	}{
		{
			name:     "Prefer MagicDNS from DNSName",
			dnsName:  "my-laptop.tailnet-xyz.ts.net.",
			hostName: "DESKTOP-ABC123",
			want:     "my-laptop",
		},
		{
			name:     "DNSName with multiple subdomains",
			dnsName:  "server-01.custom.tailnet.ts.net.",
			hostName: "server-01",
			want:     "server-01",
		},
		{
			name:     "DNSName without trailing dot",
			dnsName:  "web-server.tailnet.ts.net",
			hostName: "web-server",
			want:     "web-server",
		},
		{
			name:     "Fallback to HostName if DNSName empty",
			dnsName:  "",
			hostName: "home-nas",
			want:     "home-nas",
		},
		{
			name:     "Fallback to HostName with spaces replaced by hyphens",
			dnsName:  "",
			hostName: "Alice MacBook Pro",
			want:     "alice-macbook-pro",
		},
		{
			name:     "Fallback to HostName uppercase converted to lowercase",
			dnsName:  "",
			hostName: "PI-HOLE",
			want:     "pi-hole",
		},
		{
			name:     "Both DNSName and HostName invalid returns empty",
			dnsName:  "",
			hostName: "-invalid-label-",
			want:     "",
		},
		{
			name:     "Empty inputs return empty",
			dnsName:  "",
			hostName: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDeviceName(tt.dnsName, tt.hostName)
			if got != tt.want {
				t.Errorf("extractDeviceName(%q, %q) = %q, want %q", tt.dnsName, tt.hostName, got, tt.want)
			}
		})
	}
}

func TestFindTailscaleIPv4(t *testing.T) {
	tests := []struct {
		name string
		ips  []string
		want string
	}{
		{
			name: "Standard Tailscale IPv4 and IPv6",
			ips:  []string{"100.64.0.1", "fd7a:115c:a1e0:ab12:4843:cd96:627e:0001"},
			want: "100.64.0.1",
		},
		{
			name: "IPv6 first then IPv4",
			ips:  []string{"fd7a:115c:a1e0:ab12:4843:cd96:627e:0001", "100.101.102.103"},
			want: "100.101.102.103",
		},
		{
			name: "Only IPv6",
			ips:  []string{"fd7a:115c:a1e0:ab12:4843:cd96:627e:0001"},
			want: "",
		},
		{
			name: "Empty IP slice",
			ips:  []string{},
			want: "",
		},
		{
			name: "Invalid IP strings",
			ips:  []string{"invalid-ip", "not-an-ip"},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findTailscaleIPv4(tt.ips)
			if got != tt.want {
				t.Errorf("findTailscaleIPv4(%v) = %q, want %q", tt.ips, got, tt.want)
			}
		})
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	sampleJSON := []byte(`{
		"Version": "1.72.0",
		"BackendState": "Running",
		"TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
		"Self": {
			"ID": "node-self-id",
			"HostName": "my-workstation",
			"DNSName": "workstation.tailnet.ts.net.",
			"OS": "linux",
			"TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
			"Online": true
		},
		"Peer": {
			"nodekey:1": {
				"ID": "node-peer-1",
				"HostName": "ubuntu-server",
				"DNSName": "ubuntu-server.tailnet.ts.net.",
				"OS": "linux",
				"TailscaleIPs": ["100.64.0.2", "fd7a:115c:a1e0::2"],
				"Online": true
			},
			"nodekey:2": {
				"ID": "node-peer-2",
				"HostName": "backup-nas",
				"DNSName": "nas.tailnet.ts.net.",
				"OS": "synology",
				"TailscaleIPs": ["100.64.0.3"],
				"Online": false
			},
			"nodekey:3": {
				"ID": "node-peer-ipv6-only",
				"HostName": "v6-only",
				"DNSName": "v6-only.tailnet.ts.net.",
				"TailscaleIPs": ["fd7a:115c:a1e0::99"],
				"Online": true
			},
			"nodekey:4": {
				"ID": "node-peer-duplicate",
				"HostName": "nas",
				"DNSName": "nas.tailnet.ts.net.",
				"TailscaleIPs": ["100.64.0.4"],
				"Online": true
			}
		}
	}`)

	t.Run("Include Self true", func(t *testing.T) {
		devices, err := parseTailscaleStatus(sampleJSON, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Expected devices:
		// 1. Self ("workstation", 100.64.0.1)
		// 2. Peer node-peer-1 ("ubuntu-server", 100.64.0.2)
		// 3. Peer node-peer-2 ("nas", 100.64.0.3)
		// (nodekey:3 has no IPv4 -> skipped)
		// (nodekey:4 duplicate name "nas" -> skipped)
		if len(devices) != 3 {
			t.Fatalf("expected 3 devices, got %d: %+v", len(devices), devices)
		}

		expected := []struct {
			name   string
			ip     string
			isSelf bool
		}{
			{"workstation", "100.64.0.1", true},
			{"ubuntu-server", "100.64.0.2", false},
			{"nas", "100.64.0.3", false},
		}

		for i, exp := range expected {
			if devices[i].Name != exp.name {
				t.Errorf("device[%d].Name = %q, want %q", i, devices[i].Name, exp.name)
			}
			if devices[i].IP != exp.ip {
				t.Errorf("device[%d].IP = %q, want %q", i, devices[i].IP, exp.ip)
			}
			if devices[i].IsSelf != exp.isSelf {
				t.Errorf("device[%d].IsSelf = %v, want %v", i, devices[i].IsSelf, exp.isSelf)
			}
		}
	})

	t.Run("Include Self false", func(t *testing.T) {
		devices, err := parseTailscaleStatus(sampleJSON, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(devices) != 2 {
			t.Fatalf("expected 2 devices, got %d: %+v", len(devices), devices)
		}

		for _, d := range devices {
			if d.IsSelf {
				t.Errorf("expected no self devices when includeSelf=false, got %v", d)
			}
		}
	})

	t.Run("Self fallback to root TailscaleIPs", func(t *testing.T) {
		jsonNoSelfIPs := []byte(`{
			"TailscaleIPs": ["100.64.0.50"],
			"Self": {
				"HostName": "my-pc",
				"DNSName": "my-pc.tailnet.ts.net.",
				"TailscaleIPs": []
			}
		}`)

		devices, err := parseTailscaleStatus(jsonNoSelfIPs, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		if devices[0].IP != "100.64.0.50" {
			t.Errorf("expected IP 100.64.0.50, got %s", devices[0].IP)
		}
		if devices[0].Name != "my-pc" {
			t.Errorf("expected Name my-pc, got %s", devices[0].Name)
		}
	})
}

func TestTs2cfCmdFlags(t *testing.T) {
	// Verify command exists in rootCmd
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "ts2cf" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ts2cf command not found in rootCmd")
	}

	expectedFlags := []string{
		"cf-token",
		"cf-zone",
		"domain",
		"dry-run",
		"delete-stale",
		"tailscale-bin",
		"status-file",
		"include-self",
	}

	for _, flagName := range expectedFlags {
		flag := ts2cfCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("expected flag %q on ts2cfCmd, but not found", flagName)
		}
	}
}
