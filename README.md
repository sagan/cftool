# cftool

A cli tool to manage Cloudflare DNS records. It has several sub-commands:

- `zt2cf` : Sync DNS records from ZeroTier to Cloudflare.
- `wg2cf` : Sync DNS records from WireGuard to Cloudflare.
- `cf2hosts` : Sync DNS records from Cloudflare to local hosts file.

Written by Google Gemini Pro & Antigravity, published in public domain.

## zt2cf

Sync the DNS records between a specified ZeroTier network and a specified cloudflare domain (e.g. `example.com` or `z.example.com`) . For every authorized devices in the ZeroTier network, it adds or updates the A dns record of `<name>.<domain>` resolving to the device managed IP, where `<name>` is the device name in ZeroTier.

### Examples

```
cftool zt2cf --cf-token <cf-token> --cf-zone <cf-zone> --zt-token <zt-token> --zt-network <zt-network> --domain z.example.me --dry-run
```

### Usage

```
      --cf-token string     Cloudflare API Token (env: CF_TOKEN)
      --cf-zone string      Cloudflare Zone ID (env: CF_ZONE)
      --delete-stale        Enable deletion of stale DNS records in Cloudflare
      --domain string       Target domain (e.g., example.com or z.example.com) (env: DOMAIN)
      --dry-run             Enable dry run mode (log changes without applying)
  -h, --help                help for zt2cf
      --zt-network string   ZeroTier Network ID (env: ZT_NETWORK)
      --zt-token string     ZeroTier Central API Token (env: ZT_TOKEN)
```

## wg2cf

Sync the DNS records between a specified WireGuard interface and a specified cloudflare domain (e.g. `example.com` or `w.example.com`). For every peers defined in `/etc/wireguard/<interface>.conf`, it adds or updates the A dns record of `<name>.<domain>` resolving to the peer's private IP. The peer name is read from `# Name = foo` comment; the ip is read from the first one of `AllowedIPs` list. E.g. :

```
[Peer]
# Name = foo (any description)
AllowedIPs = 192.168.200.100/32
```

Then it sets `foo.example.com` DNS to `192.168.200.100`. Note the name is truncated at first space.

### Examples

```
cftool wg2cf --cf-token <cf-token> --cf-zone <cf-zone> --domain w.example.me --interface wg0 -dry-run
```

### Usage

```
      --cf-token string    Cloudflare API Token (env: CF_TOKEN)
      --cf-zone string     Cloudflare Zone ID (env: CF_ZONE)
      --delete-stale       Enable deletion of stale DNS records in Cloudflare
      --domain string      Target domain (e.g., example.com or z.example.com) (env: DOMAIN)
      --dry-run            Enable dry run mode (log changes without applying)
  -h, --help               help for wg2cf
      --interface string   WireGuard interface name (e.g., wg0) (default "wg0")
```

## cf2hosts

Get Cloudflare domain DNS records and update local hosts file:

1. For A/CNAME records, update the "hosts" file of currrent OS, adding / updating the domain => ip pairs.
2. (obsolete) If a optional `<save-srv-dir>` param is provided, for SRV records, like `_service._tcp.example.com`, it saves records to files in the `<save-srv-dir>` using "service" as filename, the file is in ipset ("hash:ip,port" type) save file format.

### Example

```
cf2hosts . --cf-token <token> --cf-zone <zone-id> --domain <example.com>
```

### Usage

```
      --cf-token string         Cloudflare API Token (env: CF_TOKEN)
      --cf-zone string          Cloudflare Zone ID (env: CF_ZONE)
      --domain string           Base domain/subdomain (or multiple comma separated domains) to manage (e.g., example.com) (env: DOMAIN). If a domain in list has a "^" prefix, only the domain itself matches, otherwise the domain and all subdomains inside it matches
      --dry-run                 If true, no actual changes will be made
      --exclude-domain string   Exclude domain/subdomain (or multiple comma separated domains) from management (e.g., exclude.example.com) (env: EXCLUDE_DOMAIN). If a domain in list has a "^" prefix, only the domain itself matches, otherwise the domain and all subdomains inside it matches
  -h, --help                    help for cf2hosts
      --hosts-file string       Hosts file path. If not provided, will use current OS system hosts file (env: HOSTS_FILE) (default "C:\\WINDOWS\\System32\\drivers\\etc\\hosts")
      --identifier string       Optional hosts file updating section identifier mark (env: IDENTIFIER)
      --save-srv-dir string     Directory to save SRV records for ipset (optional) (env: SAVE_SRV_DIR)
      --verbose                 Enable verbose output
```
