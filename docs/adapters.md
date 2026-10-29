# Input adapter specification

WireDiet normalizes every source into:

```go
type Event struct {
    Time   time.Time
    Client string
    Domain string
    Status string
    Source string
}
```

Adapters implement:

```go
type Adapter interface {
    Name() string
    Detect(path string, b []byte) bool
    Parse(b []byte) ([]model.Event, error)
}
```

The registry currently includes:

| Adapter | Input | Notes |
|---|---|---|
| `csv` | generic CSV | `domain` required; timestamp/time, client/client_ip and status optional |
| `json` | generic JSON | array or `{ "events": [...] }` |
| `dnsmasq` | text query log | recognizes `query[TYPE] host from client` |
| `adguard` | AdGuard Home query-log JSON | parses current `/control/querylog` `question.name` responses; accepts legacy `question.host` fixtures only when unambiguous |
| `pihole` | Pi-hole v6 query JSON | matches `/api/queries` response envelope |

## Adapter requirements

A new adapter must:

- be read-only
- never execute imported text
- enforce the shared file/event limits
- preserve unknown status values rather than invent semantics
- emit domain names only after shared normalization/validation
- ship with synthetic fixtures
- include malformed-input tests
- document source version assumptions

## Why PCAP is not in v0.1

Packet capture would require capture privileges, platform-specific drivers and substantially more code. Mature tools such as IoT Inspector already focus on capture and visualization. WireDiet’s differentiated layer is feature-aware policy learning, so v0.1 starts with resolver logs that many target users already have.

A later PCAP **import** adapter can consume existing captures without turning WireDiet into another packet-capture product.

## Incidental NextDNS CSV compatibility

NextDNS currently lets users download logs as CSV and documents columns including `timestamp`, `domain`, `client_ip` and `status`. WireDiet's generic CSV adapter recognizes those names, so a downloaded CSV containing a `domain` column can be analyzed locally without a NextDNS API integration. This is generic file compatibility, not a cloud connector and not a promise that every optional NextDNS field is interpreted.
