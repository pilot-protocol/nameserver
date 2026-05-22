# nameserver

Nameserver plugin for the Pilot Protocol daemon. Resolves
human-readable hostnames to virtual pilot addresses over the overlay
(port 53). Supports A records (hostname to address), N records
(network name to network ID), and S records (service discovery).

## Install

```go
import "github.com/pilot-protocol/nameserver"
```

## Usage

```go
s := nameserver.NewService(nameserver.Config{
    StorePath: "~/.pilot/records.json",
})
rt.Register(s)
```

## Layout

| File | What it does |
|---|---|
| `wire.go` | DNS-like wire format: query/response frames over the pilot stream. |
| `records.go` | `RecordStore` — JSON-backed record store and lookup index. |
| `server.go` | Accept loop and per-query dispatch. |
| `client.go` | `Lookup`, `Register` — caller-side helpers. |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_nameserver`. |
| `service_disabled.go` | Stub when build tag `no_nameserver` is set. |

## Build tags

| Tag | Effect |
|---|---|
| `no_nameserver` | Compiles a stub whose `Start` is a no-op. |
