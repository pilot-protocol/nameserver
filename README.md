# nameserver

[![ci](https://github.com/pilot-protocol/nameserver/actions/workflows/ci.yml/badge.svg)](https://github.com/pilot-protocol/nameserver/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/pilot-protocol/nameserver/branch/main/graph/badge.svg)](https://codecov.io/gh/pilot-protocol/nameserver)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

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

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
