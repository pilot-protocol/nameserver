# nameserver

Pilot Protocol nameserver plugin. Resolves human-readable hostnames
to virtual pilot addresses over the overlay (port 53). Supports A
records (hostname → address), N records (network name → network ID),
and S records (service discovery).

## Layout

| File | What it does |
|---|---|
| `wire.go` | DNS-like wire format: query/response frames over the pilot stream. |
| `records.go` | `RecordStore` — JSON-backed record store + lookup index. |
| `server.go` | Accept loop + per-query dispatch. |
| `client.go` | `Lookup`, `Register` — caller-side helpers. |
| `service.go` | `*Service` — `coreapi.Service` adapter. Build tag `!no_nameserver`. |
| `service_disabled.go` | Stub when build tag `no_nameserver` is set. |

## Import paths

```go
import "github.com/pilot-protocol/nameserver"

s := nameserver.NewService(nameserver.Config{
    StorePath: "~/.pilot/records.json",
})
rt.Register(s)
```

## Disabling

Pass `-tags no_nameserver` to compile a stub whose `Start` is a no-op.

## Releasing

Tag a SemVer version (e.g. `v0.1.0`); web4 pulls it in via
`require github.com/pilot-protocol/nameserver v0.1.0`. During
co-development the protocol repo uses `replace ../nameserver`.
