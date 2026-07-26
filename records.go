// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/fsutil"
	"github.com/pilot-protocol/common/protocol"
)

// Record types
const (
	RecordA = "A" // Name → Virtual Address
	RecordN = "N" // Network name → Network ID
	RecordS = "S" // Service discovery
)

// MaxNameLength is the maximum length of a name accepted by Register.
// DNS labels are limited to 63 octets; a full name (including dots)
// is limited to 255 octets total. We use 253 — the RFC 1035 maximum
// — as the per-name cap to constrain memory DoS via huge names.
const MaxNameLength = 253

// Record is a name record in the nameserver.
type Record struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`    // for A records
	NetID   uint16 `json:"network_id,omitempty"` // for N records
	Port    uint16 `json:"port,omitempty"`       // for S records
	NodeID  uint32 `json:"node_id,omitempty"`    // for S records (who registered it)
}

// Default TTL for nameserver records.
const DefaultRecordTTL = 5 * time.Minute

// aEntry wraps an A record with creation time for TTL expiry.
type aEntry struct {
	Addr      protocol.Addr
	CreatedAt time.Time
}

// nEntry wraps an N record with creation time for TTL expiry.
// Owner is the node ID that registered the record, or 0 when the
// registrant could not be identified.
type nEntry struct {
	NetID     uint16
	Owner     uint32
	CreatedAt time.Time
}

// RecordStore holds all nameserver records in memory.
type RecordStore struct {
	mu        sync.RWMutex
	aRecords  map[string]*aEntry        // name → addr entry
	nRecords  map[string]*nEntry        // network name → network ID entry
	sRecords  map[svcKey][]ServiceEntry // (network_id, port) → providers
	storePath string                    // path to persist records (empty = no persistence)
	ttl       time.Duration
	done      chan struct{}
	saveSeq   uint64 // guarded by mu; incremented once per snapshot

	// writeMu serializes on-disk writes and guards writtenSeq. It is
	// acquired only after mu has been released, so a file write never
	// blocks readers of the in-memory maps.
	writeMu    sync.Mutex
	writtenSeq uint64
}

type svcKey struct {
	NetworkID uint16
	Port      uint16
}

// ServiceEntry is a provider of a service.
type ServiceEntry struct {
	Name      string        `json:"name"`
	Address   protocol.Addr `json:"address"`
	Port      uint16        `json:"port"`
	CreatedAt time.Time     `json:"-"` // for TTL expiry (L6 fix)
}

func NewRecordStore() *RecordStore {
	rs := &RecordStore{
		aRecords: make(map[string]*aEntry),
		nRecords: make(map[string]*nEntry),
		sRecords: make(map[svcKey][]ServiceEntry),
		ttl:      DefaultRecordTTL,
		done:     make(chan struct{}),
	}
	go rs.reapLoop()
	return rs
}

// Close stops the reaper goroutine.
func (rs *RecordStore) Close() {
	select {
	case <-rs.done:
	default:
		close(rs.done)
	}
}

// reapLoop periodically removes expired records.
func (rs *RecordStore) reapLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rs.reapExpired()
		case <-rs.done:
			return
		}
	}
}

func (rs *RecordStore) reapExpired() {
	rs.mu.Lock()

	now := time.Now()
	reaped := false
	for name, e := range rs.aRecords {
		if now.Sub(e.CreatedAt) > rs.ttl {
			delete(rs.aRecords, name)
			reaped = true
		}
	}
	for name, e := range rs.nRecords {
		if now.Sub(e.CreatedAt) > rs.ttl {
			delete(rs.nRecords, name)
			reaped = true
		}
	}
	// L6 fix: also reap expired S records
	for key, entries := range rs.sRecords {
		alive := entries[:0]
		for _, e := range entries {
			if !e.CreatedAt.IsZero() && now.Sub(e.CreatedAt) > rs.ttl {
				reaped = true
				continue
			}
			alive = append(alive, e)
		}
		if len(alive) == 0 {
			delete(rs.sRecords, key)
		} else {
			rs.sRecords[key] = alive
		}
	}
	var pending *pendingSave
	if reaped {
		pending = rs.snapshotLocked()
	}
	rs.mu.Unlock()

	rs.writeSnapshot(pending)
}

// SetTTL overrides the default record TTL.
func (rs *RecordStore) SetTTL(d time.Duration) {
	rs.mu.Lock()
	rs.ttl = d
	rs.mu.Unlock()
}

// Reap forces an immediate removal of expired records.
func (rs *RecordStore) Reap() {
	rs.reapExpired()
}

// SetStorePath enables persistence to the given file path and loads existing data.
func (rs *RecordStore) SetStorePath(path string) {
	rs.mu.Lock()
	rs.storePath = path
	rs.mu.Unlock()
	rs.load()
}

// --- Persistence ---

type recordSnapshot struct {
	ARecords []snapshotA `json:"a_records"`
	NRecords []snapshotN `json:"n_records"`
	SRecords []snapshotS `json:"s_records"`
}

type snapshotA struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type snapshotN struct {
	Name      string    `json:"name"`
	NetworkID uint16    `json:"network_id"`
	NodeID    uint32    `json:"node_id,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type snapshotS struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	NetworkID uint16    `json:"network_id"`
	Port      uint16    `json:"port"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

// pendingSave is a serialized store snapshot waiting to be written to
// disk. It carries everything writeSnapshot needs so that no store field
// has to be read while the write is in flight.
type pendingSave struct {
	path     string
	data     []byte
	seq      uint64
	aRecords int
	nRecords int
}

// snapshotLocked serializes the current records. The caller must hold mu
// (at least for reading). It returns nil when persistence is disabled.
// The returned snapshot is written by writeSnapshot after mu is released.
func (rs *RecordStore) snapshotLocked() *pendingSave {
	if rs.storePath == "" {
		return nil
	}

	snap := recordSnapshot{}
	for name, e := range rs.aRecords {
		snap.ARecords = append(snap.ARecords, snapshotA{Name: name, Address: e.Addr.String(), CreatedAt: e.CreatedAt})
	}
	for name, e := range rs.nRecords {
		snap.NRecords = append(snap.NRecords, snapshotN{Name: name, NetworkID: e.NetID, NodeID: e.Owner, CreatedAt: e.CreatedAt})
	}
	for key, entries := range rs.sRecords {
		for _, e := range entries {
			snap.SRecords = append(snap.SRecords, snapshotS{
				Name:      e.Name,
				Address:   e.Address.String(),
				NetworkID: key.NetworkID,
				Port:      e.Port,
				CreatedAt: e.CreatedAt,
			})
		}
	}

	// MarshalIndent on recordSnapshot is infallible: every field is a
	// primitive (string/uint16/uint32) or time.Time, no exotic types.
	// The error branch is unreachable.
	data, _ := json.MarshalIndent(snap, "", "  ")

	rs.saveSeq++
	return &pendingSave{
		path:     rs.storePath,
		data:     data,
		seq:      rs.saveSeq,
		aRecords: len(rs.aRecords),
		nRecords: len(rs.nRecords),
	}
}

// writeSnapshot persists a snapshot produced by snapshotLocked. It must
// be called with mu released: the directory creation and the atomic file
// write (which fsyncs) can take milliseconds, and holding mu across them
// would stall every concurrent lookup.
//
// Concurrent writers are serialized on writeMu, and a snapshot older than
// the last one written is dropped so the file always ends up holding the
// most recent state.
func (rs *RecordStore) writeSnapshot(p *pendingSave) {
	if p == nil || p.path == "" {
		return
	}

	rs.writeMu.Lock()
	defer rs.writeMu.Unlock()

	if p.seq <= rs.writtenSeq {
		return
	}

	dir := filepath.Dir(p.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Error("create nameserver state directory", "dir", dir, "err", err)
		return
	}

	if err := fsutil.AtomicWrite(p.path, p.data); err != nil {
		slog.Error("write nameserver state", "err", err)
		return
	}
	rs.writtenSeq = p.seq
	slog.Debug("nameserver state saved", "a_records", p.aRecords, "n_records", p.nRecords)
}

func (rs *RecordStore) load() {
	if rs.storePath == "" {
		return
	}

	data, err := os.ReadFile(rs.storePath)
	if err != nil {
		return // no file yet
	}

	var snap recordSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		slog.Warn("load nameserver state", "err", err)
		return
	}

	// Preserve original CreatedAt across restarts so the TTL reaper
	// sees the true age of each record. Older snapshot formats (pre
	// 2026-05-26) didn't persist CreatedAt; fall back to time.Now() for
	// those so the daemon doesn't reap every loaded record on the first
	// post-upgrade tick.
	now := time.Now()
	restore := func(t time.Time) time.Time {
		if t.IsZero() {
			return now
		}
		return t
	}
	for _, a := range snap.ARecords {
		addr, err := protocol.ParseAddr(a.Address)
		if err != nil {
			continue
		}
		rs.aRecords[normalizeName(a.Name)] = &aEntry{Addr: addr, CreatedAt: restore(a.CreatedAt)}
	}
	for _, n := range snap.NRecords {
		rs.nRecords[normalizeName(n.Name)] = &nEntry{NetID: n.NetworkID, Owner: n.NodeID, CreatedAt: restore(n.CreatedAt)}
	}
	for _, s := range snap.SRecords {
		addr, err := protocol.ParseAddr(s.Address)
		if err != nil {
			continue
		}
		key := svcKey{NetworkID: s.NetworkID, Port: s.Port}
		rs.sRecords[key] = append(rs.sRecords[key], ServiceEntry{
			Name:      normalizeName(s.Name),
			Address:   addr,
			Port:      s.Port,
			CreatedAt: restore(s.CreatedAt),
		})
	}
	slog.Info("loaded nameserver state", "a_records", len(rs.aRecords), "n_records", len(rs.nRecords))
}

// normalizeName folds hostnames to lowercase so the store is case-
// insensitive (DNS convention). All Register/Lookup/Unregister paths
// must funnel name input through this so map keys are canonical.
// Snapshot keys read off disk are also normalized in load() for
// backwards-compat with pre-2026-05-26 stores that may contain mixed-
// case entries.
func normalizeName(name string) string {
	return strings.ToLower(name)
}

// RegisterA adds or updates an A record (name → address).
func (rs *RecordStore) RegisterA(name string, addr protocol.Addr) {
	name = normalizeName(name)
	rs.mu.Lock()
	rs.aRecords[name] = &aEntry{Addr: addr, CreatedAt: time.Now()}
	pending := rs.snapshotLocked()
	rs.mu.Unlock()

	rs.writeSnapshot(pending)
}

// LookupA resolves a name to an address.
func (rs *RecordStore) LookupA(name string) (protocol.Addr, error) {
	name = normalizeName(name)
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	e, ok := rs.aRecords[name]
	if !ok {
		return protocol.ZeroAddr(), fmt.Errorf("name %q not found", name)
	}
	return e.Addr, nil
}

// RegisterN adds a network name record with no recorded owner.
func (rs *RecordStore) RegisterN(name string, netID uint16) {
	rs.RegisterNOwned(name, netID, 0, false)
}

// RegisterNOwned adds a network name record and records owner as the
// node that registered it (0 means the registrant is unknown).
//
// When enforce is true and the name already carries a different non-zero
// owner, the record is left untouched and false is returned. With enforce
// false the record is overwritten unconditionally and true is returned.
func (rs *RecordStore) RegisterNOwned(name string, netID uint16, owner uint32, enforce bool) bool {
	name = normalizeName(name)
	rs.mu.Lock()
	if enforce {
		if cur, ok := rs.nRecords[name]; ok && cur.Owner != 0 && cur.Owner != owner {
			rs.mu.Unlock()
			return false
		}
	}
	rs.nRecords[name] = &nEntry{NetID: netID, Owner: owner, CreatedAt: time.Now()}
	pending := rs.snapshotLocked()
	rs.mu.Unlock()

	rs.writeSnapshot(pending)
	return true
}

// LookupN resolves a network name to a network ID.
func (rs *RecordStore) LookupN(name string) (uint16, error) {
	name = normalizeName(name)
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	e, ok := rs.nRecords[name]
	if !ok {
		return 0, fmt.Errorf("network %q not found", name)
	}
	return e.NetID, nil
}

// RegisterS registers a service provider.
func (rs *RecordStore) RegisterS(name string, addr protocol.Addr, networkID, port uint16) {
	name = normalizeName(name)
	rs.mu.Lock()
	key := svcKey{NetworkID: networkID, Port: port}
	entry := ServiceEntry{Name: name, Address: addr, Port: port, CreatedAt: time.Now()}
	// Avoid duplicates — refresh TTL if already present. Also update
	// Name in case the same (addr, port) was re-registered under a
	// different name (e.g. an operator rolls "cache" → "redis"); the
	// most-recent registration wins instead of letting the stale name
	// haunt every LookupS result until the TTL expires.
	for i, e := range rs.sRecords[key] {
		if e.Address == addr && e.Port == port {
			rs.sRecords[key][i].Name = name
			rs.sRecords[key][i].CreatedAt = time.Now()
			rs.mu.Unlock()
			return
		}
	}
	rs.sRecords[key] = append(rs.sRecords[key], entry)
	pending := rs.snapshotLocked()
	rs.mu.Unlock()

	rs.writeSnapshot(pending)
}

// LookupS finds service providers on a network+port.
func (rs *RecordStore) LookupS(networkID, port uint16) []ServiceEntry {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	key := svcKey{NetworkID: networkID, Port: port}
	result := make([]ServiceEntry, len(rs.sRecords[key]))
	copy(result, rs.sRecords[key])
	return result
}

// UnregisterA removes an A record.
func (rs *RecordStore) UnregisterA(name string) {
	name = normalizeName(name)
	rs.mu.Lock()
	delete(rs.aRecords, name)
	pending := rs.snapshotLocked()
	rs.mu.Unlock()

	rs.writeSnapshot(pending)
}

// AllA returns all A records.
func (rs *RecordStore) AllA() map[string]protocol.Addr {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	result := make(map[string]protocol.Addr, len(rs.aRecords))
	for k, e := range rs.aRecords {
		result[k] = e.Addr
	}
	return result
}
