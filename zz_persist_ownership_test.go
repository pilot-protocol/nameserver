// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// ---------------------------------------------------------------------------
// Persistence happens outside the store lock (records.go).
// ---------------------------------------------------------------------------

// TestWriteSnapshotRunsWithoutStoreLock pins that a file write in flight
// does not stall readers: writeMu is held for the duration of the write,
// but mu is released before it starts, so lookups (and the newly written
// record) are visible while the write is still pending.
func TestWriteSnapshotRunsWithoutStoreLock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rs := NewRecordStore()
	defer rs.Close()
	rs.SetStorePath(filepath.Join(dir, "ns.json"))

	rs.RegisterA("seed", protocol.Addr{Node: 1})

	// Stand in for a slow disk: the next write blocks until we release it.
	rs.writeMu.Lock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		rs.RegisterA("pending", protocol.Addr{Node: 2})
	}()

	// The map mutation must land (and lookups must keep working) even
	// though the write has not completed.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := rs.LookupA("pending"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			rs.writeMu.Unlock()
			t.Fatal("lookup of pending record blocked behind the file write")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := rs.LookupA("seed"); err != nil {
		rs.writeMu.Unlock()
		t.Fatalf("LookupA(seed) during pending write: %v", err)
	}

	select {
	case <-done:
		t.Fatal("RegisterA returned while the file write was still blocked")
	default:
	}

	rs.writeMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RegisterA did not finish after the write was released")
	}
}

// TestWriteSnapshotDropsStaleSequence pins that an older snapshot landing
// after a newer one does not roll the file back.
func TestWriteSnapshotDropsStaleSequence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ns.json")
	rs := NewRecordStore()
	defer rs.Close()
	rs.SetStorePath(path)

	rs.mu.Lock()
	rs.aRecords["older"] = &aEntry{Addr: protocol.Addr{Node: 1}, CreatedAt: time.Now()}
	older := rs.snapshotLocked()
	rs.mu.Unlock()

	rs.mu.Lock()
	rs.aRecords["newer"] = &aEntry{Addr: protocol.Addr{Node: 2}, CreatedAt: time.Now()}
	newer := rs.snapshotLocked()
	rs.mu.Unlock()

	rs.writeSnapshot(newer)
	rs.writeSnapshot(older)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if !strings.Contains(string(data), `"newer"`) {
		t.Errorf("stale snapshot overwrote the newer one: %s", data)
	}
}

// TestConcurrentRegistersConvergeOnDisk exercises the snapshot/write split
// under concurrency: the last write must reflect every registration.
func TestConcurrentRegistersConvergeOnDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ns.json")
	rs := NewRecordStore()
	defer rs.Close()
	rs.SetStorePath(path)

	const n = 32
	done := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			rs.RegisterA(fmt.Sprintf("host-%d", i), protocol.Addr{Node: uint32(i + 1)})
			_, _ = rs.LookupA("host-0")
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}

	// Force one final write so the file reflects the settled state
	// regardless of which concurrent snapshot won the race.
	rs.RegisterA("final", protocol.Addr{Node: 0xFFFF})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	for i := 0; i < n; i++ {
		if !strings.Contains(string(data), fmt.Sprintf(`"host-%d"`, i)) {
			t.Fatalf("host-%d missing from persisted snapshot", i)
		}
	}
}

// ---------------------------------------------------------------------------
// Caller identity + N-record ownership (server.go).
// ---------------------------------------------------------------------------

func TestResolveCallerNode_Forms(t *testing.T) {
	t.Parallel()
	want := protocol.Addr{Network: 0, Node: 0x12345678}

	// The shape the overlay connection adapter reports: a Pilot address
	// followed by ":<port>".
	if got, ok := resolveCallerNode(stringAddr{s: want.String() + ":53"}); !ok || got != want.Node {
		t.Errorf("addr:port form: got 0x%x ok=%v, want 0x%x true", got, ok, want.Node)
	}
	// Bare address, no port.
	if got, ok := resolveCallerNode(stringAddr{s: want.String()}); !ok || got != want.Node {
		t.Errorf("bare form: got 0x%x ok=%v, want 0x%x true", got, ok, want.Node)
	}
	// Bracketed host:port.
	if got, ok := resolveCallerNode(stringAddr{s: "[" + want.String() + "]:8080"}); !ok || got != want.Node {
		t.Errorf("bracketed form: got 0x%x ok=%v, want 0x%x true", got, ok, want.Node)
	}
	// Node 0 counts as no identity.
	zero := protocol.Addr{Network: 0, Node: 0}
	if got, ok := resolveCallerNode(stringAddr{s: zero.String() + ":53"}); ok || got != 0 {
		t.Errorf("zero node: got 0x%x ok=%v, want 0 false", got, ok)
	}
	for _, s := range []string{"", "not-a-pilot-addr", "127.0.0.1:8080"} {
		if got, ok := resolveCallerNode(stringAddr{s: s}); ok || got != 0 {
			t.Errorf("%q: got 0x%x ok=%v, want 0 false", s, got, ok)
		}
	}
	if got, ok := resolveCallerNode(nil); ok || got != 0 {
		t.Errorf("nil addr: got 0x%x ok=%v, want 0 false", got, ok)
	}
}

func callerAddr(node uint32) stringAddr {
	return stringAddr{s: protocol.Addr{Network: 0, Node: node}.String() + ":53"}
}

// TestRegisterN_DefaultAllowsOverwrite pins the default (flag off)
// behaviour: any caller may replace an N record.
func TestRegisterN_DefaultAllowsOverwrite(t *testing.T) {
	t.Parallel()
	s := New(&fakeListener{}, "")
	if s.StrictRegister() {
		t.Fatal("strict register should be off by default")
	}

	req := Request{Command: "REGISTER", RecordType: RecordN, Name: "shared", NetID: 5}
	if got := s.handleRequest(req, callerAddr(1)); got != "OK" {
		t.Fatalf("first REGISTER N: got %q", got)
	}
	req.NetID = 9
	if got := s.handleRequest(req, callerAddr(2)); got != "OK" {
		t.Fatalf("overwrite from another node: got %q", got)
	}
	if got, err := s.store.LookupN("shared"); err != nil || got != 9 {
		t.Errorf("LookupN: got (%d, %v), want (9, nil)", got, err)
	}
}

// TestRegisterN_StrictEnforcesOwnership pins that with strict handling on,
// only the node that registered a network name may change it.
func TestRegisterN_StrictEnforcesOwnership(t *testing.T) {
	t.Parallel()
	s := New(&fakeListener{}, "")
	s.SetStrictRegister(true)

	req := Request{Command: "REGISTER", RecordType: RecordN, Name: "owned", NetID: 5}
	if got := s.handleRequest(req, callerAddr(1)); got != "OK" {
		t.Fatalf("first REGISTER N: got %q", got)
	}

	other := Request{Command: "REGISTER", RecordType: RecordN, Name: "owned", NetID: 9}
	got := s.handleRequest(other, callerAddr(2))
	if !strings.HasPrefix(got, "ERR ") {
		t.Fatalf("REGISTER N from another node: got %q, want ERR", got)
	}
	if netID, err := s.store.LookupN("owned"); err != nil || netID != 5 {
		t.Errorf("record changed despite refusal: got (%d, %v)", netID, err)
	}

	// The owner may still update its own record.
	req.NetID = 7
	if got := s.handleRequest(req, callerAddr(1)); got != "OK" {
		t.Fatalf("owner update: got %q", got)
	}
	if netID, err := s.store.LookupN("owned"); err != nil || netID != 7 {
		t.Errorf("owner update not applied: got (%d, %v)", netID, err)
	}
}

// TestRegisterStrictRequiresCallerIdentity pins that strict handling
// refuses registrations whose remote address carries no node ID.
func TestRegisterStrictRequiresCallerIdentity(t *testing.T) {
	t.Parallel()
	s := New(&fakeListener{}, "")
	s.SetStrictRegister(true)

	addr := protocol.Addr{Network: 0, Node: 0x99}
	reqs := []Request{
		{Command: "REGISTER", RecordType: RecordA, Name: "a", Address: addr.String()},
		{Command: "REGISTER", RecordType: RecordN, Name: "n", NetID: 1},
		{Command: "REGISTER", RecordType: RecordS, Name: "s", Address: addr.String(), NetID: 1, Port: 80},
	}
	for _, req := range reqs {
		if got := s.handleRequest(req, nil); !strings.HasPrefix(got, "ERR ") {
			t.Errorf("REGISTER %s with no caller identity: got %q, want ERR", req.RecordType, got)
		}
		if got := s.handleRequest(req, stringAddr{s: "127.0.0.1:8080"}); !strings.HasPrefix(got, "ERR ") {
			t.Errorf("REGISTER %s from non-pilot addr: got %q, want ERR", req.RecordType, got)
		}
	}
	if _, err := s.store.LookupA("a"); err == nil {
		t.Error("A record was stored despite refusal")
	}
	if _, err := s.store.LookupN("n"); err == nil {
		t.Error("N record was stored despite refusal")
	}
	if svcs := s.store.LookupS(1, 80); len(svcs) != 0 {
		t.Errorf("S record was stored despite refusal: %+v", svcs)
	}
}

// TestRegisterA_StrictMatchesCallerNode pins that with strict handling on
// the caller node is actually resolved from the "addr:port" remote address
// form, so the existing self-registration check fires.
func TestRegisterA_StrictMatchesCallerNode(t *testing.T) {
	t.Parallel()
	s := New(&fakeListener{}, "")
	s.SetStrictRegister(true)

	foreign := protocol.Addr{Network: 0, Node: 0x99}
	req := Request{Command: "REGISTER", RecordType: RecordA, Name: "bob", Address: foreign.String()}
	if got := s.handleRequest(req, callerAddr(1)); !strings.HasPrefix(got, "ERR ") {
		t.Errorf("REGISTER A for another node: got %q, want ERR", got)
	}

	own := protocol.Addr{Network: 0, Node: 1}
	req = Request{Command: "REGISTER", RecordType: RecordA, Name: "self", Address: own.String()}
	if got := s.handleRequest(req, callerAddr(1)); got != "OK" {
		t.Errorf("REGISTER A for own node: got %q", got)
	}
	if addr, err := s.store.LookupA("self"); err != nil || addr != own {
		t.Errorf("LookupA(self): got (%v, %v)", addr, err)
	}
}

func TestStrictRegisterFromEnv(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"no", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
	} {
		t.Setenv(StrictRegisterEnv, tc.val)
		s := New(&fakeListener{}, "")
		if got := s.StrictRegister(); got != tc.want {
			t.Errorf("%s=%q: got %v, want %v", StrictRegisterEnv, tc.val, got, tc.want)
		}
	}
}

// TestRegisterNOwned_PersistsOwner pins that the owning node survives a
// snapshot round-trip, so enabling strict handling later has the data it
// needs.
func TestRegisterNOwned_PersistsOwner(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "ns.json")

	rs := NewRecordStore()
	rs.SetStorePath(path)
	if !rs.RegisterNOwned("mynet", 5, 0x1234, false) {
		t.Fatal("RegisterNOwned returned false")
	}
	rs.Close()

	rs2 := NewRecordStore()
	defer rs2.Close()
	rs2.SetStorePath(path)
	if netID, err := rs2.LookupN("mynet"); err != nil || netID != 5 {
		t.Fatalf("LookupN after reload: got (%d, %v)", netID, err)
	}
	if rs2.RegisterNOwned("mynet", 9, 0x5678, true) {
		t.Error("reloaded record accepted a different owner under enforcement")
	}
	if !rs2.RegisterNOwned("mynet", 9, 0x1234, true) {
		t.Error("reloaded record refused its own owner")
	}
}
