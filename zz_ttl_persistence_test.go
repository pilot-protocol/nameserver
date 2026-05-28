// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver_test

// Regression for the persistent-TTL-bypass bug: when records are
// reloaded from disk, RecordStore.load() sets CreatedAt = time.Now()
// because the snapshot format never persisted the field. A record
// stored 4 days ago appears fresh after a single daemon restart,
// defeating the TTL completely.
//
// Test shape: register → persist → restart-via-fresh-store → wait
// past TTL → reap → record must be gone. The bug makes the record
// appear fresh-on-load (CreatedAt = restart-time), so the post-reap
// lookup currently succeeds where it should fail.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/nameserver"
	"github.com/pilot-protocol/common/protocol"
)

func TestRecordStoreTTLSurvivesRestart(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "nameserver.json")

	// Register a record well into the past — far enough beyond the TTL
	// that an honest store would have reaped it on first opportunity.
	old := nameserver.NewRecordStore()
	old.SetStorePath(storePath)
	old.SetTTL(50 * time.Millisecond)

	addr, err := protocol.ParseAddr("0:0000.0001.2345")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	old.RegisterA("staleguy", addr)

	// Wait past TTL so any honest "reap" would clear the record.
	time.Sleep(150 * time.Millisecond)
	old.Close()

	// Fresh store loads from disk — simulating a daemon restart.
	fresh := nameserver.NewRecordStore()
	fresh.SetTTL(50 * time.Millisecond)
	fresh.SetStorePath(storePath)
	defer fresh.Close()

	// The record SHOULD already be past TTL when loaded. Reap evicts
	// expired records based on CreatedAt + TTL.
	fresh.Reap()

	if _, err := fresh.LookupA("staleguy"); err == nil {
		t.Fatal("LookupA returned a record that should have been " +
			"reaped — TTL not surviving restart (CreatedAt reset to " +
			"time.Now() on load, snapshot doesn't persist the field)")
	}
}
