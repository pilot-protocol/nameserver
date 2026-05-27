// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver_test

// Regression for hostname case-sensitivity: RecordStore stores names
// as-typed in its maps. "Daemon" and "daemon" become distinct records,
// silently leading to duplicate entries and stale lookups for any
// client that varies case. DNS-style behavior is case-insensitive;
// the daemon's hostname namespace should match that convention.

import (
	"testing"

	"github.com/pilot-protocol/nameserver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestRecordStoreLookupCaseInsensitive(t *testing.T) {
	t.Parallel()

	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr, err := protocol.ParseAddr("0:0000.0001.AAAA")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	rs.RegisterA("Daemon", addr)

	// All three lookups must resolve to the same record. With the bug
	// they don't, because "Daemon", "daemon", "DAEMON" are distinct
	// map keys.
	for _, q := range []string{"Daemon", "daemon", "DAEMON"} {
		got, err := rs.LookupA(q)
		if err != nil {
			t.Errorf("LookupA(%q): %v — case-insensitive lookup must succeed", q, err)
			continue
		}
		if got != addr {
			t.Errorf("LookupA(%q) = %v, want %v", q, got, addr)
		}
	}
}

func TestRecordStoreRegisterCollidesByCase(t *testing.T) {
	t.Parallel()

	rs := nameserver.NewRecordStore()
	defer rs.Close()

	addr1, _ := protocol.ParseAddr("0:0000.0001.AAAA")
	addr2, _ := protocol.ParseAddr("0:0000.0001.BBBB")

	rs.RegisterA("svc-x", addr1)
	rs.RegisterA("SVC-X", addr2) // re-registers, case-folded; should overwrite

	// After two registrations differing only in case, both lookups must
	// return the latest record. With the bug they return different
	// records (addr1 and addr2 respectively) — the namespace is split.
	got, err := rs.LookupA("svc-x")
	if err != nil {
		t.Fatalf("LookupA(lowercase): %v", err)
	}
	if got != addr2 {
		t.Errorf("LookupA(lowercase) returned addr1 — second register at "+
			"different case must overwrite, got %v want %v", got, addr2)
	}

	got2, err := rs.LookupA("SVC-X")
	if err != nil {
		t.Fatalf("LookupA(uppercase): %v", err)
	}
	if got2 != addr2 {
		t.Errorf("LookupA(uppercase) = %v, want %v", got2, addr2)
	}
}
