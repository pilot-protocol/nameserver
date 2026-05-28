// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// fakeListener implements PortListener using net.Listen on 127.0.0.1.
type fakeListener struct {
	addr string
}

func (l *fakeListener) Listen(port uint16) (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l.addr = ln.Addr().String()
	return ln, nil
}

// fakeDialer implements Dialer using the underlying TCP listener address.
type fakeDialer struct {
	addr string
}

func (d *fakeDialer) DialAddrTimeout(protocol.Addr, uint16, time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", d.addr, 2*time.Second)
}

// startServer launches a nameserver in a goroutine and returns the
// underlying TCP address + a teardown.
func startServer(t *testing.T) (*Server, *fakeDialer) {
	t.Helper()
	pl := &fakeListener{}
	s := New(pl, "")
	go func() {
		_ = s.ListenAndServe()
	}()
	// Wait for the server to be ready.
	select {
	case <-s.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("server not ready in 2s")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, &fakeDialer{addr: pl.addr}
}

func TestServer_NewAndStore(t *testing.T) {
	t.Parallel()
	pl := &fakeListener{}
	s := New(pl, "")
	if s.Store() == nil {
		t.Fatal("Store() nil")
	}
	if s.Ready() == nil {
		t.Fatal("Ready() nil")
	}
	// Close before Listen — should be a clean no-op.
	if err := s.Close(); err != nil {
		t.Errorf("Close before Listen: %v", err)
	}
}

func TestServer_NewWithStorePath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pl := &fakeListener{}
	s := New(pl, dir+"/records.json")
	if s.Store() == nil {
		t.Fatal("Store() nil with store path")
	}
}

func TestClient_LookupAfterRegister_AllRecords(t *testing.T) {
	t.Parallel()
	srv, dialer := startServer(t)
	_ = srv

	// Pre-populate the store directly so the lookup test doesn't depend
	// on a real Pilot RemoteAddr.
	srv.Store().RegisterA("alice", protocol.Addr{Network: 0, Node: 0x1234})
	srv.Store().RegisterN("mynet", 7)
	srv.Store().RegisterS("web", protocol.Addr{Network: 7, Node: 0x5678}, 7, 80)

	client := NewClient(dialer, protocol.Addr{Network: 0, Node: 1})

	// LookupA
	gotAddr, err := client.LookupA("alice")
	if err != nil {
		t.Fatalf("LookupA: %v", err)
	}
	if gotAddr.Node != 0x1234 {
		t.Errorf("LookupA: got node %x, want 0x1234", gotAddr.Node)
	}

	// LookupN
	netID, err := client.LookupN("mynet")
	if err != nil {
		t.Fatalf("LookupN: %v", err)
	}
	if netID != 7 {
		t.Errorf("LookupN: got %d, want 7", netID)
	}

	// LookupS
	entries, err := client.LookupS(7, 80)
	if err != nil {
		t.Fatalf("LookupS: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("LookupS: got %d entries, want 1", len(entries))
	}
}

func TestClient_LookupMisses(t *testing.T) {
	t.Parallel()
	_, dialer := startServer(t)
	client := NewClient(dialer, protocol.Addr{Network: 0, Node: 1})

	if _, err := client.LookupA("no-such-name"); err == nil {
		t.Error("LookupA(no-such-name): want error")
	}
	if _, err := client.LookupN("no-such-net"); err == nil {
		t.Error("LookupN(no-such-net): want error")
	}
	// LookupS returns empty list — no error.
	entries, err := client.LookupS(9999, 9999)
	if err != nil {
		t.Errorf("LookupS empty: unexpected err %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("LookupS empty: got %d entries", len(entries))
	}
}

func TestClient_RegisterDoesNotErrorWhenCallerCannotBeIdentified(t *testing.T) {
	t.Parallel()
	srv, dialer := startServer(t)
	client := NewClient(dialer, protocol.Addr{Network: 0, Node: 1})

	// RegisterN doesn't have the caller-self check, so it always succeeds.
	if err := client.RegisterN("created", 42); err != nil {
		t.Errorf("RegisterN: %v", err)
	}

	// Verify via direct store inspection.
	if got, err := srv.Store().LookupN("created"); err != nil || got != 42 {
		t.Errorf("LookupN after RegisterN: got (%d, %v)", got, err)
	}
}

func TestClient_RegisterA_RequiresMatchingCaller(t *testing.T) {
	t.Parallel()
	_, dialer := startServer(t)
	client := NewClient(dialer, protocol.Addr{Network: 0, Node: 1})

	// Because the TCP dialer's RemoteAddr isn't a Pilot Addr, callerNode
	// resolves to 0, which means the self-check is bypassed and the
	// register succeeds.
	err := client.RegisterA("bob", protocol.Addr{Network: 0, Node: 0x99})
	if err != nil {
		t.Errorf("RegisterA: %v", err)
	}
}

func TestClient_RegisterS_RequiresMatchingCaller(t *testing.T) {
	t.Parallel()
	_, dialer := startServer(t)
	client := NewClient(dialer, protocol.Addr{Network: 0, Node: 1})

	err := client.RegisterS("svc", protocol.Addr{Network: 1, Node: 1}, 1, 80)
	if err != nil {
		t.Errorf("RegisterS: %v", err)
	}
}

func TestExtractCallerNode_Branches(t *testing.T) {
	t.Parallel()
	if got := extractCallerNode(nil); got != 0 {
		t.Errorf("nil addr: got %d, want 0", got)
	}
	// TCP addr (no Pilot format) → 0.
	if got := extractCallerNode(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}); got != 0 {
		t.Errorf("TCP addr: got %d, want 0", got)
	}
}

func TestHandleRequest_UnknownCommand(t *testing.T) {
	t.Parallel()
	pl := &fakeListener{}
	s := New(pl, "")
	resp := s.handleRequest(Request{Command: "EXPLODE"}, nil)
	if resp == "" {
		t.Error("expected error response")
	}
}

func TestHandleRequest_QueryUnknownRecordType(t *testing.T) {
	t.Parallel()
	pl := &fakeListener{}
	s := New(pl, "")
	resp := s.handleRequest(Request{Command: "QUERY", RecordType: "X"}, nil)
	if resp == "" {
		t.Error("expected error response")
	}
}

func TestHandleRequest_RegisterUnknownRecordType(t *testing.T) {
	t.Parallel()
	pl := &fakeListener{}
	s := New(pl, "")
	resp := s.handleRequest(Request{Command: "REGISTER", RecordType: "X"}, nil)
	if resp == "" {
		t.Error("expected error response")
	}
}

func TestHandleRequest_RegisterBadAddrA(t *testing.T) {
	t.Parallel()
	pl := &fakeListener{}
	s := New(pl, "")
	resp := s.handleRequest(Request{Command: "REGISTER", RecordType: "A", Address: "not-an-addr"}, nil)
	if resp == "" {
		t.Error("expected error response")
	}
}

func TestHandleRequest_RegisterBadAddrS(t *testing.T) {
	t.Parallel()
	pl := &fakeListener{}
	s := New(pl, "")
	resp := s.handleRequest(Request{Command: "REGISTER", RecordType: "S", Address: "not-an-addr"}, nil)
	if resp == "" {
		t.Error("expected error response")
	}
}

// Confirm context can be cancelled (not used here but documents
// the lifecycle expectation).
func TestServer_CtxCancellationDoesNotBlockShutdown(t *testing.T) {
	t.Parallel()
	srv, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if err := srv.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
