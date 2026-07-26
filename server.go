// SPDX-License-Identifier: AGPL-3.0-or-later

package nameserver

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/protocol"
)

// StrictRegisterEnv names the environment variable that turns on strict
// REGISTER handling. It is off unless the value is "1" or "true".
//
// With strict handling on:
//   - every REGISTER must arrive on a connection whose remote address
//     resolves to a non-zero node ID;
//   - N records are bound to the node that registered them, and a later
//     REGISTER N for the same name from a different node is refused.
//
// With it off (the default) the server keeps its previous behaviour:
// unresolvable callers are accepted and N records may be overwritten by
// any caller.
const StrictRegisterEnv = "PILOT_NAMESERVER_STRICT_REGISTER"

// PortListener abstracts the ability to listen on a Pilot overlay port.
// Satisfied by *driver.Driver (via a thin wrapper in cmd/nameserver).
type PortListener interface {
	Listen(port uint16) (net.Listener, error)
}

// Server is the Pilot Protocol nameserver. It runs on the overlay
// network itself, listening on port 53.
//
// Trust boundary note: the nameserver responds to DNS queries from any registered
// node without trust gating. This is intentional — DNS is a public lookup service
// (like real-world DNS), and hostname→address mappings are not considered private.
// Private nodes are protected at the resolve/connect layer, not at name resolution.
type Server struct {
	store    *RecordStore
	listener PortListener
	ln       net.Listener
	ready    chan struct{}
	strict   atomic.Bool
}

// New creates a nameserver backed by a fresh record store.
// If storePath is non-empty, records are persisted to that file.
func New(pl PortListener, storePath string) *Server {
	store := NewRecordStore()
	if storePath != "" {
		store.SetStorePath(storePath)
	}
	s := &Server{
		store:    store,
		listener: pl,
		ready:    make(chan struct{}),
	}
	s.strict.Store(strictRegisterFromEnv())
	return s
}

// strictRegisterFromEnv reads StrictRegisterEnv. Anything other than
// "1"/"true" (case-insensitive) leaves strict handling off.
func strictRegisterFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(StrictRegisterEnv))) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// SetStrictRegister turns strict REGISTER handling on or off at runtime,
// overriding whatever StrictRegisterEnv selected at construction.
func (s *Server) SetStrictRegister(on bool) { s.strict.Store(on) }

// StrictRegister reports whether strict REGISTER handling is on.
func (s *Server) StrictRegister() bool { return s.strict.Load() }

// Ready returns a channel that is closed once the server is listening.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// Store returns the underlying record store for external manipulation.
func (s *Server) Store() *RecordStore {
	return s.store
}

// ListenAndServe listens on Pilot port 53 and handles name queries.
func (s *Server) ListenAndServe() error {
	ln, err := s.listener.Listen(protocol.PortNameserver)
	if err != nil {
		return fmt.Errorf("listen port %d: %w", protocol.PortNameserver, err)
	}
	s.ln = ln
	close(s.ready)
	slog.Info("nameserver listening", "port", protocol.PortNameserver)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// Close shuts down the nameserver.
func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	// L11 panic boundary: tear down THIS conn only.
	// TODO(03-INVARIANTS.md §8): the standalone nameserver binary has
	// no event bus today; once the plugin is wired into cmd/daemon's
	// plugin runtime, thread the bus through here.
	defer coreapi.RecoverPlugin("nameserver", "handleConn", nil, nil)
	defer conn.Close()

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	line := string(buf[:n])
	req, err := ParseRequest(line)
	if err != nil {
		_, _ = conn.Write([]byte(FormatResponseErr(err.Error())))
		return
	}

	resp := s.handleRequest(req, conn.RemoteAddr())
	_, _ = conn.Write([]byte(resp))
}

func (s *Server) handleRequest(req Request, remoteAddr net.Addr) string {
	switch req.Command {
	case "QUERY":
		return s.handleQuery(req)
	case "REGISTER":
		return s.handleRegister(req, remoteAddr)
	default:
		return FormatResponseErr("unknown command: " + req.Command)
	}
}

func (s *Server) handleQuery(req Request) string {
	switch req.RecordType {
	case RecordA:
		addr, err := s.store.LookupA(req.Name)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		return FormatResponseA(req.Name, addr)

	case RecordN:
		netID, err := s.store.LookupN(req.Name)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		return FormatResponseN(req.Name, netID)

	case RecordS:
		entries := s.store.LookupS(req.NetID, req.Port)
		return FormatResponseS(entries)

	default:
		return FormatResponseErr("unknown record type: " + req.RecordType)
	}
}

func (s *Server) handleRegister(req Request, remoteAddr net.Addr) string {
	// Reject excessively long names to prevent memory DoS.
	if len(req.Name) > MaxNameLength {
		return FormatResponseErr(fmt.Sprintf("name too long: %d bytes (max %d)", len(req.Name), MaxNameLength))
	}

	strict := s.strict.Load()

	// Extract caller's node ID from RemoteAddr for source validation.
	callerNode := extractCallerNode(remoteAddr)
	if strict {
		node, ok := resolveCallerNode(remoteAddr)
		if !ok {
			return FormatResponseErr("caller node identity required")
		}
		callerNode = node
	}

	switch req.RecordType {
	case RecordA:
		addr, err := protocol.ParseAddr(req.Address)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		// Validate: caller can only register addresses for their own node
		if callerNode != 0 && addr.Node != callerNode {
			return FormatResponseErr("cannot register address for another node")
		}
		s.store.RegisterA(req.Name, addr)
		slog.Debug("nameserver registered A record", "name", req.Name, "addr", addr)
		return FormatResponseOK()

	case RecordN:
		// The owning node is always recorded; it is only enforced against
		// a later registrant when strict handling is on.
		if !s.store.RegisterNOwned(req.Name, req.NetID, callerNode, strict) {
			return FormatResponseErr("network name registered by another node")
		}
		slog.Debug("nameserver registered N record", "name", req.Name, "network_id", req.NetID, "node", callerNode)
		return FormatResponseOK()

	case RecordS:
		addr, err := protocol.ParseAddr(req.Address)
		if err != nil {
			return FormatResponseErr(err.Error())
		}
		// Validate: caller can only register services for their own node
		if callerNode != 0 && addr.Node != callerNode {
			return FormatResponseErr("cannot register service for another node")
		}
		s.store.RegisterS(req.Name, addr, req.NetID, req.Port)
		slog.Debug("nameserver registered S record", "name", req.Name, "addr", addr, "port", req.Port, "network_id", req.NetID)
		return FormatResponseOK()

	default:
		return FormatResponseErr("unknown record type: " + req.RecordType)
	}
}

// extractCallerNode gets the node ID from a driver.Conn RemoteAddr().
// RemoteAddr format: "N:NNNN.HHHH.LLLL:port" — we parse the address part.
func extractCallerNode(addr net.Addr) uint32 {
	if addr == nil {
		return 0
	}
	s := addr.String()
	// driver.Conn.RemoteAddr returns "addr:port"
	// Try to parse the address portion
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	pilotAddr, err := protocol.ParseAddr(host)
	if err != nil {
		return 0
	}
	return pilotAddr.Node
}

// resolveCallerNode returns the node ID carried by a remote address, and
// whether one could be determined at all.
//
// A Pilot address renders as "<network>:<hex>.<hex>.<hex>", so the
// "<address>:<port>" string reported by the overlay connection adapter
// contains two colons and is not a host:port pair net.SplitHostPort can
// split. Each plausible substring is tried in turn: the whole string, the
// host part when the string really is host:port (the bracketed form), and
// the string with a trailing ":<port>" removed.
//
// A node ID of 0 is reported as unresolved: it is the zero value used
// throughout this package to mean "no caller identity".
func resolveCallerNode(addr net.Addr) (uint32, bool) {
	if addr == nil {
		return 0, false
	}
	s := strings.TrimSpace(addr.String())
	if s == "" {
		return 0, false
	}

	candidates := []string{s}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		candidates = append(candidates, host)
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		candidates = append(candidates, s[:i])
	}

	for _, c := range candidates {
		pilotAddr, err := protocol.ParseAddr(c)
		if err != nil {
			continue
		}
		if pilotAddr.Node == 0 {
			return 0, false
		}
		return pilotAddr.Node, true
	}
	return 0, false
}
