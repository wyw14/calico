// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package syncwatermark tracks the datastore-revision watermark of an
// incremental sync stream on a per-client basis.
//
// The backend datastore (Kubernetes API or etcd) assigns every update a
// monotonically increasing, decimal revision.  A fan-out proxy such as
// Typha serves many clients from one upstream stream, so it needs to know,
// per client, how far through the revision space the client has progressed,
// how many updates it still has outstanding, and why its previous
// connection ended.  Both the proxy (server side) and the consumer (Felix's
// calc graph, client side) record those numbers through the types below.
package syncwatermark

import (
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
)

// Revision is a comparable datastore revision.  Backends report revisions
// as decimal strings (Kubernetes resource versions, etcd v3 revisions) or
// as integers (etcd v2); zero value / NoRevision means "no revision has
// been observed", which sorts below every real revision.
type Revision struct {
	value uint64
	valid bool
}

// NoRevision is the zero Revision; it compares lower than any parsed
// revision.
var NoRevision Revision

// ParseRevision parses a revision as carried on a model.KVPair (a string)
// or on a syncproto.SerializedUpdate (an any).  It accepts nil, decimal
// strings and signed/unsigned integer kinds.  Empty, negative or
// non-numeric values are not valid datastore revisions and report ok=false
// rather than being treated as revision 0.
func ParseRevision(v any) (Revision, bool) {
	switch r := v.(type) {
	case nil:
		return NoRevision, false
	case string:
		return parseRevisionString(r)
	case []byte:
		return parseRevisionString(string(r))
	case uint64:
		return Revision{value: r, valid: true}, true
	case uint:
		return Revision{value: uint64(r), valid: true}, true
	case int64:
		if r < 0 {
			return NoRevision, false
		}
		return Revision{value: uint64(r), valid: true}, true
	case int:
		if r < 0 {
			return NoRevision, false
		}
		return Revision{value: uint64(r), valid: true}, true
	default:
		return parseRevisionString(fmt.Sprint(r))
	}
}

func parseRevisionString(s string) (Revision, bool) {
	if s == "" {
		return NoRevision, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return NoRevision, false
	}
	return Revision{value: n, valid: true}, true
}

// IsValid reports whether a real revision was observed.
func (r Revision) IsValid() bool { return r.valid }

// Value returns the numeric revision, or 0 when no revision was observed.
func (r Revision) Value() uint64 { return r.value }

// LessThan reports whether this revision is strictly behind other.  An
// invalid revision is behind any valid revision; two invalid revisions
// are equal.
func (r Revision) LessThan(other Revision) bool {
	switch {
	case r.valid && other.valid:
		return r.value < other.value
	case !r.valid && other.valid:
		return true
	default:
		return false
	}
}

func (r Revision) String() string {
	if !r.valid {
		return "<none>"
	}
	return strconv.FormatUint(r.value, 10)
}

// MaxRevision returns the higher-water-mark of the two revisions.
func MaxRevision(a, b Revision) Revision {
	if a.LessThan(b) {
		return b
	}
	return a
}

// RevisionFromUpdates returns the highest valid revision carried by the
// given updates, including deletions (a delete carries the revision at
// which the object was deleted).  It returns NoRevision if none of the
// updates carry a parseable revision.
func RevisionFromUpdates(updates []api.Update) Revision {
	high := NoRevision
	for i := range updates {
		if r, ok := ParseRevision(updates[i].Revision); ok {
			high = MaxRevision(high, r)
		}
	}
	return high
}

// DisconnectReason classifies why a client connection ended.  Values are
// part of the monitoring contract and are used as Prometheus label
// values, so they must stay short, lowercase and hyphen-separated.
type DisconnectReason string

const (
	// ReasonUnknown is the placeholder for a connection that ended without
	// a recorded cause.
	ReasonUnknown DisconnectReason = "unknown"
	// ReasonClientClosed means the peer closed or half-closed the
	// connection, or sent data we could not parse as our protocol.
	ReasonClientClosed DisconnectReason = "client-closed"
	// ReasonHandshakeFailed means the connection ended during the initial
	// handshake (timeout, bad hello, unsupported feature).
	ReasonHandshakeFailed DisconnectReason = "handshake-failed"
	// ReasonWriteFailed means a write to the client failed, including a
	// failure to send the initial snapshot.
	ReasonWriteFailed DisconnectReason = "write-failed"
	// ReasonPongTimeout means the client stopped answering pings in time.
	ReasonPongTimeout DisconnectReason = "pong-timeout"
	// ReasonFellBehind means the client lagged the live stream by more
	// than the configured age limit (after any grace period).
	ReasonFellBehind DisconnectReason = "fell-behind"
	// ReasonBacklogOverflow means the client had more outstanding delta
	// objects queued than the configured object bound permits.
	ReasonBacklogOverflow DisconnectReason = "backlog-overflow"
	// ReasonSuperseded means a newer connection for the same client ID
	// replaced this one.
	ReasonSuperseded DisconnectReason = "superseded"
	// ReasonServerShutdown means the server (or its connection governor)
	// canceled the connection.
	ReasonServerShutdown DisconnectReason = "server-shutdown"
)

// AllDisconnectReasons lists every reason; it is used to pre-create
// Prometheus label combinations.
var AllDisconnectReasons = []DisconnectReason{
	ReasonUnknown,
	ReasonClientClosed,
	ReasonHandshakeFailed,
	ReasonWriteFailed,
	ReasonPongTimeout,
	ReasonFellBehind,
	ReasonBacklogOverflow,
	ReasonSuperseded,
	ReasonServerShutdown,
}

// ClientState is a point-in-time view of one client's sync watermark.
type ClientState struct {
	// Syncer is the syncer type the client negotiated (e.g. "felix").
	Syncer string
	// ClientID identifies the client across its connections (its
	// hostname).  Watermark history is kept under this ID so a reconnected
	// client extends the same record rather than starting a new one.
	ClientID string
	// ConnectionID is the server-local ID of the current connection.
	ConnectionID uint64
	// Active reports whether the current connection is still streaming.
	Active bool
	// NumConnections is the number of connections this client has opened
	// against the server, including the current one.
	NumConnections uint64

	// SentRevision is the highest datastore revision the server has sent
	// to the current connection (snapshot and deltas combined).
	SentRevision uint64
	// SentSequenceNumber is the breadcrumb sequence number the current
	// connection has reached.
	SentSequenceNumber uint64
	// BacklogObjects is the number of delta objects the current connection
	// still owed the client at the last send.
	BacklogObjects int

	ConnectedAt          time.Time
	LastReconnectAt      time.Time
	LastDisconnectAt     time.Time
	LastDisconnectReason DisconnectReason
}

// Aggregate is the syncer-scoped roll-up of the per-client watermarks.
type Aggregate struct {
	Syncer            string
	ActiveConnections int
	// MaxSentRevision is the highest revision any connection for this
	// syncer has reached.
	MaxSentRevision uint64
	// BacklogObjects is the sum of the outstanding delta counts across
	// active connections.
	BacklogObjects int
}

// Monitor keeps the per-client watermark records for a server.  Its
// methods are safe for concurrent use.
type Monitor struct {
	mu sync.Mutex

	clients map[string]*clientWatermark
	aggs    map[string]*syncerAggregate
}

// NewMonitor returns an empty Monitor.
func NewMonitor() *Monitor {
	return &Monitor{
		clients: map[string]*clientWatermark{},
		aggs:    map[string]*syncerAggregate{},
	}
}

type syncerAggregate struct {
	activeConns    int
	maxSentRev     uint64
	backlogObjects int
}

type clientWatermark struct {
	syncer   string
	clientID string

	current *connState

	numConnections       uint64
	lastReconnectAt      time.Time
	lastDisconnectAt     time.Time
	lastDisconnectReason DisconnectReason
}

type connState struct {
	monitor *Monitor

	syncer   string
	clientID string
	connID   uint64

	active       bool
	connectedAt  time.Time
	sentRevision uint64
	sentSequence uint64
	backlog      int

	disconnectReason DisconnectReason
	disconnectedAt   time.Time
}

// Conn is the handle one connection uses to report its progress.  Its
// methods are safe for concurrent use.
type Conn struct {
	monitor *Monitor
	state   *connState
}

// Connect registers a new connection for the given client.  If the client
// already has an active connection it is marked as superseded (and
// supersededConnID reports its ID) so the caller can tear the old
// connection down; the new connection then owns the client's record.
//
// The supersede happens before any snapshot is sent on the new connection,
// so the old stream cannot interleave with the new one.
func (m *Monitor) Connect(clientID, syncer string, connID uint64) (c Conn, supersededConnID uint64, superseded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cw := m.clients[clientID]
	if cw == nil {
		cw = &clientWatermark{clientID: clientID}
		m.clients[clientID] = cw
	}
	cw.syncer = syncer

	if cw.current != nil && cw.current.active {
		old := cw.current
		old.active = false
		old.disconnectReason = ReasonSuperseded
		old.disconnectedAt = time.Now()
		cw.lastDisconnectReason = ReasonSuperseded
		cw.lastDisconnectAt = old.disconnectedAt
		supersededConnID = old.connID
		superseded = true

		oldAgg := m.aggFor(old.syncer)
		oldAgg.activeConns--
		oldAgg.backlogObjects -= old.backlog
		old.backlog = 0
	}

	cw.numConnections++
	now := time.Now()
	if cw.current != nil {
		// Anything but the very first connection is a reconnection.
		cw.lastReconnectAt = now
	}

	state := &connState{
		monitor:     m,
		syncer:      syncer,
		clientID:    clientID,
		connID:      connID,
		active:      true,
		connectedAt: now,
	}
	cw.current = state

	agg := m.aggFor(syncer)
	agg.activeConns++

	return Conn{monitor: m, state: state}, supersededConnID, superseded
}

// SnapshotSent records that the connection finished sending an initial (or
// resync) snapshot at the given breadcrumb.
func (c Conn) SnapshotSent(highWaterRevision, sequenceNumber uint64) {
	if c.state == nil {
		return
	}
	m := c.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	s := c.state
	if !s.active {
		return
	}
	// The snapshot is the authoritative starting point; adjust the
	// syncer-wide backlog down because the connection starts from zero.
	agg := m.aggFor(s.syncer)
	agg.backlogObjects -= s.backlog
	s.backlog = 0
	if highWaterRevision > s.sentRevision {
		s.sentRevision = highWaterRevision
	}
	if highWaterRevision > agg.maxSentRev {
		agg.maxSentRev = highWaterRevision
	}
	s.sentSequence = sequenceNumber
}

// DeltasSent records progress after a batch of deltas was sent.
// backlogObjects is the number of delta objects still outstanding for the
// connection after the batch.
func (c Conn) DeltasSent(highWaterRevision, sequenceNumber uint64, backlogObjects int) {
	if c.state == nil {
		return
	}
	if backlogObjects < 0 {
		backlogObjects = 0
	}
	m := c.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	s := c.state
	if !s.active {
		return
	}
	agg := m.aggFor(s.syncer)
	agg.backlogObjects += backlogObjects - s.backlog
	s.backlog = backlogObjects
	if highWaterRevision > s.sentRevision {
		s.sentRevision = highWaterRevision
	}
	if highWaterRevision > agg.maxSentRev {
		agg.maxSentRev = highWaterRevision
	}
	s.sentSequence = sequenceNumber
}

// Disconnect closes the connection's record.  A connection that was
// superseded by a newer one has already had its end state recorded, so a
// later Disconnect from its dying handler is ignored: the supersede is
// the cause that matters.
//
// It returns true if this call recorded the disconnect (and the caller is
// responsible for counting it in metrics).
func (c Conn) Disconnect(reason DisconnectReason) bool {
	if c.state == nil {
		return false
	}
	m := c.monitor
	m.mu.Lock()
	defer m.mu.Unlock()
	s := c.state
	if !s.active {
		return false
	}
	s.active = false
	if reason == "" {
		reason = ReasonUnknown
	}
	s.disconnectReason = reason
	s.disconnectedAt = time.Now()

	agg := m.aggFor(s.syncer)
	agg.activeConns--
	agg.backlogObjects -= s.backlog
	s.backlog = 0

	cw := m.clients[s.clientID]
	if cw != nil && cw.current == s {
		cw.lastDisconnectReason = reason
		cw.lastDisconnectAt = s.disconnectedAt
	}
	return true
}

func (m *Monitor) aggFor(syncer string) *syncerAggregate {
	agg := m.aggs[syncer]
	if agg == nil {
		agg = &syncerAggregate{}
		m.aggs[syncer] = agg
	}
	return agg
}

// State returns the current view of one client.
func (m *Monitor) State(clientID string) (ClientState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cw := m.clients[clientID]
	if cw == nil {
		return ClientState{}, false
	}
	return cw.snapshot(cw.current), true
}

// States returns the current view of every known client, ordered by
// client ID for deterministic output.
func (m *Monitor) States() []ClientState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]ClientState, 0, len(m.clients))
	for _, cw := range m.clients {
		out = append(out, cw.snapshot(cw.current))
	}
	slices.SortFunc(out, func(a, b ClientState) int {
		if a.ClientID < b.ClientID {
			return -1
		} else if a.ClientID > b.ClientID {
			return 1
		}
		return 0
	})
	return out
}

func (cw *clientWatermark) snapshot(s *connState) ClientState {
	st := ClientState{
		Syncer:               cw.syncer,
		ClientID:             cw.clientID,
		NumConnections:       cw.numConnections,
		LastReconnectAt:      cw.lastReconnectAt,
		LastDisconnectAt:     cw.lastDisconnectAt,
		LastDisconnectReason: cw.lastDisconnectReason,
	}
	if s != nil {
		st.ConnectionID = s.connID
		st.Active = s.active
		st.SentRevision = s.sentRevision
		st.SentSequenceNumber = s.sentSequence
		st.BacklogObjects = s.backlog
		st.ConnectedAt = s.connectedAt
		if !s.active {
			st.LastDisconnectReason = s.disconnectReason
			st.LastDisconnectAt = s.disconnectedAt
		}
	}
	return st
}

// Aggregate returns the syncer-scoped roll-up.
func (m *Monitor) Aggregate(syncer string) Aggregate {
	m.mu.Lock()
	defer m.mu.Unlock()
	agg := m.aggs[syncer]
	out := Aggregate{Syncer: syncer}
	if agg != nil {
		out.ActiveConnections = agg.activeConns
		out.MaxSentRevision = agg.maxSentRev
		out.BacklogObjects = agg.backlogObjects
	}
	return out
}
