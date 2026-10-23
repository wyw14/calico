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

package syncwatermark_test

import (
	"testing"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncwatermark"
)

func TestParseRevision(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  uint64
		ok    bool
	}{
		{"decimal string", "12345", 12345, true},
		{"uint64", uint64(99), 99, true},
		{"int64", int64(99), 99, true},
		{"int", 99, 99, true},
		{"nil", nil, 0, false},
		{"empty string", "", 0, false},
		{"non-numeric", "abc", 0, false},
		{"negative int", -1, 0, false},
		{"negative string", "-1", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := syncwatermark.ParseRevision(tc.input)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && r.Value() != tc.want {
				t.Fatalf("value = %d, want %d", r.Value(), tc.want)
			}
		})
	}

	lo, _ := syncwatermark.ParseRevision("10")
	hi, _ := syncwatermark.ParseRevision("20")
	if !lo.LessThan(hi) || hi.LessThan(lo) || lo.LessThan(lo) {
		t.Fatal("numeric ordering wrong")
	}
	if !syncwatermark.NoRevision.LessThan(lo) {
		t.Fatal("missing revision should sort below a real revision")
	}
	if syncwatermark.MaxRevision(lo, hi) != hi {
		t.Fatal("MaxRevision should return the higher watermark")
	}
}

func TestRevisionFromUpdatesIncludesDeletions(t *testing.T) {
	updates := []api.Update{
		{
			KVPair:     model.KVPair{Key: model.GlobalConfigKey{Name: "a"}, Value: "v1", Revision: "5"},
			UpdateType: api.UpdateTypeKVNew,
		},
		{
			// A delete carries the revision of the deletion; it must advance the watermark.
			KVPair:     model.KVPair{Key: model.GlobalConfigKey{Name: "a"}, Value: nil, Revision: "7"},
			UpdateType: api.UpdateTypeKVDeleted,
		},
		{
			KVPair:     model.KVPair{Key: model.GlobalConfigKey{Name: "b"}, Value: "v2"},
			UpdateType: api.UpdateTypeKVNew,
		},
	}
	r := syncwatermark.RevisionFromUpdates(updates)
	if !r.IsValid() || r.Value() != 7 {
		t.Fatalf("expected high water 7 including delete, got %v", r)
	}
}

func TestMonitorConnectProgressAndBacklog(t *testing.T) {
	m := syncwatermark.NewMonitor()

	c, oldID, superseded := m.Connect("felix-a", "felix", 100)
	if superseded {
		t.Fatal("first connection should not supersede anything")
	}
	if oldID != 0 {
		t.Fatalf("expected no superseded conn ID, got %d", oldID)
	}

	c.SnapshotSent(50, 5)
	st, ok := m.State("felix-a")
	if !ok {
		t.Fatal("state missing")
	}
	if !st.Active || st.NumConnections != 1 || st.SentRevision != 50 ||
		st.SentSequenceNumber != 5 || st.ConnectionID != 100 {
		t.Fatalf("unexpected state after snapshot: %+v", st)
	}

	// Two delta sends: first still leaves 3 objects outstanding, then the
	// client catches up.
	c.DeltasSent(60, 6, 3)
	if agg := m.Aggregate("felix"); agg.ActiveConnections != 1 || agg.MaxSentRevision != 60 || agg.BacklogObjects != 3 {
		t.Fatalf("unexpected aggregate mid-catch-up: %+v", agg)
	}
	c.DeltasSent(61, 7, 0)
	if agg := m.Aggregate("felix"); agg.BacklogObjects != 0 || agg.MaxSentRevision != 61 {
		t.Fatalf("unexpected aggregate after catch-up: %+v", agg)
	}
	if st, _ = m.State("felix-a"); st.BacklogObjects != 0 || st.SentRevision != 61 {
		t.Fatalf("unexpected per-client state: %+v", st)
	}

	// Progress from a stale (superseded) handle must be ignored.
	if c.Disconnect(syncwatermark.ReasonFellBehind) != true {
		t.Fatal("first disconnect should be recorded")
	}
	if st, _ = m.State("felix-a"); st.Active || st.LastDisconnectReason != syncwatermark.ReasonFellBehind {
		t.Fatalf("unexpected state after disconnect: %+v", st)
	}
	if agg := m.Aggregate("felix"); agg.ActiveConnections != 0 || agg.BacklogObjects != 0 {
		t.Fatalf("aggregate not reset: %+v", agg)
	}
}

func TestMonitorReconnectSupersedesOldConnection(t *testing.T) {
	m := syncwatermark.NewMonitor()

	c1, _, _ := m.Connect("felix-a", "felix", 1)
	c1.DeltasSent(10, 1, 4)

	c2, oldID, superseded := m.Connect("felix-a", "felix", 2)
	if !superseded || oldID != 1 {
		t.Fatalf("second connection should supersede conn 1, got oldID=%d superseded=%v", oldID, superseded)
	}
	st, _ := m.State("felix-a")
	if !st.Active || st.ConnectionID != 2 || st.NumConnections != 2 {
		t.Fatalf("new connection should own the record: %+v", st)
	}
	if st.LastDisconnectReason != syncwatermark.ReasonSuperseded || st.LastReconnectAt.IsZero() {
		t.Fatalf("reconnect bookkeeping wrong: %+v", st)
	}
	// The syncer-wide backlog belongs to the dead connection; the fresh
	// connection starts with no outstanding objects.
	if agg := m.Aggregate("felix"); agg.BacklogObjects != 0 || agg.ActiveConnections != 1 {
		t.Fatalf("superseded backlog not drained from aggregate: %+v", agg)
	}

	// When the old handler finally exits, its disconnect must not overwrite
	// the supersede reason or touch the new connection's state.
	if c1.Disconnect(syncwatermark.ReasonWriteFailed) {
		t.Fatal("superseded connection disconnect must be ignored")
	}
	st, _ = m.State("felix-a")
	if !st.Active || st.ConnectionID != 2 || st.LastDisconnectReason != syncwatermark.ReasonSuperseded {
		t.Fatalf("dying old connection corrupted the record: %+v", st)
	}

	c2.SnapshotSent(12, 3)
	if st, _ = m.State("felix-a"); st.SentRevision != 12 {
		t.Fatalf("new connection progress not recorded: %+v", st)
	}
}

func TestMonitorStatesAreIndependentPerClient(t *testing.T) {
	m := syncwatermark.NewMonitor()
	c1, _, _ := m.Connect("felix-a", "felix", 1)
	c2, _, _ := m.Connect("felix-b", "felix", 2)
	c1.DeltasSent(100, 1, 0)
	c2.DeltasSent(50, 1, 0)
	c1.Disconnect(syncwatermark.ReasonPongTimeout)

	states := m.States()
	if len(states) != 2 || states[0].ClientID != "felix-a" || states[1].ClientID != "felix-b" {
		t.Fatalf("states should be sorted by client ID, got %+v", states)
	}
	if states[0].SentRevision != 100 || !states[1].Active || states[1].SentRevision != 50 {
		t.Fatalf("client watermarks should be independent, got %+v", states)
	}
	if states[0].LastDisconnectReason != syncwatermark.ReasonPongTimeout {
		t.Fatalf("disconnect reason not recorded: %+v", states[0])
	}
}
