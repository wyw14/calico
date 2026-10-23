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

package fvtests_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/lib/logrusr"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/dedupebuffer"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncwatermark"
	fvtests "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
)

func registerFV(t *testing.T) {
	t.Helper()
	RegisterTestingT(t)
	logrusr.RedirectLogrusToTestingT(t)
}

// waitForWatermark polls the monitor until the named client satisfies
// pred, failing with the last observed state.
func waitForWatermark(
	t *testing.T,
	mon *syncwatermark.Monitor,
	clientID string,
	pred func(syncwatermark.ClientState) error,
) syncwatermark.ClientState {
	t.Helper()
	var last syncwatermark.ClientState
	Eventually(func() error {
		var ok bool
		last, ok = mon.State(clientID)
		if !ok {
			return fmt.Errorf("no watermark recorded for %q", clientID)
		}
		return pred(last)
	}, 30*time.Second, 20*time.Millisecond).Should(Succeed(), func() string {
		return fmt.Sprintf("last watermark for %q: %+v", clientID, last)
	})
	return last
}

func expectActiveAt(st *syncwatermark.ClientState, revision uint64) error {
	if !st.Active {
		return fmt.Errorf("client not active: %+v", st)
	}
	if st.SentRevision < revision {
		return fmt.Errorf("sent revision %d < %d", st.SentRevision, revision)
	}
	if st.BacklogObjects != 0 {
		return fmt.Errorf("expected drained backlog, got %d", st.BacklogObjects)
	}
	return nil
}

// TestWatermarkRevisionBacklogAndDeletion drives one client through an
// initial snapshot, a delete and further deltas, asserting the per-client
// watermark tracks sent revision and drains its backlog.
func TestWatermarkRevisionBacklogAndDeletion(t *testing.T) {
	registerFV(t)
	h := NewHarness()
	t.Cleanup(h.Stop)
	h.Start()

	// 25 configs => revisions 0..24.
	h.SendInitialSnapshotConfigs(25)
	client := h.CreateClient(0, syncproto.SyncerTypeFelix)
	Eventually(client.recorder.Len, 10*time.Second).Should(Equal(25))
	Eventually(client.recorder.Status).Should(Equal(api.InSync))

	mon := h.Server.WatermarkMonitor()
	st := waitForWatermark(t, mon, "test-host-0", func(st syncwatermark.ClientState) error {
		if !st.Active || st.NumConnections != 1 {
			return fmt.Errorf("unexpected connection state: %+v", st)
		}
		return expectActiveAt(&st, 24)
	})
	Expect(st.SentRevision).To(Equal(uint64(24)))

	// Delete foo0 at a higher revision; the client must converge and the
	// watermark must advance even though the object disappeared.
	path, err := model.KeyToDefaultPath(model.GlobalConfigKey{Name: "foo0"})
	Expect(err).NotTo(HaveOccurred())
	h.SendConfigDeletion("foo0", "100")
	Eventually(client.recorder.Len, 10*time.Second).Should(Equal(24))
	Eventually(func() bool {
		_, ok := client.recorder.KVs()[path]
		return ok
	}, 5*time.Second).Should(BeFalse())
	waitForWatermark(t, mon, "test-host-0", func(st syncwatermark.ClientState) error {
		return expectActiveAt(&st, 100)
	})
}

// TestWatermarkMultiClient checks each connected client gets an
// independent watermark record that advances with the stream.
func TestWatermarkMultiClient(t *testing.T) {
	registerFV(t)
	h := NewHarness()
	t.Cleanup(h.Stop)
	h.Start()

	initial := h.SendInitialSnapshotConfigs(10) // revisions 0..9
	h.CreateClients(3)
	h.ExpectAllClientsToReachState(api.InSync, initial)

	mon := h.Server.WatermarkMonitor()
	for i := range 3 {
		clientID := fmt.Sprintf("test-host-%d", i)
		waitForWatermark(t, mon, clientID, func(st syncwatermark.ClientState) error {
			if !st.Active || st.NumConnections != 1 {
				return fmt.Errorf("unexpected connection state: %+v", st)
			}
			if st.SentRevision != 9 || st.BacklogObjects != 0 {
				return fmt.Errorf("unexpected watermark: %+v", st)
			}
			return nil
		})
	}

	more := h.SendConfigUpdates(5) // revisions 10..14
	expected := initial
	for k, v := range more {
		expected[k] = v
	}
	h.ExpectAllClientsToReachState(api.InSync, expected)
	for i := range 3 {
		waitForWatermark(t, mon, fmt.Sprintf("test-host-%d", i), func(st syncwatermark.ClientState) error {
			return expectActiveAt(&st, 14)
		})
	}

	// Only the three felix clients are tracked, independently.
	Expect(mon.States()).To(HaveLen(3))
}

// gatingCallbacks forwards to a recorder but blocks OnUpdates once armed,
// simulating a client that has stopped draining its socket.
type gatingCallbacks struct {
	recorder *fvtests.StateRecorder
	gateCtx  context.Context
	armed    atomic.Bool
}

func (g *gatingCallbacks) OnStatusUpdated(status api.SyncStatus) {
	g.recorder.OnStatusUpdated(status)
}

func (g *gatingCallbacks) OnUpdates(updates []api.Update) {
	g.recorder.OnUpdates(updates)
	if g.armed.Load() {
		<-g.gateCtx.Done()
	}
}

// TestWatermarkSlowClientBoundedFlow pins the object bound low and blocks
// the only client mid-stream: its connection must be dropped with reason
// backlog-overflow rather than buffering an unbounded delta log.
func TestWatermarkSlowClientBoundedFlow(t *testing.T) {
	registerFV(t)
	h := NewHarness()

	// One delta per breadcrumb makes the outstanding object count exact.
	h.FelixCache = snapcache.New(snapcache.Config{
		MaxBatchSize:   1,
		WakeUpInterval: 50 * time.Millisecond,
	})
	h.ValFilter = calc.NewValidationFilter(h.FelixCache)
	h.Config.MaxBacklogObjects = 5
	// Coalesce the whole burst into one batch so the backlog is measured
	// before it is fragmented into small, easily buffered writes.
	h.Config.MaxMessageSize = 100000
	// Time-based fall-behind must not beat the object bound.
	h.Config.MaxFallBehind = 10 * time.Minute
	// Fail a stalled write promptly so the over-bound batch attributes the
	// disconnect to the backlog rather than waiting for the default timeout.
	h.Config.WriteTimeout = 1500 * time.Millisecond
	h.Config.WriteBufferSize = 4096
	t.Cleanup(h.Stop)
	h.Start()

	h.SendInitialSnapshotConfigs(3)

	recorder := fvtests.NewRecorder()
	recCtx, recCancel := context.WithCancel(context.Background())
	t.Cleanup(recCancel)
	go recorder.Loop(recCtx)
	gateCtx, gateCancel := context.WithCancel(context.Background())
	t.Cleanup(gateCancel) // Runs before h.Stop so the blocked client can finish.
	gating := &gatingCallbacks{recorder: recorder, gateCtx: gateCtx}
	h.CreateClientWithCallbacks(0, "slow-host", syncclient.Options{
		SyncerType:     syncproto.SyncerTypeFelix,
		ReadBufferSize: 4096,
	}, gating)

	Eventually(recorder.Len, 10*time.Second).Should(Equal(3))
	Eventually(recorder.Status).Should(Equal(api.InSync))

	// Freeze the consumer, then publish a large burst of one-delta
	// breadcrumbs (~10MB of incompressible values).  Loopback buffers can
	// absorb a few MB even with the socket buffers pinned small, so the
	// giant coalesced write must stall long enough to hit the deadline with
	// an over-bound backlog.
	gating.armed.Store(true)
	pushDone := make(chan struct{})
	go func() {
		defer close(pushDone)
		h.SendConfigUpdates(10000)
	}()

	mon := h.Server.WatermarkMonitor()
	st := waitForWatermark(t, mon, "slow-host", func(st syncwatermark.ClientState) error {
		if st.Active {
			return fmt.Errorf("slow client still active: %+v", st)
		}
		if st.LastDisconnectReason != syncwatermark.ReasonBacklogOverflow {
			return fmt.Errorf("disconnect reason = %q, want %q",
				st.LastDisconnectReason, syncwatermark.ReasonBacklogOverflow)
		}
		return nil
	})
	// Drain the upstream feeder before the harness stops so no sender is
	// blocked on a canceled decoupler channel.
	Eventually(pushDone, 60*time.Second).Should(BeClosed())
	Expect(st.NumConnections).To(Equal(uint64(1)))
	Expect(st.LastDisconnectAt).NotTo(BeZero())
}

// TestWatermarkReconnectReason kills the client's connection server side
// and checks the reconnect is recorded (connection count, server-shutdown
// reason) and the fresh snapshot reconciles state without old/new objects
// crossing.
func TestWatermarkReconnectReason(t *testing.T) {
	registerFV(t)
	h := NewHarness()
	t.Cleanup(h.Stop)
	h.Start()

	initial := h.SendInitialSnapshotConfigs(5) // revisions 0..4

	recorder := fvtests.NewRecorder()
	deduper := dedupebuffer.New()
	client := syncclient.New(
		discovery.New(discovery.WithAddrOverride(h.Addr())),
		"test-version", "reconnect-host", "test-info",
		deduper,
		&syncclient.Options{SyncerType: syncproto.SyncerTypeFelix},
	)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go deduper.SendToSinkForever(recorder)
	t.Cleanup(deduper.Stop)
	recCtx, recCancel := context.WithCancel(context.Background())
	t.Cleanup(recCancel)
	go recorder.Loop(recCtx)
	Expect(client.Start(ctx)).NotTo(HaveOccurred())
	t.Cleanup(func() {
		cancel()
		client.Finished.Wait()
	})

	Eventually(recorder.Len, 10*time.Second).Should(Equal(5))
	Eventually(recorder.Status).Should(Equal(api.InSync))

	mon := h.Server.WatermarkMonitor()
	waitForWatermark(t, mon, "reconnect-host", func(st syncwatermark.ClientState) error {
		return expectActiveAt(&st, 4)
	})

	// Publish updates immediately around the disconnect; whichever side of
	// the reconnect they land on, the fresh snapshot must reconcile them.
	more := h.SendConfigUpdates(3) // revisions 5..7
	h.Server.TerminateRandomConnection(logrus.WithField("test", t.Name()), "watermark reconnect test")

	waitForWatermark(t, mon, "reconnect-host", func(st syncwatermark.ClientState) error {
		if !st.Active || st.NumConnections < 2 {
			return fmt.Errorf("reconnect not observed: %+v", st)
		}
		if st.LastDisconnectReason != syncwatermark.ReasonServerShutdown {
			return fmt.Errorf("reason = %q, want %q",
				st.LastDisconnectReason, syncwatermark.ReasonServerShutdown)
		}
		return expectActiveAt(&st, 7)
	})

	// All eight values converge exactly once, and the reconnect snapshot
	// types the already-seen keys as updates; compare values to stay robust
	// to that.
	expected := initial
	for k, v := range more {
		expected[k] = v
	}
	Eventually(func() map[string]any {
		values := map[string]any{}
		for k, u := range recorder.KVs() {
			values[k] = u.Value
		}
		return values
	}, 15*time.Second).Should(Equal(valueMap(expected)))
	Eventually(recorder.Status).Should(Equal(api.InSync))
}

// TestWatermarkSupersede connects a second client under the same client ID
// while the first is alive: the first must be dropped as superseded and the
// new stream must own the record without interleaving.
func TestWatermarkSupersede(t *testing.T) {
	registerFV(t)
	h := NewHarness()
	t.Cleanup(h.Stop)
	h.Start()

	h.SendInitialSnapshotConfigs(5)
	clientA := h.CreateClientWithHostname(0, "same-host", syncproto.SyncerTypeFelix)
	Eventually(clientA.recorder.Len, 10*time.Second).Should(Equal(5))
	Eventually(clientA.recorder.Status).Should(Equal(api.InSync))

	// Second connection under the same hostname replaces the first.  Plain
	// recorders are not restart-aware, so the first client exits rather than
	// dueling with the second.
	clientB := h.CreateClientWithHostname(1, "same-host", syncproto.SyncerTypeFelix)
	Eventually(clientB.recorder.Len, 10*time.Second).Should(Equal(5))

	mon := h.Server.WatermarkMonitor()
	waitForWatermark(t, mon, "same-host", func(st syncwatermark.ClientState) error {
		if !st.Active || st.NumConnections != 2 {
			return fmt.Errorf("new connection did not take over: %+v", st)
		}
		if st.LastDisconnectReason != syncwatermark.ReasonSuperseded {
			return fmt.Errorf("reason = %q, want %q", st.LastDisconnectReason, syncwatermark.ReasonSuperseded)
		}
		return nil
	})
	// Client A's background goroutines wind down (it is not restart-aware).
	Eventually(h.ClientFinished(clientA), 10*time.Second).Should(BeClosed())

	// Later updates flow only to B; A's view is frozen and B advances.
	more := h.SendConfigUpdates(1) // revision 5
	Eventually(clientB.recorder.Len, 10*time.Second).Should(Equal(6))
	Consistently(clientA.recorder.Len, 500*time.Millisecond).Should(Equal(5))
	waitForWatermark(t, mon, "same-host", func(st syncwatermark.ClientState) error {
		if !st.Active {
			return fmt.Errorf("connection inactive: %+v", st)
		}
		return expectActiveAt(&st, 5)
	})
	Expect(more).To(HaveLen(1))
}

func valueMap(kvs map[string]api.Update) map[string]any {
	out := make(map[string]any, len(kvs))
	for k, u := range kvs {
		out[k] = u.Value
	}
	return out
}
