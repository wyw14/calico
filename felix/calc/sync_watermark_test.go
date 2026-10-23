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

package calc_test

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/projectcalico/calico/felix/calc"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// watermarkSinkMock is a downstream SyncerCallbacks with an optional gate so
// a test can hold the consumer mid-Apply and fill the bounded queue.
type watermarkSinkMock struct {
	mu sync.Mutex

	updates  []api.Update
	statuses []api.SyncStatus

	// entered is closed (then replaced) each time OnUpdates starts.
	entered chan struct{}
	// gate, when non-nil, blocks OnUpdates until it is closed; the mock then
	// clears it so only one call is held.
	gate chan struct{}
}

func (m *watermarkSinkMock) OnUpdates(updates []api.Update) {
	m.mu.Lock()
	gate := m.gate
	// entered is one-shot: the first call after setGate claims it.
	entered := m.entered
	m.entered = nil
	m.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if gate != nil {
		<-gate
		m.mu.Lock()
		m.gate = nil
		m.mu.Unlock()
	}
	m.mu.Lock()
	m.updates = append(m.updates, updates...)
	m.mu.Unlock()
}

func (m *watermarkSinkMock) OnStatusUpdated(status api.SyncStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, status)
}

func (m *watermarkSinkMock) setGate(g chan struct{}, entered chan struct{}) {
	m.mu.Lock()
	m.gate = g
	m.entered = entered
	m.mu.Unlock()
}

func (m *watermarkSinkMock) updatesSnapshot() []api.Update {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.Update, len(m.updates))
	copy(out, m.updates)
	return out
}

func (m *watermarkSinkMock) statusesSnapshot() []api.SyncStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]api.SyncStatus, len(m.statuses))
	copy(out, m.statuses)
	return out
}

func watermarkedUpdate(name, rev string, deleted bool) api.Update {
	upd := api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: name},
			Revision: rev,
		},
	}
	if deleted {
		upd.UpdateType = api.UpdateTypeKVDeleted
		return upd
	}
	upd.Value = "value-" + rev
	upd.UpdateType = api.UpdateTypeKVUpdated
	return upd
}

var _ = Describe("BoundedSyncCallbacks", func() {
	var (
		sink    *watermarkSinkMock
		bounded *BoundedSyncCallbacks
		cxt     context.Context
		cancel  context.CancelFunc
	)

	BeforeEach(func() {
		sink = &watermarkSinkMock{}
	})
	AfterEach(func() {
		if cancel != nil {
			cancel()
		}
	})

	start := func(capacity int) {
		cxt, cancel = context.WithCancel(context.Background())
		bounded = NewBoundedSyncCallbacks(sink, BoundedSyncCallbacksConfig{QueueCapacity: capacity})
		bounded.Start(cxt)
	}

	It("tracks revision watermarks through updates, status and deletion", func() {
		start(10)
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "10", false)})
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "20", false)})
		bounded.OnStatusUpdated(api.ResyncInProgress)
		bounded.OnStatusUpdated(api.InSync)
		// A delete carries the revision of the deletion and must advance the watermark.
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "25", true)})

		Eventually(func() WatermarkState { return bounded.State() }).Should(And(
			HaveField("ReceivedRevision", Equal(uint64(25))),
			HaveField("AppliedRevision", Equal(uint64(25))),
			HaveField("BacklogObjects", BeZero()),
			HaveField("InSync", BeTrue()),
			HaveField("Restarts", BeZero()),
		))

		ups := sink.updatesSnapshot()
		Expect(ups).To(HaveLen(3))
		Expect(ups[2].Value).To(BeNil())
		Expect(ups[2].UpdateType).To(Equal(api.UpdateTypeKVDeleted))
		Expect(sink.statusesSnapshot()).To(ContainElement(api.InSync))
	})

	It("blocks a fast producer once the bounded queue is full (bounded flow)", func() {
		start(2)

		// Hold the first update inside the downstream consumer.
		entered := make(chan struct{})
		gate := make(chan struct{})
		sink.setGate(gate, entered)
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "10", false)})
		<-entered

		// Two updates fit the queue; the fourth send blocks because the
		// consumer is stuck and the queue is bounded.
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "20", false)})
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "30", false)})
		sent := make(chan struct{})
		go func() {
			bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "40", false)})
			close(sent)
		}()
		Consistently(sent, 300*time.Millisecond, 20*time.Millisecond).ShouldNot(BeClosed())

		// The un-admitted update has already moved the received watermark but
		// the backlog is bounded at the queue capacity.
		st := bounded.State()
		Expect(st.ReceivedRevision).To(Equal(uint64(40)))
		Expect(st.BacklogObjects).To(Equal(2))

		close(gate)
		Eventually(sent, 5*time.Second).Should(BeClosed())
		Eventually(func() WatermarkState { return bounded.State() }).Should(And(
			HaveField("AppliedRevision", Equal(uint64(40))),
			HaveField("BacklogObjects", BeZero()),
		))

		// Applied order is preserved; no update dropped by the bound.
		Expect(revisionsOf(sink.updatesSnapshot())).To(Equal([]string{"10", "20", "30", "40"}))
	})

	It("does not interleave old updates with the fresh snapshot across a restart", func() {
		start(5)

		// Old connection delivers one update, which is held mid-apply.
		entered := make(chan struct{})
		gate := make(chan struct{})
		sink.setGate(gate, entered)
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "10", false)})
		<-entered

		// The old connection dies; the restart marker and a snapshot update
		// queue behind the in-flight old update.
		bounded.OnTyphaConnectionRestarted()
		bounded.OnUpdates([]api.Update{watermarkedUpdate("a", "30", false)})

		st := bounded.State()
		Expect(st.Restarts).To(Equal(1))
		Expect(st.ReceivedRevision).To(Equal(uint64(30)))
		// Nothing past the held update has applied yet.
		Expect(st.AppliedRevision).To(BeZero())

		close(gate)
		Eventually(func() []string {
			return revisionsOf(sink.updatesSnapshot())
		}, 5*time.Second).Should(Equal([]string{"10", "30"}))
		Eventually(func() WatermarkState { return bounded.State() }).Should(And(
			HaveField("AppliedRevision", Equal(uint64(30))),
			HaveField("BacklogObjects", BeZero()),
		))

		// A second restart is counted independently.
		bounded.OnTyphaConnectionRestarted()
		Expect(bounded.State().Restarts).To(Equal(2))
	})
})

func revisionsOf(updates []api.Update) []string {
	out := make([]string, 0, len(updates))
	for _, u := range updates {
		out = append(out, u.Revision)
	}
	return out
}
