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

package calc

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncwatermark"
)

const defaultBoundedSyncQueueCapacity = 1000

// WatermarkState is a point-in-time view of how far a sync stream has
// progressed on the consumer (Felix) side.
type WatermarkState struct {
	// ReceivedRevision is the highest datastore revision handed to us by
	// the Typha client, whether or not the calc graph has applied it yet.
	ReceivedRevision uint64
	// AppliedRevision is the highest revision the downstream consumer has
	// finished applying.
	AppliedRevision uint64
	// BacklogObjects is the number of messages queued ahead of the
	// downstream consumer.
	BacklogObjects int
	// Restarts counts Typha connection restarts (each followed by a fresh
	// snapshot).
	Restarts int
	// InSync reports whether the stream is currently in sync.
	InSync bool
	// LastRestartAt records the time of the most recent restart marker.
	LastRestartAt time.Time
}

// BoundedSyncCallbacksConfig configures a BoundedSyncCallbacks.
type BoundedSyncCallbacksConfig struct {
	// QueueCapacity bounds the number of callback messages buffered for the
	// downstream consumer.  When the queue is full, OnUpdates blocks; that
	// applies back-pressure through the sync client and, on the server,
	// Typha's per-client backlog bound disconnects a persistently slow
	// client so it retakes a snapshot.  Defaults to 1000.
	QueueCapacity int
}

func (c *BoundedSyncCallbacksConfig) applyDefaults() {
	if c.QueueCapacity <= 0 {
		c.QueueCapacity = defaultBoundedSyncQueueCapacity
	}
}

// BoundedSyncCallbacks sits between the Typha sync client and the calc
// graph.  It bounds the in-process update queue (so a slow calc graph
// applies back-pressure instead of growing memory without limit), records
// the received/applied revision watermark and counts connection restarts.
//
// A single channel feeds a single consumer, so updates and restart
// markers are applied in exactly the order the sync client produced them.
// The client only invokes OnTyphaConnectionRestarted after the previous
// connection's callback goroutine has stopped, so a stale update from the
// dead connection can never follow the restart marker and interleave with
// the fresh snapshot.
type BoundedSyncCallbacks struct {
	downstream api.SyncerCallbacks
	input      chan any

	mu               sync.Mutex
	receivedRevision uint64
	appliedRevision  uint64
	restarts         int
	inSync           bool
	lastRestartAt    time.Time
}

// NewBoundedSyncCallbacks wraps downstream with a bounded, watermark-aware
// callback layer.  Call Start to begin forwarding.
func NewBoundedSyncCallbacks(downstream api.SyncerCallbacks, config BoundedSyncCallbacksConfig) *BoundedSyncCallbacks {
	config.applyDefaults()
	return &BoundedSyncCallbacks{
		downstream: downstream,
		input:      make(chan any, config.QueueCapacity),
	}
}

// Start runs the forwarding loop until ctx is canceled.
func (b *BoundedSyncCallbacks) Start(ctx context.Context) {
	go b.loop(ctx)
}

// OnUpdates implements api.SyncerCallbacks.  It blocks once the bounded
// queue is full, which is the back-pressure point.
func (b *BoundedSyncCallbacks) OnUpdates(updates []api.Update) {
	if rev := syncwatermark.RevisionFromUpdates(updates); rev.IsValid() {
		b.mu.Lock()
		if rev.Value() > b.receivedRevision {
			b.receivedRevision = rev.Value()
		}
		b.mu.Unlock()
	}
	b.input <- updates
}

// OnStatusUpdated implements api.SyncerCallbacks.
func (b *BoundedSyncCallbacks) OnStatusUpdated(status api.SyncStatus) {
	b.input <- status
}

// OnTyphaConnectionRestarted implements syncclient.RestartAwareCallbacks so
// the Typha client reconnects through this layer.  The marker joins the
// same ordered stream as every other callback.
func (b *BoundedSyncCallbacks) OnTyphaConnectionRestarted() {
	log.Info("Typha connection restarted; queueing snapshot boundary marker.")
	b.mu.Lock()
	b.restarts++
	b.lastRestartAt = time.Now()
	// A fresh snapshot follows; until it is applied we cannot claim to be in
	// sync even if the previous connection was.
	b.inSync = false
	b.mu.Unlock()
	b.input <- connectionRestarted{}
}

// State returns the current watermark state.
func (b *BoundedSyncCallbacks) State() WatermarkState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return WatermarkState{
		ReceivedRevision: b.receivedRevision,
		AppliedRevision:  b.appliedRevision,
		// The channel length is the live queue depth; it is safe to read
		// while other goroutines are blocked on send.
		BacklogObjects: len(b.input),
		Restarts:       b.restarts,
		InSync:         b.inSync,
		LastRestartAt:  b.lastRestartAt,
	}
}

type connectionRestarted struct{}

func (b *BoundedSyncCallbacks) loop(ctx context.Context) {
	for {
		select {
		case msg := <-b.input:
			b.apply(msg)
		case <-ctx.Done():
			log.WithError(ctx.Err()).Info("Bounded sync callbacks stopping.")
			return
		}
	}
}

func (b *BoundedSyncCallbacks) apply(msg any) {
	switch msg := msg.(type) {
	case []api.Update:
		b.downstream.OnUpdates(msg)
		rev := syncwatermark.RevisionFromUpdates(msg)
		b.mu.Lock()
		if rev.Value() > b.appliedRevision {
			b.appliedRevision = rev.Value()
		}
		b.mu.Unlock()
	case api.SyncStatus:
		b.downstream.OnStatusUpdated(msg)
		b.mu.Lock()
		b.inSync = msg == api.InSync
		b.mu.Unlock()
	case connectionRestarted:
		// Boundary only: the old connection is gone and its stale updates
		// have all been applied by this point.  Nothing is forwarded.
	}
}
