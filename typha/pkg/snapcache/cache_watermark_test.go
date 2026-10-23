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

package snapcache_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
)

var _ = Describe("Breadcrumb revision watermark", func() {
	var (
		cache  *snapcache.Cache
		cxt    context.Context
		cancel context.CancelFunc
	)

	BeforeEach(func() {
		cache = snapcache.New(snapcache.Config{
			// Batch one update per breadcrumb so each OnUpdates maps to one
			// breadcrumb with an observable revision.
			MaxBatchSize:   1,
			WakeUpInterval: time.Second,
			Name:           "wm-cache",
		})
		cxt, cancel = context.WithCancel(context.Background())
		cache.Start(cxt)
	})
	AfterEach(func() { cancel() })

	send := func(rev string, deleted bool) {
		upd := api.Update{
			KVPair: model.KVPair{
				Key:      model.GlobalConfigKey{Name: "watermark-key"},
				Revision: rev,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}
		if deleted {
			upd.Value = nil
			upd.UpdateType = api.UpdateTypeKVDeleted
		} else {
			upd.Value = "value-" + rev
		}
		cache.OnUpdates([]api.Update{upd})
	}

	It("carries the highest revision over the breadcrumb chain, including a delete", func() {
		send("10", false)
		Eventually(func() uint64 {
			return cache.CurrentBreadcrumb().HighWaterRevision
		}).Should(BeNumerically("==", 10))

		// A follower connected at this breadcrumb sees the next watermark.
		crumb := cache.CurrentBreadcrumb()

		send("20", false)
		Eventually(func() uint64 {
			return cache.CurrentBreadcrumb().HighWaterRevision
		}).Should(BeNumerically("==", 20))

		// The delete removes the KV from the snapshot but its revision must
		// still advance the watermark.
		send("25", true)
		Eventually(func() uint64 {
			return cache.CurrentBreadcrumb().HighWaterRevision
		}).Should(BeNumerically("==", 25))
		Expect(cache.CurrentBreadcrumb().KVs.Len()).To(BeZero())

		next, err := crumb.Next(cxt)
		Expect(err).NotTo(HaveOccurred())
		// Walking the chain must only ever move to a higher watermark.
		for next.HighWaterRevision < 25 {
			next, err = next.Next(cxt)
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(next.HighWaterRevision).To(BeNumerically("==", 25))
	})
})
