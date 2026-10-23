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

package ipam

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	libipam "github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var planNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func strictConfig() libipam.IPAMConfig {
	return libipam.IPAMConfig{
		StrictAffinity:     true,
		AutoAllocateBlocks: true,
	}
}

func testPool(name, cidr string, mutate func(*v3.IPPoolSpec)) v3.IPPool {
	mode := v3.Automatic
	spec := v3.IPPoolSpec{
		CIDR:           cidr,
		AssignmentMode: &mode,
		AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel},
		NodeSelector:   "all()",
	}
	p := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
	if mutate != nil {
		mutate(&p.Spec)
	}
	return p
}

// makeBlock builds an allocation block. Ordinals in unallocated are free;
// ordinals in cooling carry a ReleasedAt timestamp; every other ordinal is
// an ordinary allocation owned by host.
func makeBlock(t *testing.T, cidr, host string, unallocated []int, cooling map[int]time.Time) *model.AllocationBlock {
	t.Helper()
	_, ipnet, err := cnet.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("bad CIDR %s: %v", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	size := 1 << uint(bits-ones)
	allocs := make([]*int, size)
	handle := "test-handle"
	attrs := []model.AllocationAttribute{{
		HandleID:         &handle,
		ActiveOwnerAttrs: map[string]string{model.IPAMBlockAttributeNode: host},
	}}
	for o := 0; o < size; o++ {
		if slices.Contains(unallocated, o) {
			continue
		}
		if released, ok := cooling[o]; ok {
			ts := metav1.NewTime(released)
			idx := len(attrs)
			attrs = append(attrs, model.AllocationAttribute{ReleasedAt: &ts})
			allocs[o] = &idx
		} else {
			idx := 0
			allocs[o] = &idx
		}
	}
	b := &model.AllocationBlock{
		CIDR:        *ipnet,
		Allocations: allocs,
		Unallocated: unallocated,
		Attributes:  attrs,
	}
	if host != "" {
		aff := model.IPAMAffinityTypeHost + ":" + host
		b.Affinity = &aff
	}
	return b
}

func baseInput() PlanInput {
	in := PlanInput{
		Config:      strictConfig(),
		IntendedUse: v3.IPPoolAllowedUseWorkload,
		NodeLabels: map[string]map[string]string{
			"n-a": {},
			"n-b": {},
		},
		NamespaceLabels: map[string]map[string]string{
			"default": {},
		},
		Revisions: SnapshotInfo{TakenAt: planNow},
	}
	return in
}

func resultFor(report *PlanReport, node, namespace string, version int) *DemandResult {
	for i := range report.Results {
		r := &report.Results[i]
		if r.Node == node && r.Namespace == namespace && r.IPVersion == version {
			return r
		}
	}
	return nil
}

func TestPlanClaimsNewBlocksInStableOrder(t *testing.T) {
	in := baseInput()
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	in.Demands = []Demand{
		{Node: "n-a", Namespace: "default", NumIPv4: 100},
		{Node: "n-b", Namespace: "default", NumIPv4: 100},
	}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}

	ra := resultFor(report, "n-a", "default", 4)
	if ra == nil || ra.Satisfiable != 100 || ra.Unsatisfied != 0 {
		t.Fatalf("unexpected n-a result: %+v", ra)
	}
	wantA := []string{"10.0.0.0/26", "10.0.0.64/26"}
	var gotA []string
	for _, b := range ra.NewBlocks {
		gotA = append(gotA, b.BlockCIDR)
		if b.UsableCapacity != 64 {
			t.Errorf("block %s capacity = %d, want 64", b.BlockCIDR, b.UsableCapacity)
		}
	}
	if !reflect.DeepEqual(gotA, wantA) {
		t.Errorf("n-a new blocks = %v, want %v", gotA, wantA)
	}

	rb := resultFor(report, "n-b", "default", 4)
	wantB := []string{"10.0.0.128/26", "10.0.0.192/26"}
	var gotB []string
	for _, b := range rb.NewBlocks {
		gotB = append(gotB, b.BlockCIDR)
	}
	if !reflect.DeepEqual(gotB, wantB) {
		t.Errorf("n-b new blocks = %v, want %v", gotB, wantB)
	}

	// Global list sorted by node, then block address.
	var gotGlobal []string
	for _, b := range report.NewBlocks {
		gotGlobal = append(gotGlobal, b.Node+":"+b.BlockCIDR)
	}
	wantGlobal := []string{
		"n-a:10.0.0.0/26", "n-a:10.0.0.64/26",
		"n-b:10.0.0.128/26", "n-b:10.0.0.192/26",
	}
	if !reflect.DeepEqual(gotGlobal, wantGlobal) {
		t.Errorf("global block order = %v, want %v", gotGlobal, wantGlobal)
	}
}

func TestPlanUsesFreeSpaceInExistingAffineBlockFirst(t *testing.T) {
	in := baseInput()
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	// Block .0/26 is n-a's, with 60 allocations (4 free).
	in.Blocks = []*model.AllocationBlock{
		makeBlock(t, "10.0.0.0/26", "n-a", []int{60, 61, 62, 63}, nil),
	}
	in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 10}}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	r := resultFor(report, "n-a", "default", 4)
	if r.Satisfiable != 10 || r.Unsatisfied != 0 {
		t.Fatalf("result = %+v, want 10/10 satisfied", r)
	}
	if len(r.NewBlocks) != 1 || r.NewBlocks[0].BlockCIDR != "10.0.0.64/26" {
		t.Fatalf("new blocks = %+v, want only 10.0.0.64/26", r.NewBlocks)
	}
}

func TestPlanSharesExistingBlockAcrossNamespaces(t *testing.T) {
	in := baseInput()
	in.NamespaceLabels["ns1"] = map[string]string{}
	in.NamespaceLabels["ns2"] = map[string]string{}
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	// 4 free addresses in n-a's existing block.
	in.Blocks = []*model.AllocationBlock{
		makeBlock(t, "10.0.0.0/26", "n-a", []int{60, 61, 62, 63}, nil),
	}
	in.Demands = []Demand{
		{Node: "n-a", Namespace: "ns1", NumIPv4: 2},
		{Node: "n-a", Namespace: "ns2", NumIPv4: 3},
	}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	r1 := resultFor(report, "n-a", "ns1", 4)
	r2 := resultFor(report, "n-a", "ns2", 4)
	if r1.Satisfiable != 2 || len(r1.NewBlocks) != 0 {
		t.Errorf("ns1 = %+v, want 2 from existing block", r1)
	}
	if r2.Satisfiable != 3 || len(r2.NewBlocks) != 1 || r2.NewBlocks[0].BlockCIDR != "10.0.0.64/26" {
		t.Errorf("ns2 = %+v, want 2 existing + 1 new block 10.0.0.64/26", r2)
	}
}

func TestPlanSkipsFullyReservedBlockAndDeductsPartialReservations(t *testing.T) {
	// Reservation covers the whole of the first /26 block.
	t.Run("whole block reserved", func(t *testing.T) {
		in := baseInput()
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
		_, reserved, _ := cnet.ParseCIDR("10.0.0.0/26")
		in.Reservations = []cnet.IPNet{*reserved}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 70}}

		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		var got []string
		for _, b := range r.NewBlocks {
			got = append(got, b.BlockCIDR)
		}
		want := []string{"10.0.0.64/26", "10.0.0.128/26"}
		if !reflect.DeepEqual(got, want) || r.Satisfiable != 70 {
			t.Fatalf("blocks = %v sat = %d, want %v and 70", got, r.Satisfiable, want)
		}
	})

	// Reservation covers half of the first block: it is still claimable but
	// only 32 of its 64 addresses are usable.
	t.Run("half block reserved", func(t *testing.T) {
		in := baseInput()
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
		_, reserved, _ := cnet.ParseCIDR("10.0.0.0/27")
		in.Reservations = []cnet.IPNet{*reserved}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 40}}

		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Satisfiable != 40 {
			t.Fatalf("sat = %d, want 40", r.Satisfiable)
		}
		if len(r.NewBlocks) != 2 {
			t.Fatalf("new blocks = %d, want 2", len(r.NewBlocks))
		}
		if r.NewBlocks[0].BlockCIDR != "10.0.0.0/26" || r.NewBlocks[0].UsableCapacity != 32 {
			t.Errorf("first block = %+v, want 10.0.0.0/26 with 32 usable", r.NewBlocks[0])
		}
		if r.NewBlocks[1].BlockCIDR != "10.0.0.64/26" {
			t.Errorf("second block = %s, want 10.0.0.64/26", r.NewBlocks[1].BlockCIDR)
		}
	})
}

func TestPlanRespectsMaxBlocksPerHost(t *testing.T) {
	in := baseInput()
	cfg := strictConfig()
	cfg.MaxBlocksPerHost = 1
	in.Config = cfg
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 200}}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	r := resultFor(report, "n-a", "default", 4)
	if r.Satisfiable != 64 || r.Unsatisfied != 136 {
		t.Fatalf("sat/unsat = %d/%d, want 64/136", r.Satisfiable, r.Unsatisfied)
	}
	if len(r.NewBlocks) != 1 {
		t.Fatalf("new blocks = %d, want 1", len(r.NewBlocks))
	}
	if len(r.Reasons) != 1 || !strings.Contains(r.Reasons[0], "limit of 1 blocks per host") {
		t.Fatalf("reasons = %v, want block limit reason", r.Reasons)
	}
}

func TestPlanRespectsSelectorsModeAndUse(t *testing.T) {
	t.Run("node selector mismatch", func(t *testing.T) {
		in := baseInput()
		in.NodeLabels["n-a"] = map[string]string{"zone": "b"}
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) {
			s.BlockSize = 26
			s.NodeSelector = "zone == 'a'"
		})}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}
		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Unsatisfied != 1 || len(r.Reasons) != 1 {
			t.Fatalf("result = %+v, want fully unmet with a reason", r)
		}
	})

	t.Run("manual pool is skipped", func(t *testing.T) {
		in := baseInput()
		manual := v3.Manual
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) {
			s.BlockSize = 26
			s.AssignmentMode = &manual
		})}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}
		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Unsatisfied != 1 || r.Satisfiable != 0 {
			t.Fatalf("result = %+v, want no satisfaction from manual pool", r)
		}
	})

	t.Run("use not allowed by pool", func(t *testing.T) {
		in := baseInput()
		in.IntendedUse = v3.IPPoolAllowedUseTunnel
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) {
			s.BlockSize = 26
			s.AllowedUses = []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload}
		})}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}
		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Unsatisfied != 1 {
			t.Fatalf("result = %+v, want tunnel demand unmet", r)
		}
	})

	t.Run("disabled and deleting pools skipped", func(t *testing.T) {
		in := baseInput()
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) {
			s.BlockSize = 26
			s.Disabled = true
		})}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}
		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Unsatisfied != 1 {
			t.Fatalf("result = %+v, want demand unmet by disabled pool", r)
		}
	})
}

func TestPlanNamespaceSelector(t *testing.T) {
	in := baseInput()
	in.NamespaceLabels["team-a"] = map[string]string{"team": "a"}
	in.NamespaceLabels["team-b"] = map[string]string{"team": "b"}
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) {
		s.BlockSize = 26
		s.NamespaceSelector = "team == 'a'"
	})}
	in.Demands = []Demand{
		{Node: "n-a", Namespace: "team-a", NumIPv4: 1},
		{Node: "n-a", Namespace: "team-b", NumIPv4: 1},
	}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	if r := resultFor(report, "n-a", "team-a", 4); r == nil || r.Satisfiable != 1 || len(r.NewBlocks) != 1 {
		t.Errorf("team-a result = %+v, want satisfied", r)
	}
	if r := resultFor(report, "n-a", "team-b", 4); r == nil || r.Unsatisfied != 1 {
		t.Errorf("team-b result = %+v, want unmet", r)
	}
}

func TestPlanDeductsCooldownAddresses(t *testing.T) {
	coolingAt := planNow.Add(-time.Minute)
	block := func(t *testing.T) *model.AllocationBlock {
		// Ordinals 0..58 allocated, 59 cooling (not yet reclaimable).
		cooling := map[int]time.Time{59: coolingAt}
		return makeBlock(t, "10.0.0.0/26", "n-a", nil, cooling)
	}

	t.Run("cooldown not elapsed: address unavailable", func(t *testing.T) {
		in := baseInput()
		cfg := strictConfig()
		cfg.IPCooldownSeconds = 3600
		in.Config = cfg
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
		in.Blocks = []*model.AllocationBlock{block(t)}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}

		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Satisfiable != 1 || len(r.NewBlocks) != 1 || r.NewBlocks[0].BlockCIDR != "10.0.0.64/26" {
			t.Fatalf("result = %+v, want demand served from a new block", r)
		}
	})

	t.Run("cooldown elapsed: address free on block load", func(t *testing.T) {
		in := baseInput()
		cfg := strictConfig()
		cfg.IPCooldownSeconds = 60
		in.Config = cfg
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
		// Released two minutes ago; cooldown is one minute.
		cooling := map[int]time.Time{59: planNow.Add(-2 * time.Minute)}
		in.Blocks = []*model.AllocationBlock{makeBlock(t, "10.0.0.0/26", "n-a", nil, cooling)}
		in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}

		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Satisfiable != 1 || len(r.NewBlocks) != 0 {
			t.Fatalf("result = %+v, want demand served from existing block", r)
		}
	})
}

func TestPlanAutoAllocateBlocksDisabled(t *testing.T) {
	in := baseInput()
	in.Config = libipam.IPAMConfig{StrictAffinity: true, AutoAllocateBlocks: false}
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}

	t.Run("no existing capacity", func(t *testing.T) {
		in2 := in
		in2.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 5}}
		report, err := RunPlan(in2)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Satisfiable != 0 || r.Unsatisfied != 5 {
			t.Fatalf("result = %+v, want fully unmet", r)
		}
		if !slices.Contains(r.Reasons, reasonAutoAllocateOff) {
			t.Fatalf("reasons = %v, want auto-allocate off reason", r.Reasons)
		}
	})

	t.Run("existing free capacity still usable", func(t *testing.T) {
		in2 := in
		in2.Blocks = []*model.AllocationBlock{
			makeBlock(t, "10.0.0.0/26", "n-a", []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, nil),
		}
		in2.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 10}}
		report, err := RunPlan(in2)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		r := resultFor(report, "n-a", "default", 4)
		if r.Satisfiable != 10 || len(r.NewBlocks) != 0 {
			t.Fatalf("result = %+v, want satisfied by existing block only", r)
		}
	})
}

func TestPlanMissingNodeAndNamespace(t *testing.T) {
	in := baseInput()
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	in.Demands = []Demand{{Node: "ghost", Namespace: "default", NumIPv4: 1}}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	r := resultFor(report, "ghost", "default", 4)
	if r == nil || r.Unsatisfied != 1 || !strings.Contains(r.Reasons[0], "does not exist") {
		t.Fatalf("result = %+v, want missing-node reason", r)
	}

	// Unknown namespace produces a warning; selectors evaluate empty labels.
	in.Demands = []Demand{{Node: "n-a", Namespace: "unknown-ns", NumIPv4: 1}}
	report, err = RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "unknown-ns") {
		t.Fatalf("warnings = %v, want unknown namespace warning", report.Warnings)
	}
	r = resultFor(report, "n-a", "unknown-ns", 4)
	if r.Satisfiable != 1 {
		t.Fatalf("result = %+v, want demand satisfied against empty namespace labels", r)
	}
}

func TestPlanIPv6(t *testing.T) {
	in := baseInput()
	in.Pools = []v3.IPPool{testPool("v6", "2001:db8::/120", func(s *v3.IPPoolSpec) { s.BlockSize = 122 })}
	in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv6: 100}}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	r := resultFor(report, "n-a", "default", 6)
	if r.Satisfiable != 100 {
		t.Fatalf("sat = %d, want 100", r.Satisfiable)
	}
	want := []string{"2001:db8::/122", "2001:db8::40/122"}
	var got []string
	for _, b := range r.NewBlocks {
		got = append(got, b.BlockCIDR)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("v6 blocks = %v, want %v", got, want)
	}
}

func TestPlanRequiresStrictAffinity(t *testing.T) {
	in := baseInput()
	in.Config = libipam.IPAMConfig{StrictAffinity: false, AutoAllocateBlocks: true}
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", nil)}
	in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 1}}
	if _, err := RunPlan(in); err == nil {
		t.Fatal("RunPlan with StrictAffinity=false should fail")
	}
}

func TestPlanDeterministicRegardlessOfDemandOrder(t *testing.T) {
	build := func(demands []Demand) *PlanReport {
		in := baseInput()
		in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
		in.Demands = demands
		report, err := RunPlan(in)
		if err != nil {
			t.Fatalf("RunPlan: %v", err)
		}
		return report
	}

	demands := []Demand{
		{Node: "n-b", Namespace: "default", NumIPv4: 100},
		{Node: "n-a", Namespace: "default", NumIPv4: 100},
	}
	reversed := slices.Clone(demands)
	slices.Reverse(reversed)
	r1 := build(demands)
	r2 := build(reversed)

	// Results are sorted; asserted globally identical including block CIDRs.
	if !reflect.DeepEqual(r1.Results, r2.Results) {
		t.Fatalf("results differ:\n%+v\nvs\n%+v", r1.Results, r2.Results)
	}
	if !reflect.DeepEqual(r1.NewBlocks, r2.NewBlocks) {
		t.Fatalf("new blocks differ:\n%+v\nvs\n%+v", r1.NewBlocks, r2.NewBlocks)
	}
}

func TestPlanDoesNotMutateInputBlocks(t *testing.T) {
	in := baseInput()
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	b := makeBlock(t, "10.0.0.0/26", "n-a", []int{60, 61, 62, 63}, nil)
	in.Blocks = []*model.AllocationBlock{b}
	in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 10}}

	if _, err := RunPlan(in); err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	if got := len(b.Unallocated); got != 4 {
		t.Fatalf("input block Unallocated mutated: len=%d, want 4", got)
	}
}
