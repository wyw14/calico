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
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"go4.org/netipx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	libipam "github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// PlanNote is printed with every plan and embedded in every report: a plan
// describes a read-only simulation against one datastore snapshot.
const PlanNote = "This is a planning result for the current datastore snapshot only; it creates no IPAM blocks, claims no affinity, and changes no allocations."

// Demand is one request for additional addresses: how many new IPv4/IPv6
// addresses a node is expected to need for a given namespace.
type Demand struct {
	// Node is the node (Calico node name) that would request the addresses.
	Node string `json:"node" yaml:"node"`

	// Namespace is the Kubernetes namespace the workloads belong to. It is
	// used to evaluate IPPool namespaceSelectors; it may be empty.
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`

	// NumIPv4 is the number of additional IPv4 addresses required.
	NumIPv4 int `json:"ipv4,omitempty" yaml:"ipv4,omitempty"`

	// NumIPv6 is the number of additional IPv6 addresses required.
	NumIPv6 int `json:"ipv6,omitempty" yaml:"ipv6,omitempty"`
}

// AffinityRef is a block affinity record read from the datastore. Affinities
// that point at blocks which do not exist yet mean the node will materialize
// that block on its next allocation, so the planner must account for them.
type AffinityRef struct {
	Host         string
	AffinityType string
	CIDR         netip.Prefix
	State        model.BlockAffinityState
}

// SnapshotInfo records the resource versions of every resource the planner
// read, so a report can be tied to the exact snapshot it was computed from.
type SnapshotInfo struct {
	TakenAt                  time.Time `json:"takenAt"`
	IPAMConfigRV             string    `json:"ipamConfigResourceVersion,omitempty"`
	IPPoolsRV                string    `json:"ipPoolsResourceVersion"`
	NodesRV                  string    `json:"nodesResourceVersion"`
	NamespacesRV             string    `json:"namespacesResourceVersion,omitempty"`
	IPReservationsRV         string    `json:"ipReservationsResourceVersion"`
	BlocksRV                 string    `json:"blocksResourceVersion"`
	BlockAffinitiesRV        string    `json:"blockAffinitiesResourceVersion,omitempty"`
	NamespacesUnavailableMsg string    `json:"namespacesUnavailable,omitempty"`
}

// PlanConfigView is the IPAM configuration the plan was computed against.
type PlanConfigView struct {
	StrictAffinity            bool `json:"strictAffinity"`
	AutoAllocateBlocks        bool `json:"autoAllocateBlocks"`
	MaxBlocksPerHost          int  `json:"maxBlocksPerHost"`
	IPCooldownSeconds         int  `json:"ipCooldownSeconds"`
	EffectiveMaxBlocksPerHost int  `json:"effectiveMaxBlocksPerHost"`
}

// PlannedBlock describes one block that the simulation predicts would need to
// be claimed (newly created) to satisfy the demand.
type PlannedBlock struct {
	Node      string `json:"node"`
	IPVersion int    `json:"ipVersion"`
	Pool      string `json:"pool"`
	PoolCIDR  string `json:"poolCIDR"`
	BlockCIDR string `json:"blockCIDR"`
	// UsableCapacity is how many addresses in the block can actually be handed
	// out after IPReservations (and, for existing blocks, host reservations)
	// are deducted.
	UsableCapacity int `json:"usableCapacity"`
}

// DemandResult is the planning outcome for one (node, namespace, IP version)
// demand.
type DemandResult struct {
	Node        string         `json:"node"`
	Namespace   string         `json:"namespace"`
	IPVersion   int            `json:"ipVersion"`
	Requested   int            `json:"requested"`
	Satisfiable int            `json:"satisfiable"`
	Unsatisfied int            `json:"unsatisfied"`
	NewBlocks   []PlannedBlock `json:"newBlocks,omitempty"`
	// Reasons explains any unsatisfied demand, in stable order.
	Reasons []string `json:"reasons,omitempty"`
}

// PlanReport is the complete planning result.
type PlanReport struct {
	Note        string         `json:"note"`
	Snapshot    SnapshotInfo   `json:"snapshot"`
	Config      PlanConfigView `json:"config"`
	IntendedUse string         `json:"intendedUse"`
	Results     []DemandResult `json:"results"`
	NewBlocks   []PlannedBlock `json:"newBlocks"`
	Warnings    []string       `json:"warnings,omitempty"`
}

// PlanInput is the immutable snapshot consumed by the planner. Nothing in it
// is modified: blocks are read but not written.
type PlanInput struct {
	Config          libipam.IPAMConfig
	IntendedUse     v3.IPPoolAllowedUse
	Pools           []v3.IPPool
	NodeLabels      map[string]map[string]string
	NamespaceLabels map[string]map[string]string
	Reservations    []cnet.IPNet
	Blocks          []*model.AllocationBlock
	Affinities      []AffinityRef
	Demands         []Demand
	Revisions       SnapshotInfo
}

// Reasons reported for unmet demand. Kept stable so reports diff cleanly.
const (
	reasonNoNodeFmt         = "node %q does not exist"
	reasonNoMatchingPool    = "no enabled, Automatic-assignment pool allows this use for this node and namespace (checked allowedUses, assignmentMode, nodeSelector and namespaceSelector)"
	reasonAutoAllocateOff   = "existing affine blocks are full and AutoAllocateBlocks is disabled"
	reasonBlockLimitFmt     = "need a new IPAM block but the node already reaches the limit of %d blocks per host"
	reasonNoUnclaimedBlocks = "no unclaimed, non-reserved block is left in any matching pool"
)

// defaultMaxBlocksPerHost mirrors the safeguard applied by IPAM autoAssign
// when neither the global config nor the request limits blocks per host.
const defaultMaxBlocksPerHost = 20

// RunPlan simulates the requested allocations in memory and returns a plan.
// It is deterministic: the same snapshot and demands always produce the same
// plan. It never mutates the datastore.
func RunPlan(in PlanInput) (*PlanReport, error) {
	if !in.Config.StrictAffinity {
		return nil, fmt.Errorf("ipam plan is only supported with strict affinity enabled (IPAMConfig StrictAffinity=true); borrowing cannot be planned")
	}
	if in.IntendedUse == "" {
		return nil, fmt.Errorf("intended use must be specified")
	}
	now := in.Revisions.TakenAt
	if now.IsZero() {
		now = time.Now()
	}

	pl, err := newPlanner(in, now)
	if err != nil {
		return nil, err
	}

	// Process demands in stable order - node, then namespace - because new
	// blocks are claimed from a cluster-wide free space and claim order
	// decides which node gets which block CIDR. IPv4 is always planned before
	// IPv6 within a demand.
	demands := slices.Clone(in.Demands)
	sort.SliceStable(demands, func(i, j int) bool {
		if demands[i].Node != demands[j].Node {
			return demands[i].Node < demands[j].Node
		}
		return demands[i].Namespace < demands[j].Namespace
	})
	for _, d := range demands {
		if d.NumIPv4 > 0 {
			pl.results = append(pl.results, pl.planDemand(d, 4))
		}
		if d.NumIPv6 > 0 {
			pl.results = append(pl.results, pl.planDemand(d, 6))
		}
	}

	// New blocks: node, then pool CIDR, then block address.
	sort.Slice(pl.planned, func(i, j int) bool {
		return plannedBlockLess(pl.planned[i], pl.planned[j])
	})

	maxBlocks := in.Config.MaxBlocksPerHost
	if maxBlocks == 0 {
		maxBlocks = defaultMaxBlocksPerHost
	}

	return &PlanReport{
		Note:        PlanNote,
		Snapshot:    in.Revisions,
		IntendedUse: string(in.IntendedUse),
		Config: PlanConfigView{
			StrictAffinity:            in.Config.StrictAffinity,
			AutoAllocateBlocks:        in.Config.AutoAllocateBlocks,
			MaxBlocksPerHost:          in.Config.MaxBlocksPerHost,
			IPCooldownSeconds:         in.Config.IPCooldownSeconds,
			EffectiveMaxBlocksPerHost: maxBlocks,
		},
		Results:   pl.results,
		NewBlocks: pl.planned,
		Warnings:  pl.warnings,
	}, nil
}

func plannedBlockLess(a, b PlannedBlock) bool {
	if a.Node != b.Node {
		return a.Node < b.Node
	}
	if a.IPVersion != b.IPVersion {
		return a.IPVersion < b.IPVersion
	}
	// Compare pool CIDRs as addresses, falling back to the pool name for
	// equal CIDRs (which should not occur, but keeps ordering total).
	ap, aerr := netip.ParsePrefix(a.PoolCIDR)
	bp, berr := netip.ParsePrefix(b.PoolCIDR)
	if aerr == nil && berr == nil {
		if c := prefixCompare(ap, bp); c != 0 {
			return c < 0
		}
	}
	if a.Pool != b.Pool {
		return a.Pool < b.Pool
	}
	ab, _ := netip.ParsePrefix(a.BlockCIDR)
	bb, _ := netip.ParsePrefix(b.BlockCIDR)
	return prefixCompare(ab, bb) < 0
}

func prefixCompare(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	if a.Bits() != b.Bits() {
		if a.Bits() < b.Bits() {
			return -1
		}
		return 1
	}
	return 0
}

// planPool is an IPPool with the block geometry precomputed for simulation.
type planPool struct {
	spec      v3.IPPool
	prefix    netip.Prefix
	blockBits int
	blockSize *big.Int
	numBlocks *big.Int
	// nextOffset is the per-pool, cluster-wide bump pointer to the lowest
	// block CIDR not yet known to be occupied or fully reserved.
	nextOffset *big.Int
}

func (p *planPool) version() int {
	if p.prefix.Addr().BitLen() == 32 {
		return 4
	}
	return 6
}

// prefixAt returns the CIDR of the block at offset (0-based, ascending address
// order) within the pool.
func (p *planPool) prefixAt(offset *big.Int) netip.Prefix {
	baseAddr := p.prefix.Masked().Addr()
	base := addrToBig(baseAddr)
	start := new(big.Int).Add(base, new(big.Int).Mul(offset, p.blockSize))
	addr := bigToAddr(baseAddr.BitLen(), start)
	return netip.PrefixFrom(addr, p.blockBits)
}

// nextFreeBlock returns the CIDR and usable capacity of the lowest unclaimed,
// not-fully-reserved block in the pool. Offsets for occupied or fully reserved
// blocks are consumed permanently because the planner never releases blocks.
func (p *planPool) nextFreeBlock(occupied map[netip.Prefix]*simBlock, resv *reservationSet) (netip.Prefix, int, bool) {
	for p.nextOffset.Cmp(p.numBlocks) < 0 {
		pref := p.prefixAt(p.nextOffset)
		p.nextOffset = new(big.Int).Add(p.nextOffset, big.NewInt(1))
		if _, taken := occupied[pref]; taken {
			continue
		}
		capacity := 1 << uint(p.prefix.Addr().BitLen()-p.blockBits)
		capacity -= resv.countInPrefix(pref)
		if capacity <= 0 {
			continue
		}
		return pref, capacity, true
	}
	return netip.Prefix{}, 0, false
}

// simBlock is an existing block or a block the simulation has claimed.
type simBlock struct {
	prefix  netip.Prefix
	host    string
	affType string
	pool    *planPool
	// free is the remaining assignable capacity, shared across every demand
	// of the owning node (IPAM blocks are not partitioned by namespace).
	free int
	// planned marks blocks that do not exist in the snapshot and would have to
	// be created.
	planned bool
}

type planner struct {
	cfg  libipam.IPAMConfig
	use  v3.IPPoolAllowedUse
	resv *reservationSet
	now  time.Time

	// poolsByVersion holds every pool, including disabled ones, so that
	// existing blocks can be attributed to a pool and counted as occupied.
	poolsByVersion map[int][]*planPool

	nodeLabels map[string]map[string]string
	nsLabels   map[string]map[string]string

	occupied   map[netip.Prefix]*simBlock
	nodeBlocks map[string]map[int][]*simBlock

	results  []DemandResult
	planned  []PlannedBlock
	warnings []string

	missingNamespaces map[string]struct{}
}

func newPlanner(in PlanInput, now time.Time) (*planner, error) {
	resv, err := newReservationSet(in.Reservations)
	if err != nil {
		return nil, err
	}

	pl := &planner{
		cfg:               in.Config,
		use:               in.IntendedUse,
		resv:              resv,
		now:               now,
		poolsByVersion:    map[int][]*planPool{},
		nodeLabels:        in.NodeLabels,
		nsLabels:          in.NamespaceLabels,
		occupied:          map[netip.Prefix]*simBlock{},
		nodeBlocks:        map[string]map[int][]*simBlock{},
		missingNamespaces: map[string]struct{}{},
	}
	if pl.nodeLabels == nil {
		pl.nodeLabels = map[string]map[string]string{}
	}
	if pl.nsLabels == nil {
		pl.nsLabels = map[string]map[string]string{}
	}

	for i := range in.Pools {
		pp, err := newPlanPool(&in.Pools[i])
		if err != nil {
			// Skip pools with geometry we cannot model; their blocks still
			// appear below as unowned but occupied.
			continue
		}
		pl.poolsByVersion[pp.version()] = append(pl.poolsByVersion[pp.version()], pp)
	}
	// Deterministic pool ordering by name, matching GetEnabledPools.
	for v := range pl.poolsByVersion {
		sort.Slice(pl.poolsByVersion[v], func(i, j int) bool {
			return pl.poolsByVersion[v][i].spec.Name < pl.poolsByVersion[v][j].spec.Name
		})
	}

	// Existing blocks occupy their CIDR cluster-wide, regardless of pool state.
	for _, b := range in.Blocks {
		sb, err := pl.blockFromSnapshot(b)
		if err != nil {
			continue
		}
		// Duplicate CIDRs should not occur, but keep the first to stay safe.
		if _, exists := pl.occupied[sb.prefix]; !exists {
			pl.occupied[sb.prefix] = sb
			if sb.affType == model.IPAMAffinityTypeHost && sb.host != "" {
				pl.addNodeBlock(sb)
			}
		}
	}

	// Affinities without a backing block: the block gets created on first use,
	// so account for its CIDR and for the node's block count.
	for _, aff := range in.Affinities {
		if aff.State == model.StatePendingDeletion {
			continue
		}
		pref := aff.CIDR.Masked()
		if _, exists := pl.occupied[pref]; exists {
			continue
		}
		pp := pl.poolForBlock(pref)
		sb := &simBlock{
			prefix:  pref,
			host:    aff.Host,
			affType: aff.AffinityType,
			pool:    pp,
			free:    1<<uint(pref.Addr().BitLen()-pref.Bits()) - resv.countInPrefix(pref),
		}
		pl.occupied[pref] = sb
		if aff.AffinityType == model.IPAMAffinityTypeHost && aff.Host != "" {
			pl.addNodeBlock(sb)
		}
	}

	return pl, nil
}

func newPlanPool(pool *v3.IPPool) (*planPool, error) {
	pref, err := netip.ParsePrefix(pool.Spec.CIDR)
	if err != nil {
		return nil, err
	}
	pref = pref.Masked()
	blockBits := accounting.BlockSize(pool)
	bits := pref.Addr().BitLen()
	if blockBits < pref.Bits() || blockBits > bits {
		return nil, fmt.Errorf("pool %s blockSize %d invalid for CIDR %s", pool.Name, blockBits, pool.Spec.CIDR)
	}
	size := new(big.Int).Lsh(big.NewInt(1), uint(bits-blockBits))
	num := new(big.Int).Lsh(big.NewInt(1), uint(blockBits-pref.Bits()))
	return &planPool{
		spec:       *pool,
		prefix:     pref,
		blockBits:  blockBits,
		blockSize:  size,
		numBlocks:  num,
		nextOffset: big.NewInt(0),
	}, nil
}

func (pl *planner) addNodeBlock(b *simBlock) {
	ver := 4
	if b.prefix.Addr().BitLen() == 128 {
		ver = 6
	}
	if pl.nodeBlocks[b.host] == nil {
		pl.nodeBlocks[b.host] = map[int][]*simBlock{}
	}
	pl.nodeBlocks[b.host][ver] = append(pl.nodeBlocks[b.host][ver], b)
}

func (pl *planner) blockFromSnapshot(b *model.AllocationBlock) (*simBlock, error) {
	pref, err := netip.ParsePrefix(b.CIDR.String())
	if err != nil {
		return nil, err
	}
	pref = pref.Masked()
	host := b.Host()
	affType := b.AffinityType()
	free := countFreeAddresses(b, pl.cfg.IPCooldownSeconds, pl.now, pl.resv)
	return &simBlock{
		prefix:  pref,
		host:    host,
		affType: affType,
		pool:    pl.poolForBlock(pref),
		free:    free,
	}, nil
}

// poolForBlock attributes an existing block to the pool that carved it:
// containing pools, preferring matching block size, then narrowest CIDR, then
// name - mirroring the accounting tracker's rules.
func (pl *planner) poolForBlock(pref netip.Prefix) *planPool {
	ver := 4
	if pref.Addr().BitLen() == 128 {
		ver = 6
	}
	var candidates []*planPool
	for _, pp := range pl.poolsByVersion[ver] {
		if pp.prefix.Contains(pref.Addr()) {
			candidates = append(candidates, pp)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		pi, pj := candidates[i], candidates[j]
		if (pi.blockBits == pref.Bits()) != (pj.blockBits == pref.Bits()) {
			return pi.blockBits == pref.Bits()
		}
		if pi.prefix.Bits() != pj.prefix.Bits() {
			return pi.prefix.Bits() > pj.prefix.Bits()
		}
		return pi.spec.Name < pj.spec.Name
	})
	return candidates[0]
}

// poolIsAllocatable mirrors clientv3.isCandidate: deleting, disabled and
// explicitly non-allocatable pools are skipped.
func poolIsAllocatable(p *v3.IPPool) bool {
	if !p.DeletionTimestamp.IsZero() {
		return false
	}
	if p.Spec.Disabled {
		return false
	}
	if p.Status != nil {
		for _, c := range p.Status.Conditions {
			if c.Type == v3.IPPoolConditionAllocatable && c.Status == metav1.ConditionFalse {
				return false
			}
		}
	}
	return true
}

// candidatePools returns the pools IPAM would consider for this demand in the
// given version: enabled, Automatic assignment mode, correct family, with
// allowedUses containing the intended use and selectors matching the node and
// namespace. Pools are returned in name order.
func (pl *planner) candidatePools(version int, nodeLabels, nsLabels map[string]string) []*planPool {
	var out []*planPool
	for _, pp := range pl.poolsByVersion[version] {
		p := &pp.spec
		if !poolIsAllocatable(p) {
			continue
		}
		if p.Spec.AssignmentMode != nil && *p.Spec.AssignmentMode != v3.Automatic {
			continue
		}
		if !slices.Contains(accounting.AllowedUses(p), pl.use) {
			continue
		}
		if !selectorMatches(p.Spec.NodeSelector, nodeLabels) {
			continue
		}
		if !selectorMatches(p.Spec.NamespaceSelector, nsLabels) {
			continue
		}
		out = append(out, pp)
	}
	return out
}

func selectorMatches(expr string, labels map[string]string) bool {
	if strings.TrimSpace(expr) == "" {
		return true
	}
	sel, err := selector.Parse(expr)
	if err != nil {
		return false
	}
	return sel.Evaluate(labels)
}

func (pl *planner) planDemand(d Demand, version int) DemandResult {
	res := DemandResult{
		Node:      d.Node,
		Namespace: d.Namespace,
		IPVersion: version,
		Requested: d.NumIPv4,
	}
	if version == 6 {
		res.Requested = d.NumIPv6
	}

	nodeLabels, nodeExists := pl.nodeLabels[d.Node]
	if !nodeExists {
		res.Unsatisfied = res.Requested
		res.Reasons = []string{fmt.Sprintf(reasonNoNodeFmt, d.Node)}
		return res
	}

	nsLabels := pl.nsLabels[d.Namespace]
	if d.Namespace != "" {
		if _, ok := pl.nsLabels[d.Namespace]; !ok {
			if _, reported := pl.missingNamespaces[d.Namespace]; !reported {
				pl.missingNamespaces[d.Namespace] = struct{}{}
				pl.warnings = append(pl.warnings,
					fmt.Sprintf("namespace %q was not found; its namespace selectors are evaluated against empty labels", d.Namespace))
			}
		}
	}

	candidates := pl.candidatePools(version, nodeLabels, nsLabels)
	if len(candidates) == 0 {
		res.Unsatisfied = res.Requested
		res.Reasons = []string{reasonNoMatchingPool}
		return res
	}
	candidateByName := map[string]*planPool{}
	for _, pp := range candidates {
		candidateByName[pp.spec.Name] = pp
	}

	remaining := res.Requested

	// Pass 1: fill from the node's existing (and already-planned) affine
	// blocks in these pools, lowest block address first - deterministic and
	// matching strict affinity (only own blocks can be used).
	nodeBlocks := slices.Clone(pl.nodeBlocks[d.Node][version])
	sort.Slice(nodeBlocks, func(i, j int) bool {
		return nodeBlocks[i].prefix.Addr().Compare(nodeBlocks[j].prefix.Addr()) < 0
	})
	for _, b := range nodeBlocks {
		if remaining == 0 {
			break
		}
		if b.pool == nil || candidateByName[b.pool.spec.Name] == nil {
			continue
		}
		if b.free <= 0 {
			continue
		}
		take := min(remaining, b.free)
		b.free -= take
		remaining -= take
		res.Satisfiable += take
	}

	// Pass 2: claim new blocks, one address request at a time, from the lowest
	// free block in pool order.
	if remaining > 0 && !pl.cfg.AutoAllocateBlocks {
		res.Unsatisfied = remaining
		res.Reasons = appendDedup(res.Reasons, reasonAutoAllocateOff)
		remaining = 0
	}
	for remaining > 0 {
		maxBlocks := pl.effectiveMaxBlocks()
		owned := 0
		for _, b := range pl.nodeBlocks[d.Node][version] {
			if b.pool != nil && candidateByName[b.pool.spec.Name] != nil {
				owned++
			}
		}
		if owned >= maxBlocks {
			res.Unsatisfied += remaining
			res.Reasons = appendDedup(res.Reasons, fmt.Sprintf(reasonBlockLimitFmt, maxBlocks))
			break
		}

		var claimed *simBlock
		var claimedPool *planPool
		for _, pp := range candidates {
			pref, capacity, ok := pp.nextFreeBlock(pl.occupied, pl.resv)
			if !ok {
				continue
			}
			sb := &simBlock{
				prefix:  pref,
				host:    d.Node,
				affType: model.IPAMAffinityTypeHost,
				pool:    pp,
				free:    capacity,
				planned: true,
			}
			pl.occupied[pref] = sb
			pl.addNodeBlock(sb)
			claimed = sb
			claimedPool = pp
			break
		}
		if claimed == nil {
			res.Unsatisfied += remaining
			res.Reasons = appendDedup(res.Reasons, reasonNoUnclaimedBlocks)
			break
		}

		take := min(remaining, claimed.free)
		claimed.free -= take
		remaining -= take
		res.Satisfiable += take
		pb := PlannedBlock{
			Node:           d.Node,
			IPVersion:      version,
			Pool:           claimedPool.spec.Name,
			PoolCIDR:       claimedPool.spec.Spec.CIDR,
			BlockCIDR:      claimed.prefix.String(),
			UsableCapacity: claimed.free + take,
		}
		res.NewBlocks = append(res.NewBlocks, pb)
		pl.planned = append(pl.planned, pb)
	}

	return res
}

func (pl *planner) effectiveMaxBlocks() int {
	if pl.cfg.MaxBlocksPerHost > 0 {
		return pl.cfg.MaxBlocksPerHost
	}
	return defaultMaxBlocksPerHost
}

func appendDedup(existing []string, s string) []string {
	if !slices.Contains(existing, s) {
		return append(existing, s)
	}
	return existing
}

// countFreeAddresses returns how many addresses the block could hand out
// right now. It deducts:
//   - existing allocations (not on the Unallocated list),
//   - IPReservation coverage,
//   - cooling addresses (released but their cooldown has not elapsed); cooling
//     addresses whose cooldown has elapsed count as free because loading the
//     block garbage-collects them before allocation, exactly as the allocator
//     does.
func countFreeAddresses(b *model.AllocationBlock, cooldownSeconds int, now time.Time, resv *reservationSet) int {
	pref, err := netip.ParsePrefix(b.CIDR.String())
	if err != nil {
		return 0
	}
	base := addrToBig(pref.Masked().Addr())
	bits := pref.Addr().BitLen()

	free := map[int]struct{}{}
	for _, ord := range b.Unallocated {
		free[ord] = struct{}{}
	}
	cutoff := now.Add(-time.Duration(cooldownSeconds) * time.Second)
	for ord, attrIdx := range b.Allocations {
		if attrIdx == nil || *attrIdx >= len(b.Attributes) {
			continue
		}
		attr := b.Attributes[*attrIdx]
		if attr.ReleasedAt == nil {
			continue
		}
		// Mirror allocationBlock.garbageCollect: with a negative cooldown the
		// address is reclaimable immediately; otherwise it is freed once the
		// release timestamp reaches the cutoff.
		if cooldownSeconds < 0 || attr.ReleasedAt.Time.Before(cutoff) {
			free[ord] = struct{}{}
		}
	}

	count := 0
	for ord := range free {
		addr := bigToAddr(bits, new(big.Int).Add(base, big.NewInt(int64(ord))))
		if !resv.contains(addr) {
			count++
		}
	}
	return count
}

// --- address-range math for IP reservations --------------------------------

type ipRange struct {
	from, to *big.Int
}

// reservationSet is the union of all reserved addresses, split by family and
// stored as sorted, non-overlapping ranges.
type reservationSet struct {
	r4, r6 []ipRange
}

func newReservationSet(cidrs []cnet.IPNet) (*reservationSet, error) {
	var builder netipx.IPSetBuilder
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c.String())
		if err != nil {
			return nil, err
		}
		builder.AddPrefix(p.Masked())
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil, err
	}
	out := &reservationSet{}
	for _, r := range set.Ranges() {
		ir := ipRange{from: addrToBig(r.From()), to: addrToBig(r.To())}
		if r.From().BitLen() == 32 {
			out.r4 = append(out.r4, ir)
		} else {
			out.r6 = append(out.r6, ir)
		}
	}
	return out, nil
}

func (s *reservationSet) rangesFor(addr netip.Addr) []ipRange {
	if addr.BitLen() == 32 {
		return s.r4
	}
	return s.r6
}

func (s *reservationSet) contains(addr netip.Addr) bool {
	n := addrToBig(addr)
	for _, r := range s.rangesFor(addr) {
		if r.to.Cmp(n) < 0 {
			continue
		}
		if r.from.Cmp(n) > 0 {
			break
		}
		return true
	}
	return false
}

// countInPrefix returns how many addresses of the prefix are reserved. Block
// prefixes hold at most 4096 addresses, so the result fits in an int.
func (s *reservationSet) countInPrefix(pref netip.Prefix) int {
	start := addrToBig(pref.Masked().Addr())
	size := new(big.Int).Lsh(big.NewInt(1), uint(pref.Addr().BitLen()-pref.Bits()))
	end := new(big.Int).Add(start, new(big.Int).Sub(size, big.NewInt(1)))

	total := big.NewInt(0)
	var ranges []ipRange
	if pref.Addr().BitLen() == 32 {
		ranges = s.r4
	} else {
		ranges = s.r6
	}
	for _, r := range ranges {
		if r.to.Cmp(start) < 0 {
			continue
		}
		if r.from.Cmp(end) > 0 {
			break
		}
		lo := new(big.Int).Set(r.from)
		if lo.Cmp(start) < 0 {
			lo.Set(start)
		}
		hi := new(big.Int).Set(r.to)
		if hi.Cmp(end) > 0 {
			hi.Set(end)
		}
		total.Add(total, new(big.Int).Add(new(big.Int).Sub(hi, lo), big.NewInt(1)))
	}
	return int(total.Int64())
}

func addrToBig(a netip.Addr) *big.Int {
	return new(big.Int).SetBytes(a.AsSlice())
}

func bigToAddr(bits int, n *big.Int) netip.Addr {
	width := bits / 8
	bs := n.Bytes()
	buf := make([]byte, width)
	if len(bs) > width {
		// Should be impossible for in-pool offsets; clamp defensively.
		bs = bs[len(bs)-width:]
	}
	copy(buf[width-len(bs):], bs)
	addr, _ := netip.AddrFromSlice(buf)
	return addr
}
