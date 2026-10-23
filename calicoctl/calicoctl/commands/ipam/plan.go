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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/accounting"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// demandDocument is the YAML/JSON file accepted by "calicoctl ipam plan".
//
// Example:
//
//	demands:
//	  - node: node-a
//	    namespace: default
//	    ipv4: 30
//	    ipv6: 30
type demandDocument struct {
	Demands []Demand `json:"demands" yaml:"demands"`
}

// LoadDemands reads and validates the demand file.
func LoadDemands(path string) ([]Demand, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read demand file %s: %w", path, err)
	}
	var doc demandDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse demand file %s: %w", path, err)
	}
	if len(doc.Demands) == 0 {
		return nil, fmt.Errorf("demand file %s contains no demands", path)
	}
	seen := map[string]struct{}{}
	for i, d := range doc.Demands {
		if d.Node == "" {
			return nil, fmt.Errorf("demand entry %d is missing a node", i)
		}
		if d.NumIPv4 < 0 || d.NumIPv6 < 0 {
			return nil, fmt.Errorf("demand entry %d (node %q) has negative address counts", i, d.Node)
		}
		if d.NumIPv4 == 0 && d.NumIPv6 == 0 {
			return nil, fmt.Errorf("demand entry %d (node %q) requests no IPv4 or IPv6 addresses", i, d.Node)
		}
		key := d.Node + "/" + d.Namespace
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("demand file lists node %q, namespace %q more than once; combine them into one entry", d.Node, d.Namespace)
		}
		seen[key] = struct{}{}
	}
	return doc.Demands, nil
}

// PlanIPAM reads the current IPAM snapshot, simulates the requested
// allocations entirely in memory, and prints the resulting plan. It never
// creates blocks, claims affinity or changes allocations.
func PlanIPAM(ctx context.Context, config, demandPath, useStr, outFile, kubeconfig string) error {
	use := v3.IPPoolAllowedUse(useStr)
	if use != v3.IPPoolAllowedUseWorkload && use != v3.IPPoolAllowedUseTunnel {
		return fmt.Errorf("invalid --use %q: must be Workload or Tunnel", useStr)
	}

	demands, err := LoadDemands(demandPath)
	if err != nil {
		return err
	}

	client, err := clientmgr.NewClient(config)
	if err != nil {
		return err
	}
	bc := client.(bapi.BackendAccessor).Backend()

	// Snapshot read starts here; everything below is treated as one logical
	// point-in-time view even though each resource carries its own revision.
	takenAt := time.Now()

	ipamClient := client.IPAM()
	ipamConfig, err := ipamClient.GetIPAMConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to read IPAM configuration: %w", err)
	}
	if !ipamConfig.StrictAffinity {
		return fmt.Errorf("ipam plan is only supported with strict affinity enabled (set StrictAffinity=true with \"calicoctl ipam configure\")")
	}

	revs := SnapshotInfo{TakenAt: takenAt}
	if cfgKVP, err := bc.Get(ctx, model.IPAMConfigKey{}, ""); err == nil {
		revs.IPAMConfigRV = cfgKVP.Revision
	}

	pools, poolRV, err := listPools(ctx, client)
	if err != nil {
		return err
	}
	revs.IPPoolsRV = poolRV

	nodeLabels, nodeRV, err := listNodeLabels(ctx, client)
	if err != nil {
		return err
	}
	revs.NodesRV = nodeRV

	nsLabels, nsRV, nsNote, err := listNamespaceLabels(ctx, config, bc, kubeconfig)
	if err != nil {
		return err
	}
	revs.NamespacesRV = nsRV
	revs.NamespacesUnavailableMsg = nsNote

	reservations, resvRV, err := listReservationCIDRs(ctx, client)
	if err != nil {
		return err
	}
	revs.IPReservationsRV = resvRV

	blocks, blockRV, err := listBlocks(ctx, bc)
	if err != nil {
		return err
	}
	revs.BlocksRV = blockRV

	affinities, affRV, err := listAffinities(ctx, bc)
	if err != nil {
		// Affinities are an optimization hint for block counts; the blocks
		// list already carries current affinity. Warn rather than fail.
		affinities = nil
		fmt.Fprintf(os.Stderr, "Warning: failed to list block affinities: %v\n", err)
	}
	revs.BlockAffinitiesRV = affRV

	report, err := RunPlan(PlanInput{
		Config:          *ipamConfig,
		IntendedUse:     use,
		Pools:           pools,
		NodeLabels:      nodeLabels,
		NamespaceLabels: nsLabels,
		Reservations:    reservations,
		Blocks:          blocks,
		Affinities:      affinities,
		Demands:         demands,
		Revisions:       revs,
	})
	if err != nil {
		return err
	}

	renderPlan(report)

	if outFile != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(outFile, data, 0o644); err != nil {
			return fmt.Errorf("failed to write plan report %s: %w", outFile, err)
		}
		fmt.Printf("\nPlan report written to %s\n", outFile)
	}

	return nil
}

func listPools(ctx context.Context, client clientv3.Interface) ([]v3.IPPool, string, error) {
	l, err := client.IPPools().List(ctx, options.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to list IP pools: %w", err)
	}
	return l.Items, l.ResourceVersion, nil
}

func listNodeLabels(ctx context.Context, client clientv3.Interface) (map[string]map[string]string, string, error) {
	l, err := client.Nodes().List(ctx, options.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to list nodes: %w", err)
	}
	out := make(map[string]map[string]string, len(l.Items))
	for _, n := range l.Items {
		out[n.Name] = n.Labels
	}
	return out, l.ResourceVersion, nil
}

func listReservationCIDRs(ctx context.Context, client clientv3.Interface) ([]cnet.IPNet, string, error) {
	l, err := client.IPReservations().List(ctx, options.ListOptions{})
	if err != nil {
		return nil, "", fmt.Errorf("failed to list IP reservations: %w", err)
	}
	items := make([]*v3.IPReservation, 0, len(l.Items))
	for i := range l.Items {
		items = append(items, &l.Items[i])
	}
	return accounting.ReservationCIDRs(items), l.ResourceVersion, nil
}

func listBlocks(ctx context.Context, bc bapi.Client) ([]*model.AllocationBlock, string, error) {
	l, err := bc.List(ctx, model.BlockListOptions{}, "")
	if err != nil {
		return nil, "", fmt.Errorf("failed to list IPAM blocks: %w", err)
	}
	out := make([]*model.AllocationBlock, 0, len(l.KVPairs))
	for _, kvp := range l.KVPairs {
		if b, ok := kvp.Value.(*model.AllocationBlock); ok {
			out = append(out, b)
		}
	}
	return out, l.Revision, nil
}

func listAffinities(ctx context.Context, bc bapi.Client) ([]AffinityRef, string, error) {
	l, err := bc.List(ctx, model.BlockAffinityListOptions{}, "")
	if err != nil {
		return nil, "", err
	}
	out := make([]AffinityRef, 0, len(l.KVPairs))
	for _, kvp := range l.KVPairs {
		key, ok := kvp.Key.(model.BlockAffinityKey)
		if !ok {
			continue
		}
		affType := key.AffinityType
		if affType == "" {
			affType = model.IPAMAffinityTypeHost
		}
		state := model.StateConfirmed
		if ba, ok := kvp.Value.(*model.BlockAffinity); ok {
			state = ba.State
		}
		out = append(out, AffinityRef{
			Host:         key.Host,
			AffinityType: affType,
			CIDR:         key.CIDR,
			State:        state,
		})
	}
	return out, l.Revision, nil
}

// listNamespaceLabels loads namespace labels using a Kubernetes client, the
// same way "ipam check" does. Missing labels evaluate against empty maps.
func listNamespaceLabels(ctx context.Context, config string, bc bapi.Client, kubeconfig string) (map[string]map[string]string, string, string, error) {
	var restConfig *rest.Config
	if _, ok := bc.(*k8s.KubeClient); ok {
		cfg, err := clientmgr.LoadClientConfig(config)
		if err != nil {
			return nil, "", "", err
		}
		restConfig, _, err = k8s.CreateKubernetesClientset(&cfg.Spec)
		if err != nil {
			return nil, "", "", err
		}
	} else {
		kubeConfigPath := os.Getenv("KUBECONFIG")
		if kubeconfig != "" {
			kubeConfigPath = kubeconfig
		}
		if kubeConfigPath == "" {
			return map[string]map[string]string{}, "", "Kubernetes API unavailable; namespace selectors evaluated against empty labels", nil
		}
		var err error
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
		if err != nil {
			return nil, "", "", err
		}
	}

	kubeClient, err := NewKubeClient(restConfig)
	if err != nil {
		return nil, "", "", err
	}
	var nsList corev1.NamespaceList
	if err := kubeClient.List(ctx, &nsList); err != nil {
		return nil, "", "", fmt.Errorf("failed to list namespaces: %w", err)
	}
	out := make(map[string]map[string]string, len(nsList.Items))
	for _, ns := range nsList.Items {
		out[ns.Name] = ns.Labels
	}
	return out, nsList.ResourceVersion, "", nil
}

func renderPlan(report *PlanReport) {
	fmt.Println("IPAM capacity plan (read-only simulation)")
	fmt.Println(PlanNote)
	fmt.Println()
	fmt.Printf("Snapshot taken at: %s\n", report.Snapshot.TakenAt.Format(time.RFC3339))
	fmt.Printf("Intended use:      %s\n", report.IntendedUse)
	fmt.Println()

	cfg := table.NewWriter()
	cfg.SetOutputMirror(os.Stdout)
	cfg.AppendHeader(table.Row{"IPAM SETTING", "VALUE"})
	cfg.AppendRow(table.Row{"StrictAffinity", report.Config.StrictAffinity})
	cfg.AppendRow(table.Row{"AutoAllocateBlocks", report.Config.AutoAllocateBlocks})
	cfg.AppendRow(table.Row{"MaxBlocksPerHost", report.Config.MaxBlocksPerHost})
	cfg.AppendRow(table.Row{"Effective blocks/host limit", report.Config.EffectiveMaxBlocksPerHost})
	cfg.AppendRow(table.Row{"IPCooldownSeconds", report.Config.IPCooldownSeconds})
	cfg.Render()
	fmt.Println()

	revs := table.NewWriter()
	revs.SetOutputMirror(os.Stdout)
	revs.AppendHeader(table.Row{"SNAPSHOT RESOURCE", "RESOURCE VERSION"})
	revs.AppendRow(table.Row{"IP pools", report.Snapshot.IPPoolsRV})
	revs.AppendRow(table.Row{"Nodes", report.Snapshot.NodesRV})
	if report.Snapshot.NamespacesRV != "" {
		revs.AppendRow(table.Row{"Namespaces", report.Snapshot.NamespacesRV})
	}
	revs.AppendRow(table.Row{"IP reservations", report.Snapshot.IPReservationsRV})
	revs.AppendRow(table.Row{"IPAM blocks", report.Snapshot.BlocksRV})
	if report.Snapshot.BlockAffinitiesRV != "" {
		revs.AppendRow(table.Row{"Block affinities", report.Snapshot.BlockAffinitiesRV})
	}
	if report.Snapshot.IPAMConfigRV != "" {
		revs.AppendRow(table.Row{"IPAM config", report.Snapshot.IPAMConfigRV})
	}
	revs.Render()
	if report.Snapshot.NamespacesUnavailableMsg != "" {
		fmt.Printf("\nNote: %s.\n", report.Snapshot.NamespacesUnavailableMsg)
	}
	fmt.Println()

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"NODE", "NAMESPACE", "IP", "REQUESTED", "SATISFIABLE", "UNSATISFIED", "NEW BLOCKS", "UNMET REASON"})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: "REQUESTED", Align: text.AlignRight},
		{Name: "SATISFIABLE", Align: text.AlignRight},
		{Name: "UNSATISFIED", Align: text.AlignRight},
		{Name: "NEW BLOCKS", Align: text.AlignRight},
	})
	var totalReq, totalSat, totalUnsat int
	for _, r := range report.Results {
		totalReq += r.Requested
		totalSat += r.Satisfiable
		totalUnsat += r.Unsatisfied
		t.AppendRow(table.Row{
			r.Node,
			r.Namespace,
			fmt.Sprintf("IPv%d", r.IPVersion),
			r.Requested,
			r.Satisfiable,
			r.Unsatisfied,
			len(r.NewBlocks),
			joinReasons(r.Reasons),
		})
	}
	t.AppendFooter(table.Row{"", "", "TOTAL", totalReq, totalSat, totalUnsat, len(report.NewBlocks), ""})
	t.Render()

	if len(report.NewBlocks) > 0 {
		fmt.Println()
		fmt.Println("Blocks that would need to be newly claimed (sorted by node, pool CIDR, block address):")
		nb := table.NewWriter()
		nb.SetOutputMirror(os.Stdout)
		nb.AppendHeader(table.Row{"NODE", "IP", "POOL", "POOL CIDR", "NEW BLOCK CIDR", "USABLE ADDRESSES"})
		nb.SetColumnConfigs([]table.ColumnConfig{
			{Name: "USABLE ADDRESSES", Align: text.AlignRight},
		})
		for _, b := range report.NewBlocks {
			nb.AppendRow(table.Row{
				b.Node,
				fmt.Sprintf("IPv%d", b.IPVersion),
				b.Pool,
				b.PoolCIDR,
				b.BlockCIDR,
				b.UsableCapacity,
			})
		}
		nb.Render()
	}

	for _, w := range report.Warnings {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
	}
}

func joinReasons(reasons []string) string {
	out := ""
	for i, r := range reasons {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}
