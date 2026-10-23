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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestLoadDemands(t *testing.T) {
	t.Run("valid YAML", func(t *testing.T) {
		p := writeTemp(t, "d.yaml", `
demands:
  - node: n-a
    namespace: default
    ipv4: 10
    ipv6: 10
  - node: n-b
    ipv4: 1
`)
		got, err := LoadDemands(p)
		if err != nil {
			t.Fatalf("LoadDemands: %v", err)
		}
		if len(got) != 2 || got[0].Node != "n-a" || got[0].NumIPv6 != 10 || got[1].Namespace != "" {
			t.Fatalf("unexpected demands: %+v", got)
		}
	})

	t.Run("valid JSON", func(t *testing.T) {
		p := writeTemp(t, "d.json", `{"demands":[{"node":"n-a","ipv4":3}]}`)
		got, err := LoadDemands(p)
		if err != nil || len(got) != 1 || got[0].NumIPv4 != 3 {
			t.Fatalf("LoadDemands: got=%+v err=%v", got, err)
		}
	})

	for _, tc := range []struct {
		name, content, want string
	}{
		{"empty", "", "contains no demands"},
		{"missing node", "demands:\n  - ipv4: 1\n", "missing a node"},
		{"zero counts", "demands:\n  - node: n-a\n", "requests no IPv4 or IPv6"},
		{"negative", "demands:\n  - node: n-a\n    ipv4: -1\n", "negative address counts"},
		{"duplicate", "demands:\n  - {node: n-a, namespace: x, ipv4: 1}\n  - {node: n-a, namespace: x, ipv4: 1}\n", "more than once"},
		{"malformed", "{not yaml", "failed to parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeTemp(t, "d.yaml", tc.content)
			_, err := LoadDemands(p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadDemands(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestPlanReportJSONRoundTripAndRender(t *testing.T) {
	in := baseInput()
	in.Pools = []v3.IPPool{testPool("p4", "10.0.0.0/24", func(s *v3.IPPoolSpec) { s.BlockSize = 26 })}
	in.Demands = []Demand{{Node: "n-a", Namespace: "default", NumIPv4: 100}}
	in.Revisions = SnapshotInfo{
		TakenAt:          planNow,
		IPPoolsRV:        "100",
		NodesRV:          "7",
		IPReservationsRV: "3",
		BlocksRV:         "42",
	}

	report, err := RunPlan(in)
	if err != nil {
		t.Fatalf("RunPlan: %v", err)
	}
	if report.Note == "" || !strings.Contains(report.Note, "snapshot") {
		t.Errorf("missing snapshot note: %q", report.Note)
	}
	if report.Snapshot.BlocksRV != "42" {
		t.Errorf("block revision not recorded: %+v", report.Snapshot)
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back PlanReport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.NewBlocks) != 2 || back.NewBlocks[0].BlockCIDR != "10.0.0.0/26" {
		t.Fatalf("roundtrip lost new blocks: %+v", back.NewBlocks)
	}

	// Rendering the report must not panic.
	renderPlan(&back)
}
