// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package networkset

import (
	"bytes"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"sigs.k8s.io/yaml"
)

// subtractCIDRs is a small convenience around the prefix trie: it builds a
// source set from the given CIDRs, subtracts the second list, and returns the
// coalesced, sorted remainder.
func subtractCIDRs(t *testing.T, source, subtract []string) []string {
	t.Helper()
	v4 := newPrefixTrie(32)
	v6 := newPrefixTrie(128)
	for _, c := range source {
		p, err := parsePrefix(c)
		if err != nil {
			t.Fatalf("unexpected error parsing source CIDR %q: %v", c, err)
		}
		if p.bits == 32 {
			v4.Add(p)
		} else {
			v6.Add(p)
		}
	}
	for _, c := range subtract {
		p, err := parsePrefix(c)
		if err != nil {
			t.Fatalf("unexpected error parsing subtract CIDR %q: %v", c, err)
		}
		if p.bits == 32 {
			v4.Remove(p)
		} else {
			v6.Remove(p)
		}
	}
	return append(v4.CIDRStrings(), v6.CIDRStrings()...)
}

func TestParsePrefix(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"10.0.0.0/24", "10.0.0.0/24"},
		// Host bits are masked off into the canonical network.
		{"10.0.0.5/24", "10.0.0.0/24"},
		// Bare IPs become host prefixes.
		{"10.0.0.1", "10.0.0.1/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:db8::/32", "2001:db8::/32"},
		// Default routes.
		{"0.0.0.0/0", "0.0.0.0/0"},
		{"::/0", "::/0"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			p, err := parsePrefix(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := p.String(); got != tc.want {
				t.Errorf("parsePrefix(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}

	for _, bad := range []string{"not-a-cidr", "10.0.0.0/40", "2001:db8::/129", "10.0.0.0/", "/24"} {
		t.Run("invalid/"+bad, func(t *testing.T) {
			if _, err := parsePrefix(bad); err == nil {
				t.Errorf("parsePrefix(%q) expected an error, got nil", bad)
			}
		})
	}
}

func TestPrefixTrieSubtract(t *testing.T) {
	for _, tc := range []struct {
		name     string
		source   []string
		subtract []string
		want     []string
	}{
		{
			name:     "simple split keeps lower half",
			source:   []string{"10.0.0.0/24"},
			subtract: []string{"10.0.0.128/25"},
			want:     []string{"10.0.0.0/25"},
		},
		{
			name:     "carve middle quarter",
			source:   []string{"10.0.0.0/24"},
			subtract: []string{"10.0.0.64/26"},
			want:     []string{"10.0.0.0/26", "10.0.0.128/25"},
		},
		{
			name:     "carve two middle quarters",
			source:   []string{"10.0.0.0/24"},
			subtract: []string{"10.0.0.64/26", "10.0.0.128/26"},
			want:     []string{"10.0.0.0/26", "10.0.0.192/26"},
		},
		{
			name:     "full coverage by same prefix",
			source:   []string{"10.0.0.0/24"},
			subtract: []string{"10.0.0.0/24"},
			want:     nil,
		},
		{
			name:     "full coverage by larger prefix",
			source:   []string{"10.0.0.0/24", "10.0.1.0/24"},
			subtract: []string{"10.0.0.0/16"},
			want:     nil,
		},
		{
			name:     "full coverage of whole address space",
			source:   []string{"0.0.0.0/0"},
			subtract: []string{"0.0.0.0/0"},
			want:     nil,
		},
		{
			name:     "non-overlapping subtraction is a no-op",
			source:   []string{"10.0.0.0/24"},
			subtract: []string{"192.168.0.0/24"},
			want:     []string{"10.0.0.0/24"},
		},
		{
			name:     "bare IP subtracts host prefix",
			source:   []string{"10.0.0.1/32"},
			subtract: []string{"10.0.0.1"},
			want:     nil,
		},
		{
			name:     "overlapping subtracts cover whole block",
			source:   []string{"10.0.0.0/24"},
			subtract: []string{"10.0.0.0/25", "10.0.0.128/25"},
			want:     nil,
		},
		{
			name:     "duplicate sources are de-duplicated",
			source:   []string{"10.0.0.0/24", "10.0.0.0/24"},
			subtract: nil,
			want:     []string{"10.0.0.0/24"},
		},
		{
			name:     "nested prefix is absorbed by its parent",
			source:   []string{"10.0.0.0/16", "10.0.1.0/24"},
			subtract: nil,
			want:     []string{"10.0.0.0/16"},
		},
		{
			name:     "adjacent halves merge into parent",
			source:   []string{"10.0.0.0/25", "10.0.0.128/25"},
			subtract: nil,
			want:     []string{"10.0.0.0/24"},
		},
		{
			name:     "quarters merge all the way to the default route",
			source:   []string{"0.0.0.0/1", "128.0.0.0/1"},
			subtract: nil,
			want:     []string{"0.0.0.0/0"},
		},
		{
			name:     "results are numerically sorted",
			source:   []string{"192.168.0.0/16", "10.0.0.0/24", "1.0.1.0/24"},
			subtract: nil,
			want:     []string{"1.0.1.0/24", "10.0.0.0/24", "192.168.0.0/16"},
		},
		{
			name:     "IPv6 simple split",
			source:   []string{"2001:db8::/32"},
			subtract: []string{"2001:db8::/33"},
			want:     []string{"2001:db8:8000::/33"},
		},
		{
			name:     "IPv6 full coverage",
			source:   []string{"2001:db8::/32"},
			subtract: []string{"2001:db8::/32"},
			want:     nil,
		},
		{
			name:     "IPv6 host removal yields 96 exact prefixes",
			source:   []string{"2001:db8::/32"},
			subtract: []string{"2001:db8::1/128"},
			want:     ipv6HostRemovalWant(),
		},
		{
			name:     "mixed families subtract only the matching family",
			source:   []string{"10.0.0.0/24", "2001:db8::/32"},
			subtract: []string{"10.0.0.0/24"},
			want:     []string{"2001:db8::/32"},
		},
		{
			name:     "whole IPv4 space removed leaves IPv6 intact",
			source:   []string{"10.0.0.0/24", "2001:db8::/32"},
			subtract: []string{"0.0.0.0/0"},
			want:     []string{"2001:db8::/32"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := subtractCIDRs(t, tc.source, tc.subtract)
			if len(tc.want) == 0 {
				if len(got) != 0 {
					t.Errorf("remainder = %v, want empty", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("remainder = %v, want %v", got, tc.want)
			}
		})
	}
}

// ipv6HostRemovalWant independently computes the expected remainder of
// 2001:db8::1/128 subtracted from 2001:db8::/32: one sibling prefix at each
// level from /128 up to /33 - 128-32 = 96 prefixes, in ascending numerical
// order (which is how the trie enumerates them).
func ipv6HostRemovalWant() []string {
	host := new(big.Int).SetBytes(net.ParseIP("2001:db8::1").To16())
	want := make([]string, 0, 96)
	for depth := 127; depth >= 32; depth-- {
		bitIndex := 127 - depth
		sibling := new(big.Int).Set(host)
		sibling.SetBit(sibling, bitIndex, 1-host.Bit(bitIndex))
		// Clear all bits below this level to get the prefix address.
		lowBits := uint(128 - (depth + 1))
		sibling.Rsh(sibling, lowBits)
		sibling.Lsh(sibling, lowBits)
		raw := sibling.Bytes()
		if len(raw) < 16 {
			padded := make([]byte, 16)
			copy(padded[16-len(raw):], raw)
			raw = padded
		}
		ipNet := &net.IPNet{IP: net.IP(raw), Mask: net.CIDRMask(depth+1, 128)}
		want = append(want, ipNet.String())
	}
	return want
}

// TestSubtractCommandEndToEnd drives the public Subtract entry point with
// resources on disk and checks the resulting YAML.
func TestSubtractCommandEndToEnd(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: allow-list
  namespace: default
  resourceVersion: "42"
  uid: 1a2b3c4d-5e6f-7890-abcd-ef0123456789
  generation: 3
  creationTimestamp: "2024-01-01T00:00:00Z"
  labels:
    zone: dmz
    team: net
  annotations:
    note: kept
spec:
  nets:
  - 10.0.0.0/24
  - 10.0.0.0/25
  - 192.168.0.0/16
  - 2001:db8::/32
`
	path := writeFile(t, "netset.yaml", manifest)

	var out bytes.Buffer
	err := Subtract(Options{
		Filename:      path,
		SubtractCIDRs: []string{"10.0.0.0/25", "192.168.1.0/24"},
	}, &out)
	if err != nil {
		t.Fatalf("Subtract returned an error: %v", err)
	}

	var got apiv3.NetworkSet
	if err := yaml.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid YAML for a NetworkSet: %v\n%s", err, out.String())
	}

	if got.Name != "allow-list" {
		t.Errorf("name = %q, want allow-list", got.Name)
	}
	if got.Namespace != "default" {
		t.Errorf("namespace = %q, want default", got.Namespace)
	}
	if got.Labels["zone"] != "dmz" || got.Labels["team"] != "net" {
		t.Errorf("labels were not preserved: %v", got.Labels)
	}
	if got.Annotations["note"] != "kept" {
		t.Errorf("annotations were not preserved: %v", got.Annotations)
	}
	if got.ResourceVersion != "" || got.UID != "" || got.Generation != 0 || !got.CreationTimestamp.IsZero() {
		t.Errorf("server-generated metadata was not stripped: %+v", got.ObjectMeta)
	}

	// 192.168.1.0/24 carved out of 192.168.0.0/16 leaves the canonical set
	// of fragments that exactly cover the rest of the /16.
	wantNets := []string{
		"10.0.0.128/25",
		"192.168.0.0/24",
		"192.168.2.0/23",
		"192.168.4.0/22",
		"192.168.8.0/21",
		"192.168.16.0/20",
		"192.168.32.0/19",
		"192.168.64.0/18",
		"192.168.128.0/17",
		"2001:db8::/32",
	}
	if !reflect.DeepEqual(got.Spec.Nets, wantNets) {
		t.Errorf("nets = %v, want %v", got.Spec.Nets, wantNets)
	}
}

func TestSubtractGlobalNetworkSet(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: global-allow
  labels:
    scope: global
spec:
  nets:
  - 0.0.0.0/0
`
	var out bytes.Buffer
	err := Subtract(Options{
		Filename:      writeFile(t, "gns.yaml", manifest),
		SubtractCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}, &out)
	if err != nil {
		t.Fatalf("Subtract returned an error: %v", err)
	}

	var got apiv3.GlobalNetworkSet
	if err := yaml.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid YAML for a GlobalNetworkSet: %v\n%s", err, out.String())
	}
	if got.Name != "global-allow" {
		t.Errorf("name = %q, want global-allow", got.Name)
	}
	if got.Namespace != "" {
		t.Errorf("GlobalNetworkSet namespace should be empty, got %q", got.Namespace)
	}
	if got.Labels["scope"] != "global" {
		t.Errorf("labels were not preserved: %v", got.Labels)
	}
	// Removing the three private ranges from 0.0.0.0/0 yields many exact
	// fragments; every remaining prefix must be disjoint from the removed
	// ranges (e.g. 172.0.0.0/12 is public and must remain).
	if len(got.Spec.Nets) == 0 {
		t.Fatal("expected remaining public address ranges, got an empty set")
	}
	removed := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	for _, c := range got.Spec.Nets {
		for _, r := range removed {
			if cidrsOverlap(c, r) {
				t.Errorf("removed range %s leaked into remainder: %s", r, c)
			}
		}
	}
	// A few well-known public prefixes must survive the subtraction.
	for _, kept := range []string{"172.0.0.0/12", "8.0.0.0/8"} {
		if !cidrCoveredBySet(kept, got.Spec.Nets) {
			t.Errorf("expected public prefix %s to be represented in the remainder: %v", kept, got.Spec.Nets)
		}
	}
}

// cidrsOverlap reports whether two CIDR strings overlap.
func cidrsOverlap(a, b string) bool {
	_, na, err := net.ParseCIDR(a)
	if err != nil {
		return false
	}
	_, nb, err := net.ParseCIDR(b)
	if err != nil {
		return false
	}
	return na.Contains(nb.IP) || nb.Contains(na.IP)
}

// cidrCoveredBySet reports whether every address of cidr falls inside one of
// the CIDRs in the set.
func cidrCoveredBySet(cidr string, set []string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, s := range set {
		_, ns, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		if ns.Contains(n.IP) {
			onesA, _ := n.Mask.Size()
			onesB, _ := ns.Mask.Size()
			if onesB <= onesA {
				return true
			}
		}
	}
	return false
}

func TestSubtractEmptyResultOmitsNets(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: empty-after
  namespace: default
spec:
  nets:
  - 10.0.0.0/24
`
	var out bytes.Buffer
	err := Subtract(Options{
		Filename:      writeFile(t, "empty.yaml", manifest),
		SubtractCIDRs: []string{"10.0.0.0/24"},
	}, &out)
	if err != nil {
		t.Fatalf("Subtract returned an error: %v", err)
	}
	if strings.Contains(out.String(), "nets:") {
		t.Errorf("expected nets to be omitted for an empty result, got:\n%s", out.String())
	}
	// The document must still parse as a complete, apply-able NetworkSet.
	var got apiv3.NetworkSet
	if err := yaml.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, out.String())
	}
	if got.Name != "empty-after" || len(got.Spec.Nets) != 0 {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestSubtractSubtractFile(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: with-list-file
spec:
  nets:
  - 10.0.0.0/24
  - 10.1.0.0/24
  - 10.2.0.0/24
`
	listFile := writeFile(t, "cidrs.txt", `# CIDRs to remove
10.0.0.0/24, 10.1.0.0/24

# blank and comment lines are ignored
   10.2.0.128/25
`)

	var out bytes.Buffer
	err := Subtract(Options{
		Filename:      writeFile(t, "gns.yaml", manifest),
		SubtractFiles: []string{listFile},
	}, &out)
	if err != nil {
		t.Fatalf("Subtract returned an error: %v", err)
	}
	var got apiv3.GlobalNetworkSet
	if err := yaml.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out.String())
	}
	wantNets := []string{"10.2.0.0/25"}
	if !reflect.DeepEqual(got.Spec.Nets, wantNets) {
		t.Errorf("nets = %v, want %v", got.Spec.Nets, wantNets)
	}
}

func TestSubtractMultipleDocumentsAndListExpansion(t *testing.T) {
	// A NetworkSetList document and a standalone GlobalNetworkSet document.
	manifest := `apiVersion: projectcalico.org/v3
kind: NetworkSetList
items:
- apiVersion: projectcalico.org/v3
  kind: NetworkSet
  metadata:
    name: first
    namespace: team-a
  spec:
    nets:
    - 10.0.0.0/24
- apiVersion: projectcalico.org/v3
  kind: NetworkSet
  metadata:
    name: second
    namespace: team-b
  spec:
    nets:
    - 10.0.0.0/24
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: third
spec:
  nets:
  - 2001:db8::/32
`
	var out bytes.Buffer
	err := Subtract(Options{
		Filename:      writeFile(t, "multi.yaml", manifest),
		SubtractCIDRs: []string{"10.0.0.0/24"},
	}, &out)
	if err != nil {
		t.Fatalf("Subtract returned an error: %v", err)
	}
	if strings.Count(out.String(), "---") != 3 {
		t.Errorf("expected 3 YAML documents, got:\n%s", out.String())
	}

	var sets []apiv3.NetworkSet
	var globals []apiv3.GlobalNetworkSet
	docs := strings.Split(out.String(), "\n---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var head struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &head); err != nil {
			t.Fatalf("failed to parse output document: %v", err)
		}
		switch head.Kind {
		case apiv3.KindNetworkSet:
			var ns apiv3.NetworkSet
			if err := yaml.Unmarshal([]byte(doc), &ns); err != nil {
				t.Fatalf("failed to parse NetworkSet output: %v", err)
			}
			sets = append(sets, ns)
		case apiv3.KindGlobalNetworkSet:
			var gns apiv3.GlobalNetworkSet
			if err := yaml.Unmarshal([]byte(doc), &gns); err != nil {
				t.Fatalf("failed to parse GlobalNetworkSet output: %v", err)
			}
			globals = append(globals, gns)
		}
	}
	if len(sets) != 2 || len(globals) != 1 {
		t.Fatalf("expected 2 NetworkSets and 1 GlobalNetworkSet, got %d and %d", len(sets), len(globals))
	}
	if sets[0].Name != "first" || sets[0].Namespace != "team-a" || len(sets[0].Spec.Nets) != 0 {
		t.Errorf("unexpected first NetworkSet: %+v", sets[0])
	}
	if sets[1].Name != "second" || sets[1].Namespace != "team-b" || len(sets[1].Spec.Nets) != 0 {
		t.Errorf("unexpected second NetworkSet: %+v", sets[1])
	}
	if globals[0].Name != "third" || !reflect.DeepEqual(globals[0].Spec.Nets, []string{"2001:db8::/32"}) {
		t.Errorf("unexpected GlobalNetworkSet: %+v", globals[0])
	}
}

func TestSubtractErrorsProduceNoOutput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		manifest   string
		cidrs      []string
		listFile   string
		wantErrSub string
	}{
		{
			name: "invalid CIDR in subtraction list",
			manifest: `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: bad-sub
  namespace: default
spec:
  nets:
  - 10.0.0.0/24
`,
			cidrs:      []string{"not-a-cidr"},
			wantErrSub: "invalid CIDR",
		},
		{
			name: "invalid net in resource",
			manifest: `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: bad-net
  namespace: default
spec:
  nets:
  - nonsense/99
`,
			cidrs:      []string{"10.0.0.0/25"},
			wantErrSub: "failed to parse net",
		},
		{
			name: "unsupported resource kind",
			manifest: `apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: not-a-network-set
spec:
  cidr: 10.0.0.0/24
`,
			cidrs:      []string{"10.0.0.0/25"},
			wantErrSub: "unsupported resource kind",
		},
		{
			name: "missing name",
			manifest: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  labels:
    a: b
spec:
  nets:
  - 10.0.0.0/24
`,
			cidrs:      []string{"10.0.0.0/25"},
			wantErrSub: "missing metadata.name",
		},
		{
			name: "global network set with namespace",
			manifest: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: gns
  namespace: default
spec:
  nets:
  - 10.0.0.0/24
`,
			cidrs:      []string{"10.0.0.0/25"},
			wantErrSub: "must not be specified for GlobalNetworkSet",
		},
		{
			name: "invalid CIDR in subtract file",
			manifest: `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: bad-file
  namespace: default
spec:
  nets:
  - 10.0.0.0/24
`,
			listFile:   "garbage\n",
			wantErrSub: "invalid CIDR",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := Options{
				Filename:      writeFile(t, "in.yaml", tc.manifest),
				SubtractCIDRs: tc.cidrs,
			}
			if tc.listFile != "" {
				opts.SubtractFiles = []string{writeFile(t, "list.txt", tc.listFile)}
			}
			var out bytes.Buffer
			err := Subtract(opts, &out)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error %q should contain %q", err.Error(), tc.wantErrSub)
			}
			if out.Len() != 0 {
				t.Errorf("expected no output on error, but got:\n%s", out.String())
			}
		})
	}
}

func TestSubtractRequiresFilename(t *testing.T) {
	var out bytes.Buffer
	err := Subtract(Options{SubtractCIDRs: []string{"10.0.0.0/24"}}, &out)
	if err == nil || !strings.Contains(err.Error(), "--filename") {
		t.Errorf("expected a --filename error, got %v", err)
	}
}

func TestReadCIDRListFileToleratesBOMAndNoise(t *testing.T) {
	contents := "\uFEFF# leading comment\r\n10.0.0.0/24, 10.1.0.0/24 # inline comment\r\n\r\n  10.2.0.128/25\r\n"
	path := writeFile(t, "bom.txt", contents)
	tokens, err := readCIDRListFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// BOM, CRLF, blank lines, full-line and inline comments must all be
	// tolerated.
	want := []string{"10.0.0.0/24", "10.1.0.0/24", "10.2.0.128/25"}
	if !reflect.DeepEqual(tokens, want) {
		t.Errorf("tokens = %v, want %v", tokens, want)
	}
}

func TestSubtractStdin(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: from-stdin
spec:
  nets:
  - 10.0.0.0/24
`
	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdin = r
	go func() {
		_, _ = w.WriteString(manifest)
		_ = w.Close()
	}()

	var out bytes.Buffer
	if err := Subtract(Options{Filename: "-", SubtractCIDRs: []string{"10.0.0.128/25"}}, &out); err != nil {
		t.Fatalf("Subtract from stdin failed: %v", err)
	}
	var got apiv3.GlobalNetworkSet
	if err := yaml.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, out.String())
	}
	if got.Name != "from-stdin" || !reflect.DeepEqual(got.Spec.Nets, []string{"10.0.0.0/25"}) {
		t.Errorf("unexpected result: %+v", got)
	}
}

func TestSubtractDirectoryRecursive(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeNamedFile(t, filepath.Join(dir, "a.yaml"), `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: a
spec:
  nets:
  - 10.0.0.0/24
`)
	writeNamedFile(t, filepath.Join(sub, "b.yml"), `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: b
spec:
  nets:
  - 10.1.0.0/24
`)

	var out bytes.Buffer
	err := Subtract(Options{Filename: dir, Recursive: true, SubtractCIDRs: []string{"10.0.0.0/24"}}, &out)
	if err != nil {
		t.Fatalf("Subtract over a directory failed: %v", err)
	}
	if !strings.Contains(out.String(), "name: a") || !strings.Contains(out.String(), "name: b") {
		t.Errorf("expected both resources in output, got:\n%s", out.String())
	}
	// "a" is fully removed; "b" is untouched.
	if strings.Count(out.String(), "nets: []") != 0 {
		t.Errorf("unexpected explicit empty nets list:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "10.1.0.0/24") {
		t.Errorf("untouched resource missing from output:\n%s", out.String())
	}
}

func writeFile(t *testing.T, name, contents string) string {
	t.Helper()
	return writeNamedFile(t, filepath.Join(t.TempDir(), name), contents)
}

func writeNamedFile(t *testing.T, path, contents string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}
