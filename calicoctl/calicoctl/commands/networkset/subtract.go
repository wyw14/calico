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
	"bufio"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/file"
	"github.com/projectcalico/calico/calicoctl/calicoctl/resourcemgr"
)

// Options configures an offline NetworkSet CIDR subtraction.
type Options struct {
	// Filename is the NetworkSet/GlobalNetworkSet manifest to read: a file,
	// a directory (see Recursive), or "-" for stdin.
	Filename string

	// Recursive processes the filename directory recursively.
	Recursive bool

	// SubtractCIDRs is a list of CIDRs (or bare IP addresses) to subtract.
	// Individual entries may themselves contain several comma- or
	// whitespace-separated CIDRs.
	SubtractCIDRs []string

	// SubtractFiles lists plain-text files containing CIDRs to subtract.
	// Blank lines are ignored and comments run from '#' to the end of the
	// line; CIDRs may be separated by commas or whitespace.
	SubtractFiles []string
}

// Subtract reads one or more NetworkSet/GlobalNetworkSet resources, subtracts
// the configured CIDR list from each resource's spec.nets, and writes the
// resulting resources to out as multi-document YAML that can be fed directly
// into "calicoctl create" or "calicoctl apply".
//
// Subtract is entirely offline: it never connects to a datastore. All inputs
// (manifests and CIDR lists) are fully parsed and validated before anything
// is written, so an invalid CIDR or resource aborts the command without
// producing partial output.
func Subtract(opts Options, out io.Writer) error {
	if opts.Filename == "" {
		return fmt.Errorf("a NetworkSet or GlobalNetworkSet manifest must be supplied with --filename (use \"-f -\" for stdin)")
	}

	// Parse the CIDR list to subtract up front so that an invalid entry
	// fails the command before any input resource is even inspected.
	subtractPrefixes, err := parseSubtractCIDRs(opts)
	if err != nil {
		return err
	}

	// Load and validate every input resource (and its nets) before writing
	// anything. This guarantees no partial output on bad input.
	resources, err := loadNetworkSets(opts)
	if err != nil {
		return err
	}

	documents := make([][]byte, 0, len(resources))
	for _, res := range resources {
		var sourceNets []string
		var setKind string
		switch r := res.(type) {
		case *apiv3.NetworkSet:
			sourceNets = r.Spec.Nets
			setKind = apiv3.KindNetworkSet
		case *apiv3.GlobalNetworkSet:
			sourceNets = r.Spec.Nets
			setKind = apiv3.KindGlobalNetworkSet
		}

		// Parse the resource's own nets as well so that a bad entry is
		// reported before anything is written.
		sourceV4 := newPrefixTrie(32)
		sourceV6 := newPrefixTrie(128)
		for _, cidr := range sourceNets {
			p, err := parsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("failed to parse net %q in %s %q: %w", cidr, setKind, res.GetObjectMeta().GetName(), err)
			}
			switch p.bits {
			case 32:
				sourceV4.Add(p)
			case 128:
				sourceV6.Add(p)
			default:
				return fmt.Errorf("unsupported IP address length for CIDR %q", cidr)
			}
		}

		for _, p := range subtractPrefixes {
			switch p.bits {
			case 32:
				sourceV4.Remove(p)
			case 128:
				sourceV6.Remove(p)
			}
		}

		nets := append(sourceV4.CIDRStrings(), sourceV6.CIDRStrings()...)

		doc, err := marshalResult(res, nets)
		if err != nil {
			return err
		}
		documents = append(documents, doc)
	}

	for _, doc := range documents {
		if _, err := fmt.Fprintln(out, "---"); err != nil {
			return err
		}
		if _, err := out.Write(doc); err != nil {
			return err
		}
	}
	return nil
}

// loadNetworkSets reads the input manifest(s) and returns the concrete
// NetworkSet and GlobalNetworkSet resources they contain. Lists are expanded.
func loadNetworkSets(opts Options) ([]resourcemgr.ResourceObject, error) {
	var resources []resourcemgr.ResourceObject

	parsedArgs := map[string]any{
		"--filename":  opts.Filename,
		"--recursive": opts.Recursive,
	}
	err := file.Iter(parsedArgs, func(modifiedArgs map[string]any) error {
		filename := modifiedArgs["--filename"].(string)
		loaded, err := resourcemgr.CreateResourcesFromFile(filename)
		if err != nil {
			return fmt.Errorf("failed to read resources from %s: %w", displayFilename(filename), err)
		}

		extracted, err := extractNetworkSets(loaded, filename)
		if err != nil {
			return err
		}
		resources = append(resources, extracted...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(resources) == 0 {
		return nil, fmt.Errorf("no NetworkSet or GlobalNetworkSet resources specified in %s", displayFilename(opts.Filename))
	}

	// Validate each resource independently; nothing has been written yet.
	for _, res := range resources {
		meta := res.GetObjectMeta()
		if meta.GetName() == "" {
			return nil, fmt.Errorf("%s resource is missing metadata.name", res.GetObjectKind().GroupVersionKind().Kind)
		}
		if gns, ok := res.(*apiv3.GlobalNetworkSet); ok && gns.Namespace != "" {
			return nil, fmt.Errorf("namespace %q must not be specified for GlobalNetworkSet %q", gns.Namespace, gns.Name)
		}
	}

	return resources, nil
}

// extractNetworkSets pulls concrete NetworkSet/GlobalNetworkSet objects out of
// the resources parsed from a file, expanding list types. Any other resource
// kind is rejected because this command only transforms network sets.
func extractNetworkSets(loaded []runtime.Object, filename string) ([]resourcemgr.ResourceObject, error) {
	var resources []resourcemgr.ResourceObject
	for _, obj := range loaded {
		switch r := obj.(type) {
		case *apiv3.NetworkSet, *apiv3.GlobalNetworkSet:
			resources = append(resources, r.(resourcemgr.ResourceObject))
		case *apiv3.NetworkSetList:
			for i := range r.Items {
				resources = append(resources, &r.Items[i])
			}
		case *apiv3.GlobalNetworkSetList:
			for i := range r.Items {
				resources = append(resources, &r.Items[i])
			}
		default:
			return nil, fmt.Errorf("unsupported resource kind %q in %s: networkset subtract only handles NetworkSet and GlobalNetworkSet",
				obj.GetObjectKind().GroupVersionKind().Kind, displayFilename(filename))
		}
	}
	return resources, nil
}

// marshalResult deep-copies the input resource, replaces its nets with the
// computed remainder, strips server-generated metadata (preserving name,
// namespace and user-supplied labels and annotations), and marshals YAML.
func marshalResult(res resourcemgr.ResourceObject, nets []string) ([]byte, error) {
	out := res.DeepCopyObject()

	meta := metav1.ObjectMeta{
		Name:        res.GetObjectMeta().GetName(),
		Namespace:   res.GetObjectMeta().GetNamespace(),
		Labels:      cloneStringMap(res.GetObjectMeta().GetLabels()),
		Annotations: cloneStringMap(res.GetObjectMeta().GetAnnotations()),
	}

	switch r := out.(type) {
	case *apiv3.NetworkSet:
		r.TypeMeta = metav1.TypeMeta{Kind: apiv3.KindNetworkSet, APIVersion: apiv3.GroupVersionCurrent}
		r.ObjectMeta = meta
		r.Spec.Nets = nets
	case *apiv3.GlobalNetworkSet:
		r.TypeMeta = metav1.TypeMeta{Kind: apiv3.KindGlobalNetworkSet, APIVersion: apiv3.GroupVersionCurrent}
		r.ObjectMeta = metav1.ObjectMeta{
			Name:        meta.Name,
			Labels:      meta.Labels,
			Annotations: meta.Annotations,
		}
		r.Spec.Nets = nets
	default:
		return nil, fmt.Errorf("unsupported resource type %T", out)
	}

	return yaml.Marshal(out)
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// parseSubtractCIDRs gathers every CIDR supplied via --subtract-cidr and
// --subtract-file and parses them all; the first invalid entry is reported.
func parseSubtractCIDRs(opts Options) ([]ipPrefix, error) {
	tokens, err := collectSubtractTokens(opts)
	if err != nil {
		return nil, err
	}

	prefixes := make([]ipPrefix, 0, len(tokens))
	for _, token := range tokens {
		p, err := parsePrefix(token)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR in subtraction list: %w", err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// collectSubtractTokens flattens --subtract-cidr values and the contents of
// --subtract-file files into a single token list (de-duplication happens
// later when the prefixes are added to the trie).
func collectSubtractTokens(opts Options) ([]string, error) {
	var tokens []string
	tokens = append(tokens, splitCIDRTokens(opts.SubtractCIDRs)...)

	for _, path := range opts.SubtractFiles {
		if path == "-" {
			return nil, fmt.Errorf("stdin (\"-\") is reserved for the input manifest and cannot be used as a --subtract-file")
		}
		fileTokens, err := readCIDRListFile(path)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, fileTokens...)
	}
	return tokens, nil
}

// splitCIDRTokens splits raw flag values into individual CIDR tokens; values
// may contain several comma- or whitespace-separated CIDRs.
func splitCIDRTokens(raw []string) []string {
	var tokens []string
	for _, v := range raw {
		v = strings.ReplaceAll(v, ",", " ")
		tokens = append(tokens, strings.Fields(v)...)
	}
	return tokens
}

// readCIDRListFile reads a plain-text CIDR list. Text from a '#' to the end
// of a line is treated as a comment and ignored.
func readCIDRListFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open subtraction CIDR file %q: %w", path, err)
	}
	defer f.Close()

	var tokens []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024), 10*1024*1024)
	firstLine := true
	for scanner.Scan() {
		line := scanner.Text()
		// Tolerate a UTF-8 BOM that Windows editors put on the first line.
		if firstLine {
			line = strings.TrimPrefix(line, "\uFEFF")
			firstLine = false
		}
		// Comments run from a '#' to the end of the line; the remainder may
		// hold several comma- or whitespace-separated CIDR tokens.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ReplaceAll(line, ",", " ")
		tokens = append(tokens, strings.Fields(line)...)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read subtraction CIDR file %q: %w", path, err)
	}
	return tokens, nil
}

func displayFilename(filename string) string {
	if filename == "-" {
		return "stdin"
	}
	return fmt.Sprintf("file %q", filename)
}

// ipPrefix is a canonical IP prefix: a big-endian address integer together
// with its prefix length and address width in bits (32 or 128).
type ipPrefix struct {
	ip   *big.Int
	ones int
	bits int
}

func (p ipPrefix) String() string {
	size := p.bits / 8
	raw := p.ip.Bytes()
	if len(raw) < size {
		padded := make([]byte, size)
		copy(padded[size-len(raw):], raw)
		raw = padded
	}
	ip := net.IP(raw)
	mask := net.CIDRMask(p.ones, p.bits)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

// parsePrefix parses a CIDR string into a canonical ipPrefix. A bare IP
// address is accepted and treated as a host prefix (/32 or /128), matching
// the validation rules of NetworkSet/GlobalNetworkSet nets. Host bits set on
// a CIDR are masked off, so the result always denotes the named network.
func parsePrefix(s string) (ipPrefix, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return ipPrefix{}, fmt.Errorf("invalid CIDR %q: expected CIDR notation such as 10.0.0.0/24 or 2001:db8::/32", s)
		}
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		bits := len(ip) * 8
		ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}

	ones, bits := ipNet.Mask.Size()
	ip := ipNet.IP.Mask(ipNet.Mask)
	if bits == 32 {
		ip = ip.To4()
	}

	return ipPrefix{ip: new(big.Int).SetBytes(ip), ones: ones, bits: bits}, nil
}

// trieNode is a binary prefix trie node. A node with cover=true denotes that
// its whole subtree belongs to the set; child pointers are then irrelevant.
type trieNode struct {
	cover bool
	child [2]*trieNode
}

// prefixTrie stores an exact set of IP prefixes of a single address family.
// Add and Remove keep the set exact (including overlapping prefixes), and
// CIDRStrings emits the minimal, fully-coalesced, numerically sorted set of
// CIDRs representing it.
type prefixTrie struct {
	bits int
	root *trieNode
}

func newPrefixTrie(bits int) *prefixTrie {
	return &prefixTrie{bits: bits, root: &trieNode{}}
}

// Add inserts a prefix into the trie.
func (t *prefixTrie) Add(p ipPrefix) {
	if p.bits != t.bits {
		return
	}
	t.root.add(p.ip, t.bits, 0, p.ones)
}

// Remove subtracts a prefix from the trie.
func (t *prefixTrie) Remove(p ipPrefix) {
	if p.bits != t.bits {
		return
	}
	if t.root.remove(p.ip, t.bits, 0, p.ones) {
		t.root = &trieNode{}
	}
}

// CIDRStrings returns the canonical, coalesced and numerically-sorted CIDRs
// represented by the trie.
func (t *prefixTrie) CIDRStrings() []string {
	t.root.canonicalize()
	var prefixes []ipPrefix
	t.root.enumerate(new(big.Int), t.bits, 0, &prefixes)
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

// add marks the path to the given prefix as covered, stopping early whenever
// the subtree is already fully covered.
func (n *trieNode) add(ip *big.Int, bits, depth, ones int) {
	if n.cover {
		return
	}
	if depth == ones {
		n.cover = true
		n.child = [2]*trieNode{}
		return
	}
	b := int(ip.Bit(bits - 1 - depth))
	if n.child[b] == nil {
		n.child[b] = &trieNode{}
	}
	n.child[b].add(ip, bits, depth+1, ones)
}

// remove subtracts the given prefix, returning true when the node becomes
// empty so that its parent can prune it.
func (n *trieNode) remove(ip *big.Int, bits, depth, ones int) bool {
	if n.cover {
		if depth == ones {
			// The exact covered prefix is removed.
			return true
		}
		// A covering prefix must be expanded: the sibling half stays
		// fully covered while we carve the removed prefix out of the
		// half leading to it.
		b := int(ip.Bit(bits - 1 - depth))
		n.cover = false
		n.child[0] = &trieNode{cover: true}
		n.child[1] = &trieNode{cover: true}
		if n.child[b].remove(ip, bits, depth+1, ones) {
			n.child[b] = nil
		}
	} else if depth < ones {
		b := int(ip.Bit(bits - 1 - depth))
		if n.child[b] == nil {
			// Nothing of the removed prefix is covered.
			return false
		}
		if n.child[b].remove(ip, bits, depth+1, ones) {
			n.child[b] = nil
		}
	} else {
		// depth == ones: drop a cover mark here if any, and discard
		// anything below since it is part of the removed prefix.
		n.cover = false
		n.child = [2]*trieNode{}
	}

	return !n.cover && n.child[0] == nil && n.child[1] == nil
}

// canonicalize collapses pairs of fully-covered sibling nodes into their
// parent, bottom-up, so that enumeration yields minimal prefixes.
func (n *trieNode) canonicalize() {
	if n.cover {
		n.child = [2]*trieNode{}
		return
	}
	for _, c := range n.child {
		if c != nil {
			c.canonicalize()
		}
	}
	if n.child[0] != nil && n.child[1] != nil && n.child[0].cover && n.child[1].cover {
		n.cover = true
		n.child = [2]*trieNode{}
	}
}

// enumerate appends covered prefixes in numerical (zero-bit first) order.
func (n *trieNode) enumerate(cur *big.Int, bits, depth int, out *[]ipPrefix) {
	if n.cover {
		*out = append(*out, ipPrefix{ip: new(big.Int).Set(cur), ones: depth, bits: bits})
		return
	}
	for b := 0; b < 2; b++ {
		if n.child[b] == nil {
			continue
		}
		next := new(big.Int).Set(cur)
		if b == 1 {
			next.SetBit(next, bits-1-depth, 1)
		}
		n.child[b].enumerate(next, bits, depth+1, out)
	}
}
