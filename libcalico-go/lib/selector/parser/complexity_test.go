// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/parser"
)

var complexityReportTests = []struct {
	name string
	sel  string
	want parser.ComplexityReport
}{
	{"empty selector", "", parser.ComplexityReport{}},
	{"whitespace only", "   ", parser.ComplexityReport{}},
	{"all is unindexed", "all()", parser.ComplexityReport{
		IndexCost: parser.IndexCostUnoptimized,
	}},
	{"global is unindexed", "global()", parser.ComplexityReport{
		IndexCost: parser.IndexCostUnoptimized,
	}},
	{"equality", `a == "b"`, parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + parser.IndexCostValueBucket,
	}},
	{"negated equality is unindexed", `!a == "b"`, parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostUnoptimized,
	}},
	{"inequality is unindexed", `a != "b"`, parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostUnoptimized,
	}},
	{"contains is a pattern matcher", `a contains "x"`, parser.ComplexityReport{
		RegexCount: 1,
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + parser.IndexCostWildcard,
	}},
	{"starts with is a pattern matcher", `a starts with "x"`, parser.ComplexityReport{
		RegexCount: 1,
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + parser.IndexCostWildcard,
	}},
	{"ends with is a pattern matcher", `a ends with "x"`, parser.ComplexityReport{
		RegexCount: 1,
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + parser.IndexCostWildcard,
	}},
	{"has is a wildcard index entry", "has(a)", parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + parser.IndexCostWildcard,
	}},
	{"negated has is unindexed", "!has(a)", parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostUnoptimized,
	}},
	{"double negated has", "!!has(a)", parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + parser.IndexCostWildcard,
	}},
	{"in set charges per value", `a in {"a", "b", "c"}`, parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry + 3*parser.IndexCostValueBucket,
	}},
	{"empty in set", `a in {}`, parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostLabelEntry,
	}},
	{"not in is unindexed", `a not in {"a"}`, parser.ComplexityReport{
		LabelCount: 1,
		IndexCost:  parser.IndexCostUnoptimized,
	}},
	{"nested parens", `((a == "b"))`, parser.ComplexityReport{
		NestingDepth: 2,
		LabelCount:   1,
		IndexCost:    parser.IndexCostLabelEntry + parser.IndexCostValueBucket,
	}},
	{"max depth across branches", `(a == "b") && ((c == "d"))`, parser.ComplexityReport{
		NestingDepth: 2,
		LabelCount:   2,
		IndexCost:    2 * (parser.IndexCostLabelEntry + parser.IndexCostValueBucket),
	}},
	{"distinct labels are counted once", `a == "b" && a == "c" || has(a)`, parser.ComplexityReport{
		NestingDepth: 0,
		LabelCount:   1,
		IndexCost: 3*(parser.IndexCostLabelEntry+parser.IndexCostValueBucket) -
			parser.IndexCostValueBucket + parser.IndexCostWildcard,
	}},
	{"pattern chain", `a contains "1" || b starts with "2" || c ends with "3"`, parser.ComplexityReport{
		RegexCount: 3,
		LabelCount: 3,
		IndexCost:  3 * (parser.IndexCostLabelEntry + parser.IndexCostWildcard),
	}},
}

func TestComplexityReports(t *testing.T) {
	RegisterTestingT(t)
	for _, tc := range complexityReportTests {
		t.Run(tc.name, func(t *testing.T) {
			RegisterTestingT(t)
			got, err := parser.AnalyzeComplexity(tc.sel)
			Expect(err).NotTo(HaveOccurred(), "selector: %q", tc.sel)
			Expect(got).To(Equal(tc.want), "selector: %q report: %+v", tc.sel, got)
		})
	}
}

func TestComplexityOnParserInstance(t *testing.T) {
	RegisterTestingT(t)
	p := parser.NewParser()
	Expect(p.ComplexityLimits()).To(Equal(parser.DefaultComplexityLimits()))
	rep, err := p.AnalyzeComplexity(`a contains "x"`)
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.RegexCount).To(Equal(1))
}

// TestNestingDepthBoundary checks the limit both at and one beyond the
// configured depth, plus the default-limit boundary.
func TestNestingDepthBoundary(t *testing.T) {
	RegisterTestingT(t)
	nested := func(depth int) string {
		return strings.Repeat("(", depth) + `a == "b"` + strings.Repeat(")", depth)
	}

	p := parser.NewParser()
	p.SetComplexityLimits(parser.ComplexityLimits{MaxNestingDepth: 3})

	// Exactly at the limit: accepted.
	rep, err := p.AnalyzeComplexity(nested(3))
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.NestingDepth).To(Equal(3))
	_, err = p.Parse(nested(3))
	Expect(err).NotTo(HaveOccurred())
	Expect(p.Validate(nested(3))).To(Succeed())

	// One beyond the limit: rejected with a locatable error.
	over := nested(4)
	rep, err = p.AnalyzeComplexity(over)
	Expect(rep.NestingDepth).To(Equal(4))
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(le.Metric).To(Equal(parser.MetricNestingDepth))
	Expect(le.Value).To(Equal(4))
	Expect(le.Limit).To(Equal(3))
	Expect(le.Offset).To(Equal(3))
	Expect(le.Line).To(Equal(1))
	Expect(le.Column).To(Equal(4))
	Expect(err).To(MatchError(ContainSubstring("^")))
	Expect(errors.Is(err, parser.ErrSelectorComplexityLimit)).To(BeTrue())

	// Parse and Validate reject it too, before recursing.
	_, err = p.Parse(over)
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(p.Validate(over)).NotTo(Succeed())

	// Default-limit boundary: 100 accepted, 101 rejected.
	defSel := nested(parser.DefaultMaxNestingDepth)
	_, err = parser.Parse(defSel)
	Expect(err).NotTo(HaveOccurred())
	tooDeep := nested(parser.DefaultMaxNestingDepth + 1)
	_, err = parser.Parse(tooDeep)
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(le.Metric).To(Equal(parser.MetricNestingDepth))
	Expect(le.Offset).To(Equal(parser.DefaultMaxNestingDepth))

	// A negative limit disables the check entirely.
	off := parser.NewParser()
	off.SetComplexityLimits(parser.ComplexityLimits{
		MaxNestingDepth: -1,
		MaxRegexCount:   -1,
		MaxIndexCost:    -1,
	})
	_, err = off.AnalyzeComplexity(nested(200))
	Expect(err).NotTo(HaveOccurred())
}

func TestRegexCountBoundary(t *testing.T) {
	RegisterTestingT(t)
	patterns := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf(`l%d contains "v%d"`, i, i))
		}
		return strings.Join(parts, " && ")
	}

	p := parser.NewParser()
	p.SetComplexityLimits(parser.ComplexityLimits{MaxRegexCount: 2})

	rep, err := p.AnalyzeComplexity(patterns(2))
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.RegexCount).To(Equal(2))

	over := patterns(3)
	rep, err = p.AnalyzeComplexity(over)
	Expect(rep.RegexCount).To(Equal(3))
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(le.Metric).To(Equal(parser.MetricRegexCount))
	Expect(le.Limit).To(Equal(2))
	Expect(le.Value).To(Equal(3))
	// The location is the third "contains" operator.
	wantOff := strings.Index(over, `l2 contains`) + len("l2 ")
	Expect(le.Offset).To(Equal(wantOff))
	Expect(le.Column).To(Equal(wantOff + 1))
}

func TestIndexCostBoundary(t *testing.T) {
	RegisterTestingT(t)
	one := parser.IndexCostLabelEntry + parser.IndexCostValueBucket

	p := parser.NewParser()
	p.SetComplexityLimits(parser.ComplexityLimits{MaxIndexCost: 2 * one})

	// Two equality leaves land exactly on the limit.
	atLimit := `a == "1" && b == "2"`
	rep, err := p.AnalyzeComplexity(atLimit)
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.IndexCost).To(Equal(2 * one))

	// A third leaf crosses it; the error points at that leaf's label.
	over := `a == "1" && b == "2" && c == "3"`
	rep, err = p.AnalyzeComplexity(over)
	Expect(rep.IndexCost).To(Equal(3 * one))
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(le.Metric).To(Equal(parser.MetricIndexCost))
	Expect(le.Limit).To(Equal(2 * one))
	Expect(le.Offset).To(Equal(strings.Index(over, "c ==")))

	// A large "in" set is charged per value; the crossing points at the
	// value literal that tips the estimate over the limit.
	big := `k in {"a", "b", "c", "d"}`
	rep, err = p.AnalyzeComplexity(big)
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(le.Metric).To(Equal(parser.MetricIndexCost))
	Expect(le.Offset).To(Equal(strings.Index(big, `"c"`)))
}

func TestErrorLocationIgnoresByteWidthForColumns(t *testing.T) {
	RegisterTestingT(t)
	// A multibyte literal precedes the offending operator; Offset counts
	// bytes but Column must count runes.
	sel := `a == "世界" && b contains "x" && c contains "y" && d contains "z"`
	p := parser.NewParser()
	p.SetComplexityLimits(parser.ComplexityLimits{MaxRegexCount: 2})
	_, err := p.AnalyzeComplexity(sel)
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeTrue())
	// The location is the third "contains" operator (not its label).
	opOff := strings.Index(sel, "d contains") + len("d ")
	prefix := sel[:opOff]
	Expect(le.Offset).To(Equal(opOff))
	Expect(le.Column).To(Equal(utf8.RuneCountInString(prefix) + 1))
	Expect(le.Column).NotTo(Equal(le.Offset + 1))
}

func TestSyntaxErrorsAreNotComplexityErrors(t *testing.T) {
	RegisterTestingT(t)
	// Tokenizer-level errors are reported by AnalyzeComplexity too, and
	// they must never be misclassified as complexity errors.
	for _, sel := range []string{
		`2001:db8::1 == "x"`, // ':' is not a valid label-name character.
		`a == "unterminated`, // unterminated string literal.
	} {
		_, err := parser.AnalyzeComplexity(sel)
		Expect(err).To(HaveOccurred(), "selector: %q", sel)
		var le *parser.LimitExceededError
		Expect(errors.As(err, &le)).To(BeFalse(),
			"syntax error must not be reported as a complexity error: %q", sel)
		_, err = parser.Parse(sel)
		Expect(err).To(HaveOccurred())
	}

	// Unbalanced parentheses are a grammar (parser) error, not a
	// tokenizer or complexity-limit error.
	_, err := parser.Parse(`(((a == "b")`)
	Expect(err).To(HaveOccurred())
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeFalse())
	// Analysis itself is purely lexical and remains error-free.
	rep, err := parser.AnalyzeComplexity(`(((a == "b")`)
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.NestingDepth).To(Equal(3))
}

func TestLegalSelectorSemanticsAndCanonicalStringPreserved(t *testing.T) {
	RegisterTestingT(t)
	cases := []struct {
		sel       string
		canonical string
		matches   map[string]string
	}{
		{``, "all()", map[string]string{}},
		{`! (has( b)||! has(a ))`, "!(has(b) || !has(a))",
			map[string]string{"a": "1"}},
		{`a in {"z", "x", "y", "a"}`, `a in {"a", "x", "y", "z"}`,
			map[string]string{"a": "x"}},
		{`a == "'"`, `a == "'"`, map[string]string{"a": "'"}},
		{`a == '"'`, `a == '"'`, map[string]string{"a": `"`}},
		{`a contains '"'`, `a contains '"'`, map[string]string{"a": `x"y`}},
		// Legal up to (and at) the default nesting limit.
		{strings.Repeat("(", 50) + `a == "b"` + strings.Repeat(")", 50),
			`a == "b"`, map[string]string{"a": "b"}},
	}
	for _, tc := range cases {
		sel, err := parser.Parse(tc.sel)
		Expect(err).NotTo(HaveOccurred(), "selector: %q", tc.sel)
		Expect(sel.String()).To(Equal(tc.canonical), "canonical form of %q", tc.sel)
		Expect(sel.Evaluate(tc.matches)).To(BeTrue(), "evaluation of %q", tc.sel)
		// Canonical form round-trips with a stable UID.
		rt, err := parser.Parse(sel.String())
		Expect(err).NotTo(HaveOccurred())
		Expect(rt.String()).To(Equal(sel.String()))
		Expect(rt.UniqueID()).To(Equal(sel.UniqueID()))
		Expect(rt.Evaluate(tc.matches)).To(BeTrue())
	}
}

func TestNegationChainHasNoNestingDepth(t *testing.T) {
	RegisterTestingT(t)
	// "!" is collapsed by the parser and must not count as nesting;
	// only parentheses do.
	sel := strings.Repeat("!", 200) + "has(a)"
	rep, err := parser.AnalyzeComplexity(sel)
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.NestingDepth).To(BeZero())
	parsed, err := parser.Parse(sel)
	Expect(err).NotTo(HaveOccurred())
	Expect(parsed.Evaluate(map[string]string{"a": "b"})).To(BeTrue())
}

func TestIPv4AndIPv6Labels(t *testing.T) {
	RegisterTestingT(t)
	// IPv4 addresses are valid label names (digits and dots).
	sel, err := parser.Parse(`10.0.0.1 == "10.0.0.1"`)
	Expect(err).NotTo(HaveOccurred())
	Expect(sel.Evaluate(map[string]string{"10.0.0.1": "10.0.0.1"})).To(BeTrue())
	Expect(sel.Evaluate(map[string]string{"10.0.0.1": "10.0.0.2"})).To(BeFalse())
	Expect(sel.String()).To(Equal(`10.0.0.1 == "10.0.0.1"`))
	rep, err := parser.AnalyzeComplexity(`has(192.168.1.1)`)
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.LabelCount).To(Equal(1))
	sel, err = parser.Parse(`has(192.168.1.1)`)
	Expect(err).NotTo(HaveOccurred())
	Expect(sel.Evaluate(map[string]string{"192.168.1.1": "gw"})).To(BeTrue())
	// Prefixed IPv4 names (slashes are legal label-name characters).
	sel, err = parser.Parse(`net/10.0.0.1 == "x"`)
	Expect(err).NotTo(HaveOccurred())
	Expect(sel.Evaluate(map[string]string{"net/10.0.0.1": "x"})).To(BeTrue())

	// IPv6 addresses are legal label VALUES (string literals).
	for _, ip := range []string{"2001:db8::1", "fe80::1", "::1", "fe80::1%eth0"} {
		expr := fmt.Sprintf(`ip == "%s"`, ip)
		sel, err = parser.Parse(expr)
		Expect(err).NotTo(HaveOccurred(), "selector: %s", expr)
		Expect(sel.Evaluate(map[string]string{"ip": ip})).To(BeTrue())
		Expect(sel.Evaluate(map[string]string{"ip": "other"})).To(BeFalse())
	}
	sel, err = parser.Parse(`ip in {"10.0.0.1", "2001:db8::1", "::1"}`)
	Expect(err).NotTo(HaveOccurred())
	Expect(sel.Evaluate(map[string]string{"ip": "2001:db8::1"})).To(BeTrue())
	Expect(sel.Evaluate(map[string]string{"ip": "8.8.8.8"})).To(BeFalse())

	// IPv6 addresses are NOT legal label NAMES because ':' is not an
	// identifier character: all entry points must reject them (with a
	// syntax error, not a complexity error).
	_, err = parser.Parse(`2001:db8::1 == "x"`)
	Expect(err).To(HaveOccurred())
	Expect(parser.Validate(`2001:db8::1 == "x"`)).NotTo(Succeed())
	_, err = parser.AnalyzeComplexity(`2001:db8::1 == "x"`)
	Expect(err).To(HaveOccurred())
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeFalse())
}

func TestEscapedAndBackslashContentInLiterals(t *testing.T) {
	RegisterTestingT(t)
	// Backslashes are ordinary literal characters (the tokenizer has no
	// escape processing); they must be preserved through analysis,
	// evaluation and canonicalisation.
	sel, err := parser.Parse(`path == "C:\Users\admin"`)
	Expect(err).NotTo(HaveOccurred())
	Expect(sel.Evaluate(map[string]string{"path": `C:\Users\admin`})).To(BeTrue())
	Expect(sel.String()).To(Equal(`path == "C:\Users\admin"`))
	rep, err := parser.AnalyzeComplexity(`path == "C:\Users\admin"`)
	Expect(err).NotTo(HaveOccurred())
	Expect(rep.LabelCount).To(Equal(1))
	Expect(rep.IndexCost).To(Equal(parser.IndexCostLabelEntry + parser.IndexCostValueBucket))

	// A literal that contains the other quote character is legal and is
	// re-quoted canonically with the other quote style.
	sel, err = parser.Parse(`a == 'say "hi"'`)
	Expect(err).NotTo(HaveOccurred())
	Expect(sel.String()).To(Equal(`a == 'say "hi"'`))
	Expect(sel.Evaluate(map[string]string{"a": `say "hi"`})).To(BeTrue())

	// A backslash before the closing quote does not act as an escape:
	// the literal is unterminated and must be reported as a syntax error
	// by every entry point.
	for _, entry := range []func() error{
		func() error { _, e := parser.Parse(`a == "x\`); return e },
		func() error { return parser.Validate(`a == "x\`) },
		func() error { _, e := parser.AnalyzeComplexity(`a == "x\`); return e },
	} {
		Expect(entry()).To(HaveOccurred())
	}

	// Pattern-limit location stays accurate when earlier literals
	// contain backslashes.
	sel2 := `a contains "x\y" && b contains "z" && c contains "w"`
	p := parser.NewParser()
	p.SetComplexityLimits(parser.ComplexityLimits{MaxRegexCount: 2})
	_, err = p.AnalyzeComplexity(sel2)
	var le *parser.LimitExceededError
	Expect(errors.As(err, &le)).To(BeTrue())
	Expect(le.Offset).To(Equal(strings.Index(sel2, "c contains") + len("c ")))
}
