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

package parser

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
)

// Default static-complexity limits applied to parsers created with
// NewParser.  They are chosen to be well above any realistic selector
// while still bounding parser recursion and label-index fan-out.
//
// A limit field set to a negative value disables the corresponding
// check; a zero field is replaced by the default.
const (
	// DefaultMaxNestingDepth bounds the depth of parenthesised
	// sub-expressions.  Each level recurses through the parser so the
	// bound protects against stack-exhaustion inputs.
	DefaultMaxNestingDepth = 100
	// DefaultMaxRegexCount bounds the number of pattern matchers
	// ("contains", "starts with", "ends with") in a selector.  Those
	// operators are evaluated as runtime substring patterns rather than
	// via exact label-index lookups.
	DefaultMaxRegexCount = 64
	// DefaultMaxIndexCost bounds the conservative estimate of the work
	// the label restriction index has to do for a selector.
	DefaultMaxIndexCost = 1_000_000
)

// Per-leaf index-cost weights.  They model the work done by
// felix/labelindex/labelrestrictionindex when a selector is added: a
// selector is indexed under a single label restriction but, in the
// general (e.g. disjunctive) case, every leaf can contribute an entry.
// The weights are summed per leaf; see ComplexityReport.IndexCost for
// the limitations of that approximation.
const (
	// IndexCostLabelEntry is charged once per leaf that references a
	// label: the index may need a per-label sub-index.
	IndexCostLabelEntry = 10
	// IndexCostValueBucket is charged per exact value that a leaf
	// requires ("k == 'v'" and each member of an "in {...}" set),
	// because each value creates/touches a per-value index bucket.
	IndexCostValueBucket = 100
	// IndexCostWildcard is charged for a presence-only restriction such
	// as "has(k)" or a substring matcher, which is indexed as a wildcard
	// and is less selective than an exact value.
	IndexCostWildcard = 50
	// IndexCostUnoptimized is charged for a leaf that contributes no
	// usable label restriction (negation, "!=", "not in", "all()",
	// "global()"): such selectors fall back to a full scan in the
	// unoptimized set.
	IndexCostUnoptimized = 1000
)

// Metric names reported by LimitExceededError.Metric.
const (
	MetricNestingDepth = "nesting depth"
	MetricRegexCount   = "regex count"
	MetricIndexCost    = "index cost"
)

// ErrSelectorComplexityLimit is the sentinel wrapped by every
// LimitExceededError.
var ErrSelectorComplexityLimit = errors.New("selector complexity limit exceeded")

// ComplexityReport summarises the static complexity of a selector.  It is
// computed from the token stream before any AST node is built, so it is
// available even for selectors that would be expensive to parse.
type ComplexityReport struct {
	// NestingDepth is the maximum number of unclosed '(' at any point in
	// the selector (parenthesised expression nesting depth).
	NestingDepth int
	// RegexCount is the number of runtime pattern-matching operators
	// (contains, starts with, ends with) in the selector.  The selector
	// grammar has no general regular-expression operator; these
	// substring matchers are what it counts because, like regexes, they
	// cannot be resolved through an exact label index.
	RegexCount int
	// LabelCount is the number of distinct label names referenced by the
	// selector (including has()).
	LabelCount int
	// IndexCost estimates the cost of adding the selector to the label
	// restriction index (felix/labelindex/labelrestrictionindex): it
	// sums a per-leaf charge, see the IndexCost* constants.  It is
	// deliberately computed from tokens only, so it does not model the
	// boolean structure of the selector (for example a negation that
	// wraps a whole parenthesised group); it is intended for bounding
	// fan-out rather than as an exact restriction analysis.
	IndexCost int
}

// ComplexityLimits configures the static-complexity checks a Parser
// applies before building an AST.  A zero field means "use the default";
// a negative field disables that check.
type ComplexityLimits struct {
	MaxNestingDepth int
	MaxRegexCount   int
	MaxIndexCost    int
}

// DefaultComplexityLimits returns the built-in set of limits.
func DefaultComplexityLimits() ComplexityLimits {
	return ComplexityLimits{
		MaxNestingDepth: DefaultMaxNestingDepth,
		MaxRegexCount:   DefaultMaxRegexCount,
		MaxIndexCost:    DefaultMaxIndexCost,
	}
}

// withDefaults replaces zero fields with the built-in defaults.
func (l ComplexityLimits) withDefaults() ComplexityLimits {
	d := DefaultComplexityLimits()
	if l.MaxNestingDepth == 0 {
		l.MaxNestingDepth = d.MaxNestingDepth
	}
	if l.MaxRegexCount == 0 {
		l.MaxRegexCount = d.MaxRegexCount
	}
	if l.MaxIndexCost == 0 {
		l.MaxIndexCost = d.MaxIndexCost
	}
	return l
}

// LimitExceededError reports a static-complexity limit violation together
// with the location of the token that took the selector over the limit.
// Byte offsets are 0-based; line and column are 1-based (column counts
// runes).
type LimitExceededError struct {
	// Metric is one of the Metric* constants.
	Metric string
	// Value is the measured value that exceeded the limit.
	Value int
	// Limit is the configured limit.
	Limit int
	// Offset is the byte offset of the offending token within the
	// original selector string.
	Offset int
	// Line and Column are the 1-based location of Offset (Column counts
	// runes, not bytes).
	Line   int
	Column int

	input string
}

func newLimitExceededError(metric string, value, limit, offset int, input string) *LimitExceededError {
	lineStart := 0
	if i := strings.LastIndexByte(input[:offset], '\n'); i >= 0 {
		lineStart = i + 1
	}
	return &LimitExceededError{
		Metric: metric,
		Value:  value,
		Limit:  limit,
		Offset: offset,
		Line:   strings.Count(input[:offset], "\n") + 1,
		Column: utf8.RuneCountInString(input[lineStart:offset]) + 1,
		input:  input,
	}
}

// Unwrap allows errors.Is(err, ErrSelectorComplexityLimit).
func (e *LimitExceededError) Unwrap() error {
	return ErrSelectorComplexityLimit
}

// Error renders a description of the violation with a caret pointing at
// the offending token, for example:
//
//	selector complexity limit exceeded: nesting depth (4) exceeds limit (3) at line 1, column 4:
//	((((a
//	   ^
func (e *LimitExceededError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "selector complexity limit exceeded: %s (%d) exceeds limit (%d) at line %d, column %d",
		e.Metric, e.Value, e.Limit, e.Line, e.Column)
	if e.input != "" {
		lineStart := 0
		if i := strings.LastIndexByte(e.input[:e.Offset], '\n'); i >= 0 {
			lineStart = i + 1
		}
		lineEnd := strings.IndexByte(e.input[e.Offset:], '\n')
		var line string
		if lineEnd < 0 {
			line = e.input[lineStart:]
		} else {
			line = e.input[lineStart : e.Offset+lineEnd]
		}
		b.WriteString(":\n")
		b.WriteString(line)
		b.WriteByte('\n')
		b.WriteString(strings.Repeat(" ", e.Column-1))
		b.WriteString("^")
	}
	return b.String()
}

// AnalyzeComplexity tokenizes the selector and reports its static
// complexity without building an AST.  If the selector's complexity
// exceeds the parser's configured limits, a *LimitExceededError is
// returned alongside the (still fully populated) report.  Tokenizer
// syntax errors are returned directly.
func AnalyzeComplexity(selector string) (ComplexityReport, error) {
	sharedParserLock.Lock()
	defer sharedParserLock.Unlock()
	return sharedParser.AnalyzeComplexity(selector)
}

// AnalyzeComplexity is the Parser-bound variant of the package-level
// function; it uses this parser's configured ComplexityLimits.
func (p *Parser) AnalyzeComplexity(selector string) (ComplexityReport, error) {
	tokens, err := tokenizer.AppendTokens(p.tokBuf[:0], selector)
	if err != nil {
		return ComplexityReport{}, err
	}
	if cap(tokens) > cap(p.tokBuf) && cap(tokens) < 4096 {
		// Allow buffer to grow if we're seeing large inputs.
		p.tokBuf = tokens[:0]
	}
	return p.analyzeTokens(selector, tokens)
}

// ComplexityLimits returns the parser's current static-complexity limits.
func (p *Parser) ComplexityLimits() ComplexityLimits {
	return p.limits
}

// SetComplexityLimits sets the parser's static-complexity limits.  Zero
// fields are replaced by the defaults and negative fields disable that
// particular check.
func (p *Parser) SetComplexityLimits(limits ComplexityLimits) {
	p.limits = limits.withDefaults()
}

// analyzeTokens computes the complexity report for an already tokenized
// selector and enforces the parser's limits.  It mutates no parser state
// other than the reusable offsets buffer.
func (p *Parser) analyzeTokens(selector string, tokens []tokenizer.Token) (ComplexityReport, error) {
	p.offBuf = tokenizer.AppendTokenOffsets(p.offBuf[:0], selector, tokens)

	report := ComplexityReport{}
	labels := map[string]struct{}{}
	depth := 0
	limits := p.limits

	var depthErr, regexErr, costErr *LimitExceededError

	// addCost accumulates index cost, clamping on overflow, and records
	// the first token that takes the total over the limit.
	addCost := func(amount, offset int) {
		if amount > 0 && report.IndexCost > math.MaxInt-amount {
			report.IndexCost = math.MaxInt
		} else {
			report.IndexCost += amount
		}
		if costErr == nil && limits.MaxIndexCost >= 0 && report.IndexCost > limits.MaxIndexCost {
			costErr = newLimitExceededError(MetricIndexCost, report.IndexCost,
				limits.MaxIndexCost, offset, selector)
		}
	}

	addLabel := func(name string) {
		if _, ok := labels[name]; !ok {
			labels[name] = struct{}{}
			report.LabelCount++
		}
	}

	for i, tok := range tokens {
		off := p.offBuf[i]
		switch tok.Kind {
		case tokenizer.TokLParen:
			depth++
			if depth > report.NestingDepth {
				report.NestingDepth = depth
			}
			if depthErr == nil && limits.MaxNestingDepth >= 0 && depth > limits.MaxNestingDepth {
				depthErr = newLimitExceededError(MetricNestingDepth, depth,
					limits.MaxNestingDepth, off, selector)
			}
		case tokenizer.TokRParen:
			depth--
		case tokenizer.TokContains, tokenizer.TokStartsWith, tokenizer.TokEndsWith:
			report.RegexCount++
			if regexErr == nil && limits.MaxRegexCount >= 0 && report.RegexCount > limits.MaxRegexCount {
				regexErr = newLimitExceededError(MetricRegexCount, report.RegexCount,
					limits.MaxRegexCount, off, selector)
			}
		case tokenizer.TokHas:
			addLabel(tok.Value)
			if isNegated(tokens, i) {
				// !has(k) is indexed as MustBeAbsent, which the label
				// restriction index cannot optimise.
				addCost(IndexCostUnoptimized, off)
			} else {
				addCost(IndexCostLabelEntry+IndexCostWildcard, off)
			}
		case tokenizer.TokLabel:
			addLabel(tok.Value)
			if isNegated(tokens, i) {
				// !(leaf) contributes no usable restriction.
				addCost(IndexCostUnoptimized, off)
				break
			}
			if i+1 >= len(tokens) {
				// Bare label: the parser will report a syntax error;
				// still charge a label entry for reporting purposes.
				addCost(IndexCostLabelEntry, off)
				break
			}
			switch tokens[i+1].Kind {
			case tokenizer.TokEq:
				addCost(IndexCostLabelEntry+IndexCostValueBucket, off)
			case tokenizer.TokNe:
				addCost(IndexCostUnoptimized, off)
			case tokenizer.TokContains, tokenizer.TokStartsWith, tokenizer.TokEndsWith:
				addCost(IndexCostLabelEntry+IndexCostWildcard, off)
			case tokenizer.TokIn:
				// "k in {v1, v2, ...}" creates one per-value bucket per
				// set member.
				addCost(IndexCostLabelEntry, off)
				for j := i + 3; j+1 < len(tokens) && tokens[j].Kind == tokenizer.TokStringLiteral; j += 2 {
					addCost(IndexCostValueBucket, p.offBuf[j])
					if tokens[j+1].Kind != tokenizer.TokComma {
						break
					}
				}
			case tokenizer.TokNotIn:
				addCost(IndexCostUnoptimized, off)
			default:
				addCost(IndexCostLabelEntry, off)
			}
		case tokenizer.TokAll, tokenizer.TokGlobal:
			// No label restrictions: the selector cannot be narrowed by
			// the index (and that also applies to "!all()").
			addCost(IndexCostUnoptimized, off)
		}
	}

	if depthErr != nil {
		return report, depthErr
	}
	if regexErr != nil {
		return report, regexErr
	}
	if costErr != nil {
		return report, costErr
	}
	return report, nil
}

// isNegated reports whether the leaf token at index i is immediately
// preceded by an odd number of "!" tokens (as in "!has(k)" or
// "!!has(k)").  It scans backwards over the run of TokNot tokens,
// stopping at anything else.
func isNegated(tokens []tokenizer.Token, i int) bool {
	negated := false
	for j := i - 1; j >= 0 && tokens[j].Kind == tokenizer.TokNot; j-- {
		negated = !negated
	}
	return negated
}
