// Copyright (c) 2016, 2019 Tigera, Inc. All rights reserved.

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

package tokenizer_test

import (
	"fmt"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/selector/tokenizer"
)

var tokenTests = []struct {
	input    string
	expected []tokenizer.Token
}{
	{`a=="b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a!="b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNe},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a != "b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNe},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`(a=="b")`, []tokenizer.Token{
		{Kind: tokenizer.TokLParen},
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokRParen},
		{Kind: tokenizer.TokEOF},
	}},

	{`a=="b"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "b"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label == "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label contains "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`contains contains "contains"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "contains"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "contains"},
		{Kind: tokenizer.TokEOF},
	}},
	{`contains contains 'contains'`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "contains"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "contains"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label contains"value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokContains},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label startswith "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label endswith "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label starts with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`startswith starts with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "startswith"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label ends with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`endswith ends with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "endswith"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label starts  with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokStartsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{`label ends  with "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "label"},
		{Kind: tokenizer.TokEndsWith},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{strings.Repeat("a", 512) + ` == "value"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: strings.Repeat("a", 512)},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "value"},
		{Kind: tokenizer.TokEOF},
	}},
	{strings.Repeat("a", 513) + ` == "value"`, nil},
	{`label == "value`, nil},
	{`label == 'value`, nil},
	{`label = "value"`, nil},
	{`all(`, nil},
	{`global(`, nil},
	{`has()`, nil},
	{`has(foo`, nil},
	{`has( foo `, nil},
	{`a == "b" & has(foo)`, nil},
	{`a == "b" | has(foo)`, nil},
	{`label starts foo "value"`, nil},
	{`label inf "value"`, nil},
	{`label ends foo "value"`, nil},
	{`label ends withs "value"`, nil},
	{`label squiggles "value"`, nil},
	{`a not in "bar" && !has(foo) || b in c`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokStringLiteral, Value: "bar"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokNot},
		{Kind: tokenizer.TokHas, Value: "foo"},
		{Kind: tokenizer.TokOr},
		{Kind: tokenizer.TokLabel, Value: "b"},
		{Kind: tokenizer.TokIn},
		{Kind: tokenizer.TokLabel, Value: "c"},
		{Kind: tokenizer.TokEOF},
	}},
	{`has(calico/k8s_ns)`, []tokenizer.Token{
		{Kind: tokenizer.TokHas, Value: "calico/k8s_ns"},
		{Kind: tokenizer.TokEOF},
	}},
	{`has(calico/k8s_ns/role)`, []tokenizer.Token{
		{Kind: tokenizer.TokHas, Value: "calico/k8s_ns/role"},
		{Kind: tokenizer.TokEOF},
	}},
	{`has(calico/k8s_NS-.1/role)`, []tokenizer.Token{
		{Kind: tokenizer.TokHas, Value: "calico/k8s_NS-.1/role"},
		{Kind: tokenizer.TokEOF},
	}},
	{`calico/k8s_ns == "kube-system" && k8s-app == "kube-dns"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "calico/k8s_ns"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "kube-system"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokLabel, Value: "k8s-app"},
		{Kind: tokenizer.TokEq},
		{Kind: tokenizer.TokStringLiteral, Value: "kube-dns"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a  not  in  "bar"  &&  ! has( foo )  ||  b  in  c `, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokStringLiteral, Value: "bar"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokNot},
		{Kind: tokenizer.TokHas, Value: "foo"},
		{Kind: tokenizer.TokOr},
		{Kind: tokenizer.TokLabel, Value: "b"},
		{Kind: tokenizer.TokIn},
		{Kind: tokenizer.TokLabel, Value: "c"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a notin"bar"&&!has(foo)||b in"c"`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokStringLiteral, Value: "bar"},
		{Kind: tokenizer.TokAnd},
		{Kind: tokenizer.TokNot},
		{Kind: tokenizer.TokHas, Value: "foo"},
		{Kind: tokenizer.TokOr},
		{Kind: tokenizer.TokLabel, Value: "b"},
		{Kind: tokenizer.TokIn},
		{Kind: tokenizer.TokStringLiteral, Value: "c"},
		{Kind: tokenizer.TokEOF},
	}},
	{`a not in {}`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokLBrace},
		{Kind: tokenizer.TokRBrace},
		{Kind: tokenizer.TokEOF},
	}},
	{`a not in {"a"}`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokLBrace},
		{Kind: tokenizer.TokStringLiteral, Value: "a"},
		{Kind: tokenizer.TokRBrace},
		{Kind: tokenizer.TokEOF},
	}},
	{`a not in {"a","B"}`, []tokenizer.Token{
		{Kind: tokenizer.TokLabel, Value: "a"},
		{Kind: tokenizer.TokNotIn},
		{Kind: tokenizer.TokLBrace},
		{Kind: tokenizer.TokStringLiteral, Value: "a"},
		{Kind: tokenizer.TokComma},
		{Kind: tokenizer.TokStringLiteral, Value: "B"},
		{Kind: tokenizer.TokRBrace},
		{Kind: tokenizer.TokEOF},
	}},
	{`global()`, []tokenizer.Token{
		{Kind: tokenizer.TokGlobal},
		{Kind: tokenizer.TokEOF},
	}},
	{`global( )`, []tokenizer.Token{
		{Kind: tokenizer.TokGlobal},
		{Kind: tokenizer.TokEOF},
	}},
	{`all()`, []tokenizer.Token{
		{Kind: tokenizer.TokAll},
		{Kind: tokenizer.TokEOF},
	}},
	{`all( )`, []tokenizer.Token{
		{Kind: tokenizer.TokAll},
		{Kind: tokenizer.TokEOF},
	}},
}

var _ = Describe("Token", func() {
	for _, test := range tokenTests {
		if test.expected == nil {
			It(fmt.Sprintf("should return error for input %#v", test.input), func() {
				_, err := tokenizer.Tokenize(test.input)
				Expect(err).To(HaveOccurred())
			})
		} else {
			It(fmt.Sprintf("should tokenize <%s> as %v", test.input, test.expected), func() {
				tokens, err := tokenizer.Tokenize(test.input)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokens).To(Equal(test.expected), fmt.Sprintf("Expected: %s\nGot: %s", test.expected, tokens))
			})
		}
	}
})

var tokenOffsetTests = []struct {
	input   string
	offsets []int
}{
	{`a=="b"`, []int{0, 1, 3, 6}},
	{`( a == "b" )`, []int{0, 2, 4, 7, 11, 12}},
	{`a starts  with "x"`, []int{0, 2, 15, 18}},
	{`a not in "x"`, []int{0, 2, 9, 12}},
	{`a notin"x"`, []int{0, 2, 7, 10}},
	{`has( foo )`, []int{0, 10}},
	{`all( )`, []int{0, 6}},
	{`global( )`, []int{0, 9}},
	{`a == "x\y"`, []int{0, 2, 5, 10}},
	// Multibyte content is inside a string literal; offsets stay byte based.
	{`a == "世界"`, []int{0, 2, 5, 13}},
	// IPv4-shaped label names.
	{`10.0.0.1 == 'x'`, []int{0, 9, 12, 15}},
	// Trailing whitespace: EOF is reported at end of input.
	{`a == "b"  `, []int{0, 2, 5, 10}},
}

var _ = Describe("TokenOffsets", func() {
	for _, test := range tokenOffsetTests {
		test := test
		It(fmt.Sprintf("should locate each token of %#v", test.input), func() {
			tokens, err := tokenizer.Tokenize(test.input)
			Expect(err).NotTo(HaveOccurred())
			Expect(tokens).To(HaveLen(len(test.offsets)))
			offsets := tokenizer.TokenOffsets(test.input, tokens)
			Expect(offsets).To(Equal(test.offsets))

			// The token must actually start at its reported offset.
			for i, tok := range tokens[:len(tokens)-1] {
				off := offsets[i]
				Expect(off).To(BeNumerically(">=", 0))
				Expect(off).To(BeNumerically("<", len(test.input)))
				switch tok.Kind {
				case tokenizer.TokLabel:
					Expect(test.input[off : off+len(tok.Value)]).To(Equal(tok.Value))
				case tokenizer.TokHas:
					Expect(test.input[off : off+len("has(")]).To(Equal("has("))
					Expect(test.input).To(ContainSubstring(tok.Value))
				case tokenizer.TokStringLiteral:
					Expect(test.input[off]).To(BeElementOf(byte('"'), byte('\'')))
				}
			}
			Expect(offsets[len(offsets)-1]).To(Equal(len(test.input)))
		})
	}

	It("should work when appending to an existing offsets slice", func() {
		tokens, err := tokenizer.Tokenize(`a == "b"`)
		Expect(err).NotTo(HaveOccurred())
		offsets := tokenizer.AppendTokenOffsets([]int{-1}, `a == "b"`, tokens)
		Expect(offsets).To(Equal([]int{-1, 0, 2, 5, 8}))
	})
})
