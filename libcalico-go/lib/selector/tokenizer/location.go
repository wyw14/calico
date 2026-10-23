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

package tokenizer

import "strings"

// TokenOffsets returns the byte offset within input of the first byte of
// each token.  The tokens slice must have been produced from input by
// Tokenize or AppendTokens; in particular the final TokEOF is given the
// end-of-input offset (after any trailing whitespace).
//
// Offsets are reconstructed from input and the token values rather than
// being stored on Token, so the common (hot) tokenization path does no
// extra work and Token keeps its small footprint.
func TokenOffsets(input string, tokens []Token) []int {
	return AppendTokenOffsets(nil, input, tokens)
}

// AppendTokenOffsets is the append-friendly variant of TokenOffsets; it
// appends the offsets to the supplied slice (which may be nil).
func AppendTokenOffsets(offsets []int, input string, tokens []Token) []int {
	pos := 0
	for _, tok := range tokens {
		pos = skipSpaces(input, pos)
		offsets = append(offsets, pos)
		if tok.Kind == TokEOF {
			// EOF is the last token; there is nothing after it.
			break
		}
		pos = advancePastToken(input, pos, tok)
	}
	return offsets
}

// skipSpaces skips the same whitespace characters as the tokenizer itself
// (spaces and tabs).
func skipSpaces(input string, pos int) int {
	for pos < len(input) && (input[pos] == ' ' || input[pos] == '\t') {
		pos++
	}
	return pos
}

// advancePastToken returns the offset just past the token that starts at
// pos.  It mirrors the lexical rules implemented by AppendTokens.
func advancePastToken(input string, pos int, tok Token) int {
	switch tok.Kind {
	case TokLParen, TokRParen, TokLBrace, TokRBrace, TokComma, TokNot:
		return pos + 1
	case TokEq, TokNe, TokAnd, TokOr:
		// "==", "!=", "&&", "||".
		return pos + 2
	case TokStringLiteral:
		// The tokenizer terminates a literal at the first occurrence of
		// the opening quote character.
		q := input[pos]
		end := strings.IndexByte(input[pos+1:], q)
		return pos + 1 + end + 1
	case TokLabel:
		return pos + len(tok.Value)
	case TokContains:
		return pos + len("contains")
	case TokStartsWith:
		return skipSpaces(input, pos+len("starts")) + len("with")
	case TokEndsWith:
		return skipSpaces(input, pos+len("ends")) + len("with")
	case TokIn:
		return pos + len("in")
	case TokNotIn:
		// "not" and "in" may be separated by whitespace (or run together
		// as "notin").
		return skipSpaces(input, pos+len("not")) + len("in")
	case TokHas:
		p := pos + len("has(")
		p = skipSpaces(input, p)
		p += len(tok.Value)
		p = skipSpaces(input, p)
		return p + len(")")
	case TokAll:
		p := pos + len("all(")
		p = skipSpaces(input, p)
		return p + len(")")
	case TokGlobal:
		p := pos + len("global(")
		p = skipSpaces(input, p)
		return p + len(")")
	}
	return pos
}
