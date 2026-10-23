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

package selector

import (
	"errors"
	"strings"
	"testing"
)

func TestAnalyzeComplexity(t *testing.T) {
	rep, err := AnalyzeComplexity(`a contains "b" && c == "d"`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.RegexCount != 1 || rep.LabelCount != 2 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if rep.IndexCost == 0 {
		t.Fatalf("expected a non-zero index cost, got %+v", rep)
	}
	if rep.NestingDepth != 0 {
		t.Fatalf("expected zero nesting depth, got %d", rep.NestingDepth)
	}
}

func TestAnalyzeComplexityOverLimitIsLocatable(t *testing.T) {
	depth := 101
	sel := strings.Repeat("(", depth) + `a == "b"` + strings.Repeat(")", depth)
	_, err := AnalyzeComplexity(sel)
	if err == nil {
		t.Fatalf("expected a complexity error for depth %d", depth)
	}
	var le *LimitExceededError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LimitExceededError, got %T: %v", err, err)
	}
	if le.Metric != "nesting depth" || le.Value != depth || le.Offset != depth-1 {
		t.Fatalf("unexpected error details: %+v", le)
	}
	if !strings.Contains(err.Error(), "^") {
		t.Fatalf("expected a caret in the error, got: %v", err)
	}
	// The same error must surface through Parse/Validate.
	if _, err := Parse(sel); !errors.As(err, &le) {
		t.Fatalf("Parse should reject over-limit selector with a locatable error, got: %v", err)
	}
	if err := Validate(sel); !errors.As(err, &le) {
		t.Fatalf("Validate should reject over-limit selector, got: %v", err)
	}
}
