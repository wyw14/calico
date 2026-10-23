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

package commands

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// captureStdout swaps os.Stdout for a pipe while fn runs and returns whatever
// fn wrote to stdout.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	runErr := fn()

	_ = w.Close()
	os.Stdout = oldStdout
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("failed to read captured stdout: %v", err)
	}
	return string(out), runErr
}

// findSubcommand walks the command tree and returns the named subcommand of
// parent, or nil if it is not registered.
func findSubcommand(t *testing.T, parent *cobra.Command, name string) *cobra.Command {
	t.Helper()
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// TestNetworkSetSubtractCommand drives the full cobra command tree, proving
// the new subcommand is wired in and runs entirely offline (there is no
// --config/datastore flag on it).
func TestNetworkSetSubtractCommand(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: NetworkSet
metadata:
  name: wired
  namespace: prod
  resourceVersion: "7"
  labels:
    app: wired
spec:
  nets:
  - 10.0.0.0/24
  - 10.0.0.0/25
  - 2001:db8::/32
`
	path := filepath.Join(t.TempDir(), "wired.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// The command must be registered and must not offer a datastore config
	// flag, since it runs entirely offline.
	root := NewCommand()
	netset := findSubcommand(t, root, "networkset")
	if netset == nil {
		t.Fatal("networkset command group is not registered")
	}
	sub := findSubcommand(t, netset, "subtract")
	if sub == nil {
		t.Fatal("networkset subtract command is not registered")
	}
	if sub.Flags().Lookup("config") != nil {
		t.Error("networkset subtract must be offline and must not register a --config flag")
	}

	// Execute through the tree with no datastore reachable.
	out, err := captureStdout(t, func() error {
		cmd := NewCommand()
		cmd.SetArgs([]string{"networkset", "subtract", "-f", path, "--subtract-cidr", "10.0.0.0/25"})
		return cmd.Execute()
	})
	if err != nil {
		t.Fatalf("command execution failed: %v", err)
	}
	for _, want := range []string{"kind: NetworkSet", "name: wired", "namespace: prod", "app: wired", "10.0.0.128/25", "2001:db8::/32"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, stripped := range []string{"resourceVersion", "uid:", "creationTimestamp"} {
		if strings.Contains(out, stripped) {
			t.Errorf("output should not contain %q:\n%s", stripped, out)
		}
	}
}

// TestNetworkSetSubtractCommandErrors checks the user-facing failures through
// cobra, including invalid CIDR input that must abort before writing output.
func TestNetworkSetSubtractCommandErrors(t *testing.T) {
	manifest := `apiVersion: projectcalico.org/v3
kind: GlobalNetworkSet
metadata:
  name: wired-errors
spec:
  nets:
  - 10.0.0.0/24
`
	path := filepath.Join(t.TempDir(), "wired-errors.yaml")
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	t.Run("missing filename", func(t *testing.T) {
		cmd := NewCommand()
		cmd.SetArgs([]string{"networkset", "subtract"})
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--filename") {
			t.Errorf("expected a --filename error, got %v", err)
		}
	})

	t.Run("invalid subtract CIDR produces no output", func(t *testing.T) {
		out, err := captureStdout(t, func() error {
			cmd := NewCommand()
			cmd.SetArgs([]string{"networkset", "subtract", "-f", path, "--subtract-cidr", "10.0.0.0/42"})
			return cmd.Execute()
		})
		if err == nil {
			t.Fatal("expected an error for an invalid CIDR, got nil")
		}
		if !strings.Contains(err.Error(), "invalid CIDR") {
			t.Errorf("error %q should mention an invalid CIDR", err.Error())
		}
		if out != "" {
			t.Errorf("expected no output, got:\n%s", out)
		}
	})
}
