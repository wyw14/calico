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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/networkset"
)

func newNetworkSetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "networkset",
		Short: "Offline operations on NetworkSet and GlobalNetworkSet resources",
		Long: `Work with NetworkSet and GlobalNetworkSet manifests without contacting a
datastore. These commands read resource YAML/JSON, transform the CIDR lists
they contain, and print YAML that can be piped straight into create or apply.`,
	}
	cmd.AddCommand(newNetworkSetSubtractCommand())
	return cmd
}

func newNetworkSetSubtractCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subtract",
		Short: "Subtract CIDRs from a NetworkSet or GlobalNetworkSet",
		Long: `Subtract a list of CIDRs from the spec.nets of one or more NetworkSet or
GlobalNetworkSet resources read from a file, directory, or stdin. The command
runs entirely offline and never connects to the datastore.

The remaining address space is represented exactly: overlapping entries are
de-duplicated, adjacent or overlapping CIDRs are merged into the fewest
possible prefixes, and the result is stably sorted (IPv4 then IPv6). Full
coverage produces an empty nets list. Name, namespace and user labels and
annotations are preserved; server-generated metadata (resourceVersion, UID,
timestamps, and so on) is stripped. The resulting same-kind YAML can be fed
directly to "calicoctl create" or "calicoctl apply".

CIDRs to subtract may be passed with --subtract-cidr (repeatable) and/or with
--subtract-file, a plain-text file containing CIDRs separated by commas or
whitespace; blank lines and comments introduced by '#' are ignored. Bare IP
addresses are accepted and treated as /32 or /128 prefixes. Any invalid CIDR
in either the input resources or the subtraction list aborts the command
before any output is written.`,
		Example: `  # Subtract two CIDRs from a NetworkSet defined in a file.
  calicoctl networkset subtract -f my-netset.yaml \
    --subtract-cidr 10.0.0.0/24 --subtract-cidr 10.0.1.0/24

  # Subtract every CIDR listed in a text file from a GlobalNetworkSet on stdin.
  cat gns.yaml | calicoctl networkset subtract -f - --subtract-file cidrs.txt

  # Rewrite the manifest in place after carving out a /26.
  calicoctl networkset subtract -f gns.yaml --subtract-cidr 10.10.0.64/26 \
    | calicoctl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {
			filename, _ := cmd.Flags().GetString("filename")
			recursive, _ := cmd.Flags().GetBool("recursive")
			subtractCIDRs, _ := cmd.Flags().GetStringArray("subtract-cidr")
			subtractFiles, _ := cmd.Flags().GetStringArray("subtract-file")

			if filename == "" {
				return fmt.Errorf("a NetworkSet or GlobalNetworkSet manifest must be supplied with --filename (use \"-f -\" for stdin)")
			}

			return networkset.Subtract(networkset.Options{
				Filename:      filename,
				Recursive:     recursive,
				SubtractCIDRs: subtractCIDRs,
				SubtractFiles: subtractFiles,
			}, os.Stdout)
		},
	}
	cmd.Flags().StringP("filename", "f", "", "Filename identifying a NetworkSet or GlobalNetworkSet manifest to subtract from. Use '-' for stdin; directories are processed with --recursive.")
	cmd.Flags().BoolP("recursive", "R", false, "Process the filename specified in -f recursively.")
	cmd.Flags().StringArray("subtract-cidr", nil, "CIDR (or bare IP address) to subtract. Can be specified multiple times, and may contain comma-separated CIDRs.")
	cmd.Flags().StringArray("subtract-file", nil, "Plain-text file containing CIDRs to subtract. Can be specified multiple times.")
	return cmd
}
