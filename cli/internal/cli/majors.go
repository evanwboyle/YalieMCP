// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"github.com/spf13/cobra"
)

func newNovelMajorsCmd(flags *rootFlags) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "majors",
		Short: "List and browse Yale majors/programs from the official course catalog",
		Long: "List Yale majors/programs, fetch a major's full requirements text, or check your own " +
			"course history against a major's requirements.\n\n" +
			"Course flags (e.g. 'YC CPSC Elective') are a useful signal but not the complete " +
			"picture. Many departments have eligibility rules that go beyond what flags capture — " +
			"e.g. certain course-number ranges or cross-listed subjects may satisfy requirements " +
			"without carrying the flag. Always read the DUS requirements text to understand the " +
			"full eligibility rules.",
		Example:     "  yalie-pp-cli majors list\n  yalie-pp-cli majors requirements computer-science\n  yalie-pp-cli majors fit 'Computer Science' --json",
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	addNovelCommandIfAbsent(cmd, newMajorsListCmd(flags))
	addNovelCommandIfAbsent(cmd, newMajorsRequirementsCmd(flags))
	addNovelCommandIfAbsent(cmd, newNovelMajorsFitCmd(flags))
	return cmd
}
