// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"github.com/spf13/cobra"
)

func newNovelAuditCmd(flags *rootFlags) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Fetch your Yale degree audit and get course recommendations",
		Long: "Fetch the authenticated student's Yale degree audit (GPA, requirement blocks, course " +
			"history), or get course recommendations for a specific unmet requirement.\n\n" +
			"Use 'audit recommend' to find highly-rated courses for unmet requirements. Do NOT " +
			"use it for general course search; use 'courses search' for that, or 'audit get' for " +
			"the raw requirement list alone.",
		Example:     "  yalie-pp-cli audit get\n  yalie-pp-cli audit recommend --block 'Humanities & Arts' --json",
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	addNovelCommandIfAbsent(cmd, newAuditGetCmd(flags))
	addNovelCommandIfAbsent(cmd, newNovelAuditRecommendCmd(flags))
	return cmd
}
