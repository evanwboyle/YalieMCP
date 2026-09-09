// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_degree_audit tool (src/tools.ts) to
// Cobra. Registered as a child of the "audit" novel-group parent in
// audit.go, alongside the "audit recommend" transcendence command.

package cli

import (
	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newAuditGetCmd(flags *rootFlags) *cobra.Command {
	var school, degree string
	var includeCourses bool

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Fetch the authenticated student's Yale degree audit",
		Long: "Fetch the authenticated student's Yale degree audit — overall progress, GPA, " +
			"requirement blocks with completion percentages, and full course history with grades. " +
			"Also returns advisor info, degree/major, class year, and distributional attributes " +
			"per course. Requires AUDIT_COOKIE (copy document.cookie from a logged-in " +
			"degreeaudit.yale.edu tab).",
		Example:     "  yalie-pp-cli audit get --json\n  yalie-pp-cli audit get --school UG --degree BA --include-courses=false",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "audit get")
			}
			cookie, err := requireAuditCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			result, err := yale.FetchDegreeAudit(ctx, cookie, school, degree, includeCourses)
			if err != nil {
				return apiErr(err)
			}
			return printJSONFiltered(cmd.OutOrStdout(), result, flags)
		},
	}
	cmd.Flags().StringVar(&school, "school", "UG", "School code, default 'UG'")
	cmd.Flags().StringVar(&degree, "degree", "BA", "Degree code, default 'BA'")
	cmd.Flags().BoolVar(&includeCourses, "include-courses", true, "Include full course history with grades")
	return cmd
}
