// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_user_info tool (src/tools.ts) to Cobra.
//
// Named "account whoami" rather than the manifest's literal "profile
// whoami" — the generator reserves both "profile" (run-profile flag
// presets) and bare "whoami" (a conditional platform-identity command
// wired to --client-profile / verified-credential resolution, see
// platform_cli_test.go) as framework command names. Nesting under a new
// "account" parent avoids both collisions. Deliberate deviation from the
// absorb manifest's literal path, noted in the build log.

package cli

import (
	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newAccountCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "account",
		Short:       "Yale account / profile info",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newAccountWhoamiCmd(flags))
	return cmd
}

func newAccountWhoamiCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Get the authenticated user's Yale profile",
		Long: "Get the authenticated user's Yale profile: netId, name, email, class year, school, " +
			"major, and whether they have evaluation access (hasEvals). Requires COURSETABLE_COOKIE.",
		Example:     "  yalie-pp-cli account whoami",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "account whoami")
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			info, err := yale.GetUserInfo(ctx, cookie)
			if err != nil {
				return apiErr(err)
			}
			return printJSONFiltered(cmd.OutOrStdout(), info, flags)
		},
	}
	return cmd
}
