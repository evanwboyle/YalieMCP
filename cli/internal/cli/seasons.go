// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's list_seasons tool (src/tools.ts) to Cobra.

package cli

import (
	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

type seasonView struct {
	Code  string `json:"code"`
	Label string `json:"label"`
}

func newSeasonsCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "seasons",
		Short:       "List available CourseTable academic seasons/terms",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newSeasonsListCmd(flags))
	return cmd
}

func newSeasonsListCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available academic seasons",
		Long: "List all available academic seasons. Returns season codes (e.g. '202303' = Fall " +
			"2023) and labels. Call this first to get valid season_code values for other commands. " +
			"No authentication required — this is a public CourseTable query.",
		Example:     "  yalie-pp-cli seasons list --json",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "seasons list")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var data struct {
				Seasons []struct {
					SeasonCode string `json:"season_code"`
				} `json:"seasons"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.SeasonsQuery, nil, &data); err != nil {
				return apiErr(err)
			}
			out := make([]seasonView, 0, len(data.Seasons))
			for _, s := range data.Seasons {
				out = append(out, seasonView{Code: s.SeasonCode, Label: yale.SeasonLabel(s.SeasonCode)})
			}
			return printJSONFiltered(cmd.OutOrStdout(), out, flags)
		},
	}
	return cmd
}
