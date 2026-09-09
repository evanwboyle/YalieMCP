// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's search_professors tool (src/tools.ts) to Cobra.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newProfessorsCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "professors",
		Short:       "Search CourseTable professors",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newProfessorsSearchCmd(flags))
	return cmd
}

func newProfessorsSearchCmd(flags *rootFlags) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "search <name>",
		Short: "Search for professors by name",
		Long: "Search for professors by name. Returns professor rating and their recent courses " +
			"across all seasons. Useful for finding which professor teaches a course, exploring a " +
			"professor's teaching history, or finding what season a course was last offered. To " +
			"then search for a professor's courses in a specific season, use 'courses search' " +
			"with --professor.",
		Example:     "  yalie-pp-cli professors search Spielman",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "professors search")
			}
			if limit <= 0 || limit > 20 {
				limit = 10
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var data struct {
				Professors []yale.Professor `json:"professors"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.SearchProfessorsQuery, map[string]any{
				"name": "%" + args[0] + "%", "limit": limit,
			}, &data); err != nil {
				return apiErr(err)
			}
			if len(data.Professors) == 0 {
				if !wantsHumanTable(cmd.OutOrStdout(), flags) {
					return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": 0, "professors": []any{}}, flags)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "No professors found matching %q.\n", args[0])
				return nil
			}
			var results []map[string]any
			for _, p := range data.Professors {
				var recent []map[string]any
				for _, cp := range p.CourseProfessors {
					code := "—"
					if len(cp.Course.Listings) > 0 {
						code = cp.Course.Listings[0].CourseCode
					}
					recent = append(recent, map[string]any{
						"course_id": cp.Course.CourseID, "code": code, "title": cp.Course.Title,
						"season": yale.SeasonLabel(cp.Course.Season.SeasonCode),
					})
				}
				results = append(results, map[string]any{
					"professor_id": p.ProfessorID, "name": p.Name, "avg_rating": yale.Round1(p.AverageRating), "recent_courses": recent,
				})
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": len(results), "professors": results}, flags)
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 10, "Max results (default 10, max 20)")
	return cmd
}
