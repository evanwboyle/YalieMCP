// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_wishlist / update_wishlist_course tools
// (src/tools.ts) to Cobra.

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newWishlistCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "wishlist",
		Short:       "View and manage the CourseTable wishlist",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newWishlistListCmd(flags))
	cmd.AddCommand(newWishlistSetCourseCmd(flags))
	return cmd
}

func newWishlistListCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "list",
		Short:       "Get the authenticated user's CourseTable wishlist",
		Long:        "Get the authenticated user's CourseTable wishlist. Returns a list of {season, crn} pairs. Requires COURSETABLE_COOKIE.",
		Example:     "  yalie-pp-cli wishlist list",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "wishlist list")
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			items, err := yale.GetWishlist(ctx, cookie)
			if err != nil {
				return apiErr(err)
			}
			if items == nil {
				items = []yale.WishlistItem{}
			}
			return printJSONFiltered(cmd.OutOrStdout(), items, flags)
		},
	}
	return cmd
}

func newWishlistSetCourseCmd(flags *rootFlags) *cobra.Command {
	var action, season string
	var crn int
	cmd := &cobra.Command{
		Use:   "set-course",
		Short: "Add or remove a course from the wishlist",
		Long:  "Add or remove a course from the user's CourseTable wishlist. Requires COURSETABLE_COOKIE.",
		Example: "  yalie-pp-cli wishlist set-course --action add --season 202503 --crn 10529\n" +
			"  yalie-pp-cli wishlist set-course --action remove --season 202503 --crn 10529 --dry-run",
		Annotations: map[string]string{"mcp:read-only": "false"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "wishlist set-course")
			}
			if action != "add" && action != "remove" {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--action must be 'add' or 'remove'"))
			}
			if !yale.IsValidSeasonCode(season) {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code"))
			}
			if crn <= 0 {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--crn is required"))
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			if err := yale.UpdateWishlistCourse(ctx, cookie, action, season, crn); err != nil {
				return apiErr(err)
			}
			verb := "added to"
			if action == "remove" {
				verb = "removed from"
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
				"ok": true, "message": fmt.Sprintf("Course CRN %d (%s) %s wishlist.", crn, season, verb),
			}, flags)
		},
	}
	cmd.Flags().StringVar(&action, "action", "", "add or remove")
	cmd.Flags().StringVar(&season, "season", "", "Season code e.g. '202503'")
	cmd.Flags().IntVar(&crn, "crn", 0, "Course registration number")
	return cmd
}
