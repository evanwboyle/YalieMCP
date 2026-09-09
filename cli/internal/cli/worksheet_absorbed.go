// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_worksheets / update_worksheet_course /
// update_worksheet_metadata tools (src/tools.ts) to Cobra. Registered as
// children of the "worksheet" novel-group parent in worksheet.go, alongside
// the "worksheet conflicts" / "worksheet syllabus-search" transcendence
// commands.

package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newWorksheetListCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Get the authenticated user's CourseTable worksheets",
		Long: "Get the authenticated user's CourseTable worksheets. Returns all seasons with " +
			"worksheets, each containing named course lists (CRN, title, credits, color, hidden " +
			"flag). Requires COURSETABLE_COOKIE." + creditsConventionNote + deepLinkNote,
		Example:     "  yalie-pp-cli worksheet list",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "worksheet list")
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			enriched, err := fetchEnrichedWorksheets(ctx, cookie)
			if err != nil {
				return apiErr(err)
			}
			return printJSONFiltered(cmd.OutOrStdout(), enriched, flags)
		},
	}
	return cmd
}

type enrichedWorksheetCourse struct {
	CRN     int      `json:"crn"`
	Title   *string  `json:"title"`
	Credits *float64 `json:"credits"`
	Color   string   `json:"color"`
	Hidden  *bool    `json:"hidden"`
}

// fetchEnrichedWorksheets fetches the raw worksheet data, then batch-fetches
// title/credits for every referenced CRN via GraphQL, ported from tools.ts
// get_worksheets.
func fetchEnrichedWorksheets(ctx context.Context, cookie string) (map[string]map[string]map[string]any, error) {
	raw, err := yale.GetWorksheetsRaw(ctx, cookie)
	if err != nil {
		return nil, err
	}

	var allCRNs []int
	for _, seasons := range raw {
		for _, ws := range seasons {
			for _, c := range ws.Courses {
				allCRNs = append(allCRNs, c.CRN)
			}
		}
	}

	type courseKey struct {
		title   string
		credits *float64
	}
	crnMap := map[string]courseKey{}
	if len(allCRNs) > 0 {
		courses, err := yale.GetWorksheetCoursesInfo(ctx, cookie, allCRNs)
		if err != nil {
			return nil, err
		}
		for _, c := range courses {
			for _, l := range c.Listings {
				crnMap[fmt.Sprintf("%s-%d", c.SeasonCode, l.CRN)] = courseKey{title: c.Title, credits: c.Credits}
			}
		}
	}

	enriched := map[string]map[string]map[string]any{}
	for season, worksheets := range raw {
		enriched[season] = map[string]map[string]any{}
		for wsNum, ws := range worksheets {
			var courses []enrichedWorksheetCourse
			for _, c := range ws.Courses {
				key := crnMap[fmt.Sprintf("%s-%d", season, c.CRN)]
				var title *string
				if key.title != "" {
					t := key.title
					title = &t
				}
				courses = append(courses, enrichedWorksheetCourse{CRN: c.CRN, Title: title, Credits: key.credits, Color: c.Color, Hidden: c.Hidden})
			}
			enriched[season][wsNum] = map[string]any{"name": ws.Name, "courses": courses}
		}
	}
	return enriched, nil
}

func newWorksheetSetCourseCmd(flags *rootFlags) *cobra.Command {
	var action, season string
	var crn, worksheetNumber int
	var color string
	var hidden bool

	cmd := &cobra.Command{
		Use:   "set-course",
		Short: "Add, remove, or update a course in a CourseTable worksheet",
		Long: "Add, remove, or update a course in a CourseTable worksheet. For 'add': --color and " +
			"--hidden are required. For 'update': --color/--hidden are optional. For 'remove': " +
			"--color/--hidden are ignored. Requires COURSETABLE_COOKIE.",
		Example: "  yalie-pp-cli worksheet set-course --action add --season 202503 --crn 10529 --color blue\n" +
			"  yalie-pp-cli worksheet set-course --action remove --season 202503 --crn 10529 --dry-run",
		Annotations: map[string]string{"mcp:read-only": "false"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "worksheet set-course")
			}
			if action != "add" && action != "remove" && action != "update" {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--action must be 'add', 'remove', or 'update'"))
			}
			if !yale.IsValidSeasonCode(season) {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code"))
			}
			if crn <= 0 {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--crn is required"))
			}
			if action == "add" && (color == "" || !cmd.Flags().Changed("hidden")) {
				return usageErr(fmt.Errorf("--color and --hidden are required for --action add"))
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var colorPtr *string
			var hiddenPtr *bool
			if cmd.Flags().Changed("color") {
				colorPtr = &color
			}
			if cmd.Flags().Changed("hidden") {
				hiddenPtr = &hidden
			}
			if err := yale.UpdateWorksheetCourse(ctx, cookie, action, season, crn, worksheetNumber, colorPtr, hiddenPtr); err != nil {
				return apiErr(err)
			}
			verb := map[string]string{"add": "added to", "remove": "removed from", "update": "updated in"}[action]
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
				"ok": true, "message": fmt.Sprintf("Course CRN %d %s worksheet %d (%s).", crn, verb, worksheetNumber, season),
			}, flags)
		},
	}
	cmd.Flags().StringVar(&action, "action", "", "add, remove, or update")
	cmd.Flags().StringVar(&season, "season", "", "Season code e.g. '202503'")
	cmd.Flags().IntVar(&crn, "crn", 0, "Course registration number")
	cmd.Flags().IntVar(&worksheetNumber, "worksheet-number", 0, "Worksheet number (0 = default)")
	cmd.Flags().StringVar(&color, "color", "", "Color string (required for add, optional for update)")
	cmd.Flags().BoolVar(&hidden, "hidden", false, "Hidden flag (required for add, optional for update)")
	return cmd
}

func newWorksheetManageCmd(flags *rootFlags) *cobra.Command {
	var action, season, name string
	var worksheetNumber int
	var hasWorksheetNumber bool

	cmd := &cobra.Command{
		Use:   "manage",
		Short: "Create, delete, or rename a CourseTable worksheet",
		Long: "Create, delete, or rename a CourseTable worksheet. add: creates a new worksheet with " +
			"the given name, returns worksheetNumber. delete: removes a worksheet by number. " +
			"rename: renames a worksheet. Requires COURSETABLE_COOKIE.",
		Example: "  yalie-pp-cli worksheet manage --action add --season 202503 --name \"Fall Plan\"\n" +
			"  yalie-pp-cli worksheet manage --action rename --season 202503 --worksheet-number 1 --name \"Backup\" --dry-run",
		Annotations: map[string]string{"mcp:read-only": "false"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "worksheet manage")
			}
			if action != "add" && action != "delete" && action != "rename" {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--action must be 'add', 'delete', or 'rename'"))
			}
			if !yale.IsValidSeasonCode(season) {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code"))
			}
			hasWorksheetNumber = cmd.Flags().Changed("worksheet-number")
			if (action == "delete" || action == "rename") && !hasWorksheetNumber {
				return usageErr(fmt.Errorf("--worksheet-number is required for --action %s", action))
			}
			if (action == "add" || action == "rename") && name == "" {
				return usageErr(fmt.Errorf("--name is required for --action %s", action))
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var wsNum *int
			if hasWorksheetNumber {
				wsNum = &worksheetNumber
			}
			var namePtr *string
			if name != "" {
				namePtr = &name
			}
			result, err := yale.UpdateWorksheetMetadata(ctx, cookie, action, season, wsNum, namePtr)
			if err != nil {
				return apiErr(err)
			}
			if action == "add" && result != nil && result.WorksheetNumber != nil {
				return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
					"ok": true, "worksheet_number": *result.WorksheetNumber,
					"message": fmt.Sprintf("Worksheet '%s' created as worksheet #%d in season %s.", name, *result.WorksheetNumber, season),
				}, flags)
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"ok": true, "message": fmt.Sprintf("Worksheet %s successful.", action)}, flags)
		},
	}
	cmd.Flags().StringVar(&action, "action", "", "add, delete, or rename")
	cmd.Flags().StringVar(&season, "season", "", "Season code e.g. '202503'")
	cmd.Flags().IntVar(&worksheetNumber, "worksheet-number", 0, "Required for delete/rename")
	cmd.Flags().StringVar(&name, "name", "", "Required for add/rename")
	return cmd
}
