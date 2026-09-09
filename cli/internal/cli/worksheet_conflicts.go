// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Transcendence command: decodes and compares meeting-time bitmasks across
// every course in a worksheet to flag real schedule overlaps — no CourseTable
// API endpoint does this.

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

type worksheetConflict struct {
	CourseA string `json:"course_a"`
	CourseB string `json:"course_b"`
	Day     string `json:"day"`
	TimeA   string `json:"time_a"`
	TimeB   string `json:"time_b"`
}

// pp:data-source live
//
// Fetches the worksheet and course meeting times live on every call — there
// is no local worksheet or meeting-time cache to fall back to, so this
// command does not honor --data-source local.
func newNovelWorksheetConflictsCmd(flags *rootFlags) *cobra.Command {
	var flagSeason string
	var worksheetNumber int

	cmd := &cobra.Command{
		Use:   "conflicts",
		Short: "Flag real schedule overlaps between courses in a worksheet",
		Long: "Decode and compare meeting-time bitmasks across every course already saved in a " +
			"CourseTable worksheet, flagging real time overlaps. Requires COURSETABLE_COOKIE.\n\n" +
			"Use this to check for time overlaps in a saved worksheet. Do NOT use it for comparing " +
			"course content; use 'courses compare' for that.",
		Example:     "  yalie-pp-cli worksheet conflicts --season 202603",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "worksheet conflicts")
			}
			if flags.dataSource == "local" {
				return usageErr(fmt.Errorf("worksheet conflicts has no local data source — worksheet contents and meeting times are always fetched live; drop --data-source local"))
			}
			if !yale.IsValidSeasonCode(flagSeason) {
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code"))
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()

			raw, err := yale.GetWorksheetsRaw(ctx, cookie)
			if err != nil {
				return apiErr(err)
			}
			seasonWorksheets, ok := raw[flagSeason]
			if !ok {
				return emptyConflicts(cmd, flags, fmt.Sprintf("no worksheet found for season %s", flagSeason))
			}
			wsKey := fmt.Sprintf("%d", worksheetNumber)
			ws, ok := seasonWorksheets[wsKey]
			if !ok {
				return emptyConflicts(cmd, flags, fmt.Sprintf("no worksheet #%d found for season %s", worksheetNumber, flagSeason))
			}
			var crns []int
			for _, c := range ws.Courses {
				crns = append(crns, c.CRN)
			}
			if len(crns) < 2 {
				return emptyConflicts(cmd, flags, "worksheet has fewer than 2 courses; nothing to check")
			}

			var data struct {
				Courses []yale.Course `json:"courses"`
			}
			where := map[string]any{"_and": []map[string]any{
				{"season_code": map[string]any{"_eq": flagSeason}},
				{"listings": map[string]any{"crn": map[string]any{"_in": crns}}},
			}}
			if err := yale.GQL(ctx, cookie, yale.SearchQuery, map[string]any{"where": where, "limit": len(crns) * 2}, &data); err != nil {
				return apiErr(err)
			}

			conflicts := findScheduleConflicts(data.Courses)
			if !wantsHumanTable(cmd.OutOrStdout(), flags) {
				return printJSONFiltered(cmd.OutOrStdout(), conflicts, flags)
			}
			if len(conflicts) == 0 {
				cmd.Println("No schedule conflicts found.")
				return nil
			}
			for _, c := range conflicts {
				cmd.Printf("CONFLICT: %s (%s) overlaps %s (%s) on %s\n", c.CourseA, c.TimeA, c.CourseB, c.TimeB, c.Day)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flagSeason, "season", "", "Season code e.g. '202603'")
	cmd.Flags().IntVar(&worksheetNumber, "worksheet-number", 0, "Worksheet number (0 = default)")
	return cmd
}

func emptyConflicts(cmd *cobra.Command, flags *rootFlags, note string) error {
	rows := make([]worksheetConflict, 0)
	if !wantsHumanTable(cmd.OutOrStdout(), flags) {
		return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"conflicts": rows, "note": note}, flags)
	}
	cmd.Println(note)
	return nil
}

// findScheduleConflicts decodes each course's meeting-time bitmasks and
// flags any pair of distinct courses that share a day and an overlapping
// time range.
func findScheduleConflicts(courses []yale.Course) []worksheetConflict {
	type meetingSlot struct {
		code           string
		day            string
		startH, startM int
		endH, endM     int
	}
	var slots []meetingSlot
	for _, c := range courses {
		code := c.PrimaryCode()
		for _, m := range c.CourseMeetings {
			days := yale.DecodeDays(m.DaysOfWeek)
			if days == "TBA" {
				continue
			}
			sh, sm := parseHM(m.StartTime)
			eh, em := parseHM(m.EndTime)
			for _, day := range strings.Split(days, "/") {
				slots = append(slots, meetingSlot{code: code, day: day, startH: sh, startM: sm, endH: eh, endM: em})
			}
		}
	}
	var conflicts []worksheetConflict
	for i := 0; i < len(slots); i++ {
		for j := i + 1; j < len(slots); j++ {
			a, b := slots[i], slots[j]
			if a.code == b.code || a.day != b.day {
				continue
			}
			aStart, aEnd := a.startH*60+a.startM, a.endH*60+a.endM
			bStart, bEnd := b.startH*60+b.startM, b.endH*60+b.endM
			if aStart < bEnd && bStart < aEnd {
				conflicts = append(conflicts, worksheetConflict{
					CourseA: a.code, CourseB: b.code, Day: a.day,
					TimeA: fmt.Sprintf("%02d:%02d-%02d:%02d", a.startH, a.startM, a.endH, a.endM),
					TimeB: fmt.Sprintf("%02d:%02d-%02d:%02d", b.startH, b.startM, b.endH, b.endM),
				})
			}
		}
	}
	if conflicts == nil {
		conflicts = []worksheetConflict{}
	}
	return conflicts
}

func parseHM(t string) (int, int) {
	var h, m int
	if _, err := fmt.Sscanf(t, "%d:%d", &h, &m); err != nil {
		return 0, 0
	}
	return h, m
}
