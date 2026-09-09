// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"github.com/spf13/cobra"
)

func newNovelWorksheetCmd(flags *rootFlags) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "worksheet",
		Short: "View and manage CourseTable worksheets",
		Long: "View, create, and modify CourseTable worksheets, or check a worksheet for schedule " +
			"conflicts and search its fetched syllabi.\n\n" +
			"NOTE on Yale credits: Lectures and seminars typically carry 1 credit. Discussion " +
			"sections often carry 0 credits, and labs often carry 0.5 credits — but these are " +
			"conventions, not rules. Always use the credits field as the authoritative value.\n\n" +
			"TIP: Link directly to a course in the worksheet view with: " +
			"https://coursetable.com/worksheet?course-modal={season}-{crn}",
		Example:     "  yalie-pp-cli worksheet list\n  yalie-pp-cli worksheet conflicts --season 202603",
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	addNovelCommandIfAbsent(cmd, newWorksheetListCmd(flags))
	addNovelCommandIfAbsent(cmd, newWorksheetSetCourseCmd(flags))
	addNovelCommandIfAbsent(cmd, newWorksheetManageCmd(flags))
	addNovelCommandIfAbsent(cmd, newNovelWorksheetConflictsCmd(flags))
	addNovelCommandIfAbsent(cmd, newNovelWorksheetSyllabusSearchCmd(flags))
	return cmd
}
