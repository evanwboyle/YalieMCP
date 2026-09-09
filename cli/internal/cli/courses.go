// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-adapted from a CLI Printing Press generated Canvas endpoint-mirror group.

package cli

import (
	"github.com/spf13/cobra"
)

// newCanvasCmd is the "canvas" command group: pages/assignments/quizzes/
// grades/files browsing for a Canvas course, ported from the generated
// spec-based endpoint mirror. Dual-mode auth (Bearer token if the student's
// Yale account has one, cookie fallback otherwise — Yale blocks
// self-service Canvas token generation for most students, confirmed
// directly during research for this CLI).
func newCanvasCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "canvas",
		Short: "Browse Canvas course content (pages, assignments, quizzes, grades, files)",
		Long: "Browse a Yale Canvas course's pages, assignments, quizzes, grades, and files.\n\n" +
			"Always cite the source URL when presenting page/assignment/quiz/file content. " +
			"Do NOT fetch Canvas URLs yourself outside this CLI — they require authentication " +
			"cookies/tokens this CLI manages internally.",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true", "pp:api-resource": "true", "pp:typed-exit-codes": "0,2"},
		RunE:        parentNoSubcommandRunE(flags),
	}

	cmd.AddCommand(newCanvasAssignmentsCmd(flags))
	cmd.AddCommand(newCanvasGradesCmd(flags))
	cmd.AddCommand(newCanvasFilesCmd(flags))
	cmd.AddCommand(newCanvasPagesCmd(flags))
	cmd.AddCommand(newCanvasQuizzesCmd(flags))
	return cmd
}
