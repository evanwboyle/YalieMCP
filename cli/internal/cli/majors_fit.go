// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Transcendence command: matches a student's real course history (from the
// live degree audit) against a scraped catalog major's requirement text — no
// declaration flow or API join exists for this.

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

type majorFitCourseMatch struct {
	Code   string `json:"code"`
	Title  string `json:"title"`
	Grade  string `json:"grade"`
	Cited  bool   `json:"mentioned_in_requirements_text"`
}

// pp:data-source live
//
// Always fetches the degree audit and the catalog requirements page live —
// there is no local cache for either, so this command does not honor
// --data-source local.
func newNovelMajorsFitCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fit <slug-or-name>",
		Short: "Check how much of a major's requirements your course history already satisfies",
		Long: "Match your real course history (from the live degree audit) against a scraped " +
			"catalog major's requirement text, without declaring the major. Requires " +
			"AUDIT_COOKIE.\n\n" +
			"Use this to check completion against one specific major's requirements using your " +
			"own course history. Do NOT use it for browsing general requirement text; use " +
			"'majors requirements' for that." + subjectEligibilityNote +
			"\n\nThis is a KEYWORD-MATCH heuristic: it flags a course as \"mentioned\" only when " +
			"its subject+number literally appears in the requirements text. Many courses satisfy " +
			"a requirement without being named (equivalencies, cross-listings, flag-based rules) " +
			"— a course NOT flagged as mentioned may still count. Always verify with 'majors " +
			"requirements' and the DUS before treating this as authoritative.",
		Example:     "  yalie-pp-cli majors fit computer-science --json",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "majors fit")
			}
			if flags.dataSource == "local" {
				return usageErr(fmt.Errorf("majors fit has no local data source — the degree audit and catalog requirements text are always fetched live; drop --data-source local"))
			}
			cookie, err := requireAuditCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()

			slug := yale.CleanSlug(args[0])
			reqURL := yale.CatalogBase + "/ycps/subjects-of-instruction/" + slug + "/"
			reqText, err := yale.FetchCatalogText(ctx, reqURL)
			if err != nil {
				return apiErr(err)
			}
			if len(reqText) < 100 {
				return notFoundErr(&fitNotFoundError{slug: slug})
			}

			audit, err := yale.FetchDegreeAudit(ctx, cookie, "UG", "BA", true)
			if err != nil {
				return apiErr(err)
			}

			lowerReq := strings.ToLower(reqText)
			var matches []majorFitCourseMatch
			mentioned := 0
			for _, c := range audit.Courses {
				if c.InProgress || c.Code == "" {
					continue
				}
				cited := strings.Contains(lowerReq, strings.ToLower(c.Code))
				if cited {
					mentioned++
				}
				matches = append(matches, majorFitCourseMatch{Code: c.Code, Title: c.Title, Grade: c.Grade, Cited: cited})
			}
			if matches == nil {
				matches = []majorFitCourseMatch{}
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
				"slug": slug, "requirements_source": reqURL,
				"courses_mentioned_in_requirements_text": mentioned,
				"courses_checked":                        len(matches),
				"courses":                                matches,
				"caveat":                                  "Keyword-match heuristic only — not an authoritative eligibility determination. See --help.",
			}, flags)
		},
	}
	return cmd
}

type fitNotFoundError struct{ slug string }

func (e *fitNotFoundError) Error() string {
	return "no requirements content found for slug '" + e.slug + "'. Use 'majors list' to find the correct slug."
}
