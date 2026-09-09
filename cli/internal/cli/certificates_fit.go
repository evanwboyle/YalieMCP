// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Transcendence command: same pattern as 'majors fit', applied to certificate
// programs — matches real course history against a scraped catalog
// certificate's requirement text.

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

// pp:data-source live
//
// Always fetches the degree audit and the catalog requirements page live —
// there is no local cache for either, so this command does not honor
// --data-source local.
func newNovelCertificatesFitCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fit <slug-or-name>",
		Short: "Check how much of a certificate's requirements your course history already satisfies",
		Long: "Match your real course history (from the live degree audit) against a scraped " +
			"catalog certificate's requirement text, without declaring the certificate. Requires " +
			"AUDIT_COOKIE. Use 'certificates list' to find valid slugs.\n\n" +
			"Use this to check completion against one specific certificate's requirements using " +
			"your own course history. Do NOT use it for browsing general certificate text; use " +
			"'certificates list' for that." + subjectEligibilityNote +
			"\n\nThis is a KEYWORD-MATCH heuristic: it flags a course as \"mentioned\" only when " +
			"its subject+number literally appears in the requirements text. Many courses satisfy " +
			"a requirement without being named — always verify with the official requirements text.",
		Example:     "  yalie-pp-cli certificates fit data-science --json",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "certificates fit")
			}
			if flags.dataSource == "local" {
				return usageErr(fmt.Errorf("certificates fit has no local data source — the degree audit and catalog requirements text are always fetched live; drop --data-source local"))
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
