// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's list_majors / get_major_requirements tools
// (src/tools.ts) to Cobra. Registered as children of the "majors" novel-group
// parent in majors.go, alongside the "majors fit" transcendence command.

package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

// majorEntry is one major/program list_majors row.
type majorEntry struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// listMajors scrapes the catalog A-Z index for subjects-of-instruction
// links, ported from tools.ts list_majors.
func listMajors(ctx context.Context) ([]majorEntry, error) {
	html, err := yale.FetchRawHTML(ctx, yale.CatalogBase+"/ycps/azindex/")
	if err != nil {
		return nil, err
	}
	links := yale.ExtractCatalogLinks(html)
	seen := map[string]bool{}
	var out []majorEntry
	for _, l := range links {
		if seen[l.Href] {
			continue
		}
		seen[l.Href] = true
		slug := trimMajorSlug(l.Href)
		out = append(out, majorEntry{Name: l.Text, Slug: slug})
	}
	if out == nil {
		out = []majorEntry{}
	}
	return out, nil
}

func trimMajorSlug(href string) string {
	s := href
	const prefix = "/ycps/subjects-of-instruction/"
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		s = s[len(prefix):]
	}
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func newMajorsListCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all Yale majors and programs from the official catalog",
		Long: "List all Yale majors and programs from the official Yale course catalog " +
			"(catalog.yale.edu). Returns names and URL slugs. Use slugs with 'majors requirements' " +
			"to fetch requirements.",
		Example:     "  yalie-pp-cli majors list --json",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "majors list")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			majors, err := listMajors(ctx)
			if err != nil {
				return apiErr(err)
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": len(majors), "majors": majors}, flags)
		},
	}
	return cmd
}

func newMajorsRequirementsCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "requirements <slug>",
		Short: "Fetch major or program requirements from the official catalog",
		Long: "Fetch major or program requirements from the official Yale course catalog " +
			"(catalog.yale.edu). Use 'majors list' to find valid slugs (e.g. 'computer-science', " +
			"'mathematics', 'economics'). Returns the full requirements text including " +
			"prerequisites, core courses, distributional requirements, and senior requirements." +
			subjectEligibilityNote +
			"\n\nNOTE — course flags vs. DUS rules: course flags (e.g. 'YC CPSC Elective') are a " +
			"useful signal but are not the complete picture. Many departments have eligibility " +
			"rules that go beyond what flags capture — for example, certain course number ranges " +
			"or cross-listed subjects may automatically satisfy requirements without carrying the " +
			"corresponding flag. Always read the DUS requirements text here to understand the " +
			"full eligibility rules for a major.",
		Example:     "  yalie-pp-cli majors requirements computer-science",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "majors requirements")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			clean := yale.CleanSlug(args[0])
			url := yale.CatalogBase + "/ycps/subjects-of-instruction/" + clean + "/"
			text, err := yale.FetchCatalogText(ctx, url)
			if err != nil {
				return apiErr(err)
			}
			if len(text) < 100 {
				return notFoundErr(fmt.Errorf("no content found at %s. Use 'majors list' to find the correct slug.", url))
			}
			truncated := false
			if len(text) > 12000 {
				text = text[:12000] + "\n\n[truncated — content continues at " + url + "]"
				truncated = true
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"source": url, "text": text, "truncated": truncated}, flags)
		},
	}
	return cmd
}
