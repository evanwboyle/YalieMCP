// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_curriculum_info tool (src/tools.ts) to Cobra.

package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newCurriculumCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "curriculum",
		Short:       "Yale College curriculum and academic policy info",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newCurriculumInfoCmd(flags))
	return cmd
}

func newCurriculumInfoCmd(flags *rootFlags) *cobra.Command {
	var sections []string
	for k := range yale.CurriculumSections {
		sections = append(sections, k)
	}
	sort.Strings(sections)

	cmd := &cobra.Command{
		Use:   "info <section>",
		Short: "Fetch Yale College curriculum and academic policy information",
		Long: "Fetch Yale College curriculum and academic policy information from the official Yale " +
			"course catalog. Pass a section slug to retrieve that section's full text.\n\n" +
			"Available sections:\n  " + strings.Join(sections, "\n  "),
		Example:     "  yalie-pp-cli curriculum info distributional-requirements",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "curriculum info")
			}
			clean := yale.CleanSlug(args[0])
			path, ok := yale.CurriculumSections[clean]
			if !ok {
				return usageErr(fmt.Errorf("unknown section %q. Available sections: %s", clean, strings.Join(sections, ", ")))
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			url := yale.CatalogBase + path
			text, err := yale.FetchCatalogText(ctx, url)
			if err != nil {
				return apiErr(err)
			}
			if len(text) < 100 {
				return notFoundErr(fmt.Errorf("no content found at %s", url))
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
