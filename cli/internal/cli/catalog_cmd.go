// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_catalog_metadata tool (src/tools.ts) to Cobra.

package cli

import (
	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newCatalogCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "catalog",
		Short:       "CourseTable course catalog metadata",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newCatalogMetadataCmd(flags))
	return cmd
}

func newCatalogMetadataCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "metadata",
		Short:       "Get the last time the CourseTable course catalog was updated",
		Long:        "Get the last time the CourseTable course catalog was updated. No authentication required. Returns an ISO date string.",
		Example:     "  yalie-pp-cli catalog metadata",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "catalog metadata")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			data, err := yale.GetCatalogMetadata(ctx)
			if err != nil {
				return apiErr(err)
			}
			return printJSONFiltered(cmd.OutOrStdout(), data, flags)
		},
	}
	return cmd
}
