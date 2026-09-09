// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's list_certificates tool (src/tools.ts) to Cobra.
// Registered as a child of the "certificates" novel-group parent in
// certificates.go, alongside the "certificates fit" transcendence command.

package cli

import (
	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newCertificatesListCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Yale certificate programs from the official catalog",
		Long: "List all certificate programs available in Yale College from the official Yale " +
			"course catalog (catalog.yale.edu/ycps/programs_certificates/). Returns certificate " +
			"names and slugs grouped by category: Advanced Language Certificates, Interdisciplinary " +
			"Certificates, and Skills-Based Certificates. Use the returned slugs with " +
			"'majors requirements' to fetch full requirements for a certificate.",
		Example:     "  yalie-pp-cli certificates list --json",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "certificates list")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			html, err := yale.FetchRawHTML(ctx, yale.CatalogBase+"/ycps/programs_certificates/")
			if err != nil {
				return apiErr(err)
			}
			certs := yale.ExtractCertificateLinks(html)
			if certs == nil {
				certs = []yale.Cert{}
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": len(certs), "certificates": certs}, flags)
		},
	}
	return cmd
}
