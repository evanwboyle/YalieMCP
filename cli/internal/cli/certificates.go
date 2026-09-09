// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"github.com/spf13/cobra"
)

func newNovelCertificatesCmd(flags *rootFlags) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "certificates",
		Short: "List Yale certificate programs and check your fit against one",
		Long: "List all Yale College certificate programs from the official course catalog, or check " +
			"your own course history against one certificate's requirements.",
		Example:     "  yalie-pp-cli certificates list\n  yalie-pp-cli certificates fit 'Data Science' --json",
		Annotations: map[string]string{"mcp:read-only": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	addNovelCommandIfAbsent(cmd, newCertificatesListCmd(flags))
	addNovelCommandIfAbsent(cmd, newNovelCertificatesFitCmd(flags))
	return cmd
}
