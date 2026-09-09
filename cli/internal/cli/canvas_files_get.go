// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-adapted from a CLI Printing Press generated top-level "files" endpoint
// command (GET /files/{id}) into "canvas files get --file <id>", matching the
// absorb manifest's approved command path and its explicit-one-file-at-a-time
// requirement.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newCanvasFilesGetCmd(flags *rootFlags) *cobra.Command {
	var flagFile string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Fetch metadata + download URL for one specific Canvas file by ID",
		Long: "Fetch metadata and a download URL for exactly one Canvas file by ID.\n\n" +
			"Always list a course's Files directory first with 'canvas files list' — NEVER " +
			"bulk-fetch every file in one call. Some Files sections contain entire textbooks; " +
			"auto-fetching would flood context. This command requires an explicit --file id and " +
			"never fetches an entire directory in one call. Always cite the source URL when " +
			"presenting file content to a user.\n\n" +
			"When the requested file is a PDF (by content-type or a .pdf filename/URL), its " +
			"text is downloaded and extracted automatically and included as " +
			"'extracted_text' in the output; a failed extraction is reported as " +
			"'extracted_text_error' instead of failing the whole command.",
		Example: "  yalie-pp-cli canvas files get --file 123456",
		Annotations: map[string]string{
			"pp:endpoint":   "files.get",
			"pp:method":     "GET",
			"pp:path":       "/files/{id}",
			"mcp:read-only": "true",
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "canvas files get")
			}
			if flagFile == "" {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--file is required\nUsage: %s --file <id>", cmd.CommandPath()))
			}
			c, err := flags.newClient()
			if err != nil {
				return err
			}
			path := replacePathParam("/files/{id}", "id", flagFile)
			params := map[string]string{}
			data, prov, err := resolveReadWithStrategyAndResponsePath(cmd.Context(), c, flags, "auto", "files", false, path, params, nil, "", cmd.ErrOrStderr())
			if err != nil {
				return classifyAPIError(cmd.OutOrStdout(), err, flags)
			}
			data = maybeExtractCanvasFilePDF(cmd.Context(), flags, data)
			outputData := data
			if wantsHumanTable(cmd.OutOrStdout(), flags) {
				var countItems []json.RawMessage
				if json.Unmarshal(outputData, &countItems) != nil {
					countItems = []json.RawMessage{outputData}
				}
				printProvenance(cmd, len(countItems), prov)
			}
			if flags.asJSON || (!isTerminal(cmd.OutOrStdout()) && !flags.csv && !flags.quiet && !flags.plain) {
				filtered := data
				if flags.selectFields != "" {
					filtered = filterFields(filtered, flags.selectFields)
				} else if flags.compact {
					filtered = compactFields(filtered, map[string]bool{"content-type": true, "display_name": true, "extracted_text": true, "filename": true, "folder_id": true, "id": true, "size": true, "updated_at": true, "url": true})
				}
				wrapped, wrapErr := wrapWithProvenance(filtered, prov)
				if wrapErr != nil {
					return wrapErr
				}
				wrapped, wrapErr = wrapPlatformStructuredOutput(wrapped, flags, "results", true)
				if wrapErr != nil {
					return wrapErr
				}
				return printOutput(cmd.OutOrStdout(), wrapped, true)
			}
			if wantsHumanTable(cmd.OutOrStdout(), flags) {
				var items []map[string]any
				if json.Unmarshal(outputData, &items) == nil && len(items) > 0 {
					if err := printAutoTable(cmd.OutOrStdout(), items); err != nil {
						return err
					}
					if len(items) >= 25 {
						fmt.Fprintf(os.Stderr, "\nShowing %d results. To narrow: add --limit, --json --select, or filter flags.\n", len(items))
					}
					return nil
				}
			}
			formatData := data
			if flags.csv || flags.plain {
				formatData = outputData
			}
			return printOutputWithFlagsMeta(cmd.OutOrStdout(), formatData, flags, map[string]any{"source": "live"}, map[string]bool{"content-type": true, "display_name": true, "extracted_text": true, "filename": true, "folder_id": true, "id": true, "size": true, "updated_at": true, "url": true})
		},
	}
	cmd.Flags().StringVar(&flagFile, "file", "", "Canvas file ID to fetch (from 'canvas files list')")
	return cmd
}

// canvasFileMeta is the subset of the Canvas /files/{id} response needed to
// decide whether a file is a PDF worth extracting text from.
type canvasFileMeta struct {
	URL         string `json:"url"`
	ContentType string `json:"content-type"`
	Filename    string `json:"filename"`
}

// maybeExtractCanvasFilePDF inspects a fetched Canvas file's metadata and,
// if it looks like a PDF, downloads it and merges its extracted text into
// the JSON object as "extracted_text" (or "extracted_text_error" on
// failure). This is the "canvas files get" analogue of the automatic PDF
// extraction 'courses syllabus' performs on linked attachments — the one
// file the caller explicitly asked for gets its content inlined instead of
// just a download link, without changing when/whether a fetch happens
// (still requires an explicit --file id; never bulk-fetches a directory).
func maybeExtractCanvasFilePDF(ctx context.Context, flags *rootFlags, data json.RawMessage) json.RawMessage {
	var meta canvasFileMeta
	if err := json.Unmarshal(data, &meta); err != nil || meta.URL == "" {
		return data
	}
	if !yale.LooksLikePDF(meta.ContentType, meta.Filename, meta.URL) {
		return data
	}
	auth := canvasAuth()
	fetchCtx, cancel := boundCtx(ctx, flags)
	defer cancel()
	res, err := yale.FetchAndExtractPDF(fetchCtx, auth, true, meta.URL)

	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil {
		return data
	}
	if err != nil {
		obj["extracted_text_error"] = err.Error()
	} else {
		obj["extracted_text"] = res.Text
		obj["extracted_text_truncated"] = res.Truncated
	}
	merged, mErr := json.Marshal(obj)
	if mErr != nil {
		return data
	}
	return merged
}
