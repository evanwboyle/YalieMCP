// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Transcendence command: local full-text search over syllabus text already
// fetched (via 'courses syllabus') for every course in a worksheet at once —
// no batch syllabus-search endpoint exists anywhere.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/store"
	"yalie-pp-cli/internal/yale"
)

type syllabusSearchHit struct {
	CourseCode string `json:"course_code"`
	CRN        int    `json:"crn"`
	SourceURL  string `json:"source_url"`
	Snippet    string `json:"snippet"`
}

// pp:data-source auto
//
// Always makes one live worksheet fetch (worksheet membership is never
// mirrored locally) to learn which courses to search, then searches each
// course's already-fetched syllabus text in the local cache (no live
// syllabus fetch is wired up here). Neither --data-source live nor
// --data-source local can be honored on their own, so both are rejected with
// a clear error below; only the default auto strategy is supported.
func newNovelWorksheetSyllabusSearchCmd(flags *rootFlags) *cobra.Command {
	var flagSeason string
	var worksheetNumber int
	var dbPath string

	cmd := &cobra.Command{
		Use:   "syllabus-search <keyword>",
		Short: "Search a keyword across every already-fetched syllabus for a worksheet",
		Long: "Search for a keyword or policy (e.g. 'no laptops', 'final exam') across every " +
			"syllabus already fetched via 'courses syllabus' for your worksheet courses at once. " +
			"A course's syllabus must have been fetched at least once (with 'courses syllabus') " +
			"before it can be searched here — the syllabus text itself is searched from the local " +
			"cache only; this command does not fetch syllabus content itself, though it does make " +
			"one live call to look up which courses are currently on your worksheet. Requires " +
			"COURSETABLE_COOKIE.\n\n" +
			"Use this over repeated single-course 'courses syllabus' calls when the task spans a " +
			"whole worksheet. Do NOT use it for a single course's full syllabus text; use " +
			"'courses syllabus' for that." + canvasFetchCaution,
		Example:     "  yalie-pp-cli worksheet syllabus-search \"final exam\" --season 202603",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "auto"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "worksheet syllabus-search")
			}
			switch flags.dataSource {
			case "local":
				return usageErr(fmt.Errorf("worksheet syllabus-search has no local worksheet cache to read from — it always needs a live worksheet fetch to know which courses to search; drop --data-source local (or pass --data-source auto)"))
			case "live":
				return usageErr(fmt.Errorf("worksheet syllabus-search only searches already-fetched syllabus text in the local cache, not a live syllabus fetch — run 'courses syllabus' for each course first and drop --data-source live (or pass --data-source auto)"))
			}
			if len(args) == 0 {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("keyword is required"))
			}
			if !yale.IsValidSeasonCode(flagSeason) {
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code"))
			}
			keyword := strings.ToLower(args[0])
			if dbPath == "" {
				dbPath = defaultDBPath("yalie-pp-cli")
			}
			if _, statErr := os.Stat(dbPath); os.IsNotExist(statErr) {
				fmt.Fprintf(cmd.ErrOrStderr(), "no local mirror at %s\nrun: yalie-pp-cli sync --resources courses --season %s --db %s, then fetch syllabi with 'courses syllabus'\n", dbPath, flagSeason, dbPath)
				if !wantsHumanTable(cmd.OutOrStdout(), flags) {
					return printJSONFiltered(cmd.OutOrStdout(), make([]syllabusSearchHit, 0), flags)
				}
				return nil
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()

			raw, err := yale.GetWorksheetsRaw(ctx, cookie)
			if err != nil {
				return apiErr(err)
			}
			seasonWorksheets, ok := raw[flagSeason]
			wsKey := strconv.Itoa(worksheetNumber)
			var crns []int
			if ok {
				if ws, ok := seasonWorksheets[wsKey]; ok {
					for _, c := range ws.Courses {
						crns = append(crns, c.CRN)
					}
				}
			}
			hits := make([]syllabusSearchHit, 0)
			if len(crns) == 0 {
				return printJSONFiltered(cmd.OutOrStdout(), hits, flags)
			}

			db, err := store.OpenReadOnlyContext(ctx, dbPath)
			if err != nil {
				return apiErr(err)
			}
			defer db.Close()

			crnToCode, crnToSyllabus := crnLookupsForSeason(db, flagSeason, crns)
			for _, crn := range crns {
				syllabusURL, ok := crnToSyllabus[crn]
				if !ok || syllabusURL == "" {
					continue
				}
				cached, err := db.Get("syllabus", syllabusURL)
				if err != nil {
					continue
				}
				var s struct {
					Text string `json:"text"`
				}
				if json.Unmarshal(cached, &s) != nil {
					continue
				}
				lower := strings.ToLower(s.Text)
				idx := strings.Index(lower, keyword)
				if idx == -1 {
					continue
				}
				start := idx - 60
				if start < 0 {
					start = 0
				}
				end := idx + len(keyword) + 60
				if end > len(s.Text) {
					end = len(s.Text)
				}
				hits = append(hits, syllabusSearchHit{
					CourseCode: crnToCode[crn], CRN: crn, SourceURL: syllabusURL, Snippet: "…" + s.Text[start:end] + "…",
				})
			}
			if !wantsHumanTable(cmd.OutOrStdout(), flags) {
				return printJSONFiltered(cmd.OutOrStdout(), hits, flags)
			}
			if len(hits) == 0 {
				cmd.Println("No matches found in cached syllabi for this worksheet.")
				return nil
			}
			for _, h := range hits {
				cmd.Printf("%s: %s\n", h.CourseCode, h.Snippet)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flagSeason, "season", "", "Season code e.g. '202603'")
	cmd.Flags().IntVar(&worksheetNumber, "worksheet-number", 0, "Worksheet number (0 = default)")
	cmd.Flags().StringVar(&dbPath, "db", "", "Local SQLite path (default: platform data dir)")
	return cmd
}

// crnLookupsForSeason scans the locally-synced "course" resources for
// season, returning crn->course_code and crn->syllabus_url maps. Requires
// 'sync --resources courses --season <code>' to have been run; a course
// missing from the local mirror simply has no lookup entry.
func crnLookupsForSeason(db *store.Store, season string, crns []int) (map[int]string, map[int]string) {
	wanted := map[int]bool{}
	for _, c := range crns {
		wanted[c] = true
	}
	codeOf := map[int]string{}
	syllabusOf := map[int]string{}
	rows, err := db.List("course", 0)
	if err != nil {
		return codeOf, syllabusOf
	}
	for _, row := range rows {
		var c struct {
			SeasonCode  string  `json:"season_code"`
			Code        string  `json:"code"`
			SyllabusURL *string `json:"syllabus_url"`
			Listings    []struct {
				CRN int `json:"crn"`
			} `json:"listings"`
		}
		if json.Unmarshal(row, &c) != nil || c.SeasonCode != season {
			continue
		}
		for _, l := range c.Listings {
			if wanted[l.CRN] {
				codeOf[l.CRN] = c.Code
				if c.SyllabusURL != nil {
					syllabusOf[l.CRN] = *c.SyllabusURL
				}
			}
		}
	}
	return codeOf, syllabusOf
}
