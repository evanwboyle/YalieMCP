// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Transcendence command: joins the live degree-audit's unmet requirement
// blocks with the locally-synced course catalog's evaluation ratings — no
// single CourseTable or DegreeWorks API call cross-references these two
// sources. Requires 'sync --resources courses' to have been run for the
// season being searched.

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/store"
	"yalie-pp-cli/internal/yale"
)

type recommendedCourse struct {
	CourseID int      `json:"course_id"`
	Code     string   `json:"code"`
	Title    string   `json:"title"`
	Rating   *float64 `json:"rating"`
	Credits  *float64 `json:"credits"`
}

type blockRecommendation struct {
	Block   string              `json:"block"`
	Status  yale.RuleStatus     `json:"status"`
	Matches []recommendedCourse `json:"top_rated_courses"`
}

// pp:data-source auto
//
// Always makes one live degree-audit fetch (no local audit cache exists to
// fall back to) and joins it against the locally-synced course catalog (no
// live course search is wired up here). Neither --data-source live nor
// --data-source local can be honored on their own, so both are rejected with
// a clear error below; only the default auto strategy is supported.
func newNovelAuditRecommendCmd(flags *rootFlags) *cobra.Command {
	var flagBlock string
	var season string
	var limit int
	var dbPath string

	cmd := &cobra.Command{
		Use:   "recommend",
		Short: "See which of your remaining degree requirements have the best-rated available courses",
		Long: "Join your live degree-audit's unmet (incomplete/in-progress) requirement blocks with " +
			"the locally-synced course catalog's evaluation ratings, ranked by rating. Requires " +
			"AUDIT_COOKIE and a local course mirror populated via 'sync --resources courses " +
			"--season <code>'.\n\n" +
			"Use this to find highly-rated courses for unmet requirements. Do NOT use it for " +
			"general course search; use 'courses search' for that, or 'audit get' for the raw " +
			"requirement list alone." + subjectEligibilityNote +
			"\n\nThis is a keyword-based approximation: it matches each requirement block/rule " +
			"label against synced course titles/descriptions and ranks matches by rating. It is " +
			"NOT an authoritative eligibility determination — always confirm with 'majors " +
			"requirements' and the course's own flags before registering.",
		Example: strings.Trim(`
  yalie-pp-cli audit recommend --block "Humanities & Arts" --season 202603 --json
  yalie-pp-cli audit recommend --season 202603
`, "\n"),
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "auto"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "audit recommend")
			}
			switch flags.dataSource {
			case "local":
				return usageErr(fmt.Errorf("audit recommend has no local degree-audit cache to read from — it always needs a live audit fetch; drop --data-source local (or pass --data-source auto)"))
			case "live":
				return usageErr(fmt.Errorf("audit recommend joins against the locally-synced course catalog, not a live course search — run 'sync --resources courses --season %s' and drop --data-source live (or pass --data-source auto)", season))
			}
			if !yale.IsValidSeasonCode(season) {
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code (courses must be synced for this season first)"))
			}
			if limit <= 0 || limit > 20 {
				limit = 5
			}
			if dbPath == "" {
				dbPath = defaultDBPath("yalie-pp-cli")
			}
			if _, statErr := os.Stat(dbPath); os.IsNotExist(statErr) {
				emptyRows := make([]blockRecommendation, 0)
				if !wantsHumanTable(cmd.OutOrStdout(), flags) {
					return printJSONFiltered(cmd.OutOrStdout(), emptyRows, flags)
				}
				cmd.Printf("no local mirror at %s\nrun: yalie-pp-cli sync --resources courses --season %s --db %s\n", dbPath, season, dbPath)
				return nil
			}
			cookie, err := requireAuditCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()

			audit, err := yale.FetchDegreeAudit(ctx, cookie, "UG", "BA", false)
			if err != nil {
				return apiErr(err)
			}

			db, err := store.OpenReadOnlyContext(ctx, dbPath)
			if err != nil {
				return apiErr(err)
			}
			defer db.Close()

			var recs []blockRecommendation
			for _, block := range audit.RequirementBlocks {
				if block.Status == yale.StatusComplete {
					continue
				}
				if flagBlock != "" && !strings.Contains(strings.ToLower(block.Title), strings.ToLower(flagBlock)) {
					continue
				}
				matches, err := recommendCoursesForBlock(db, season, block, limit)
				if err != nil {
					return apiErr(err)
				}
				recs = append(recs, blockRecommendation{Block: block.Title, Status: block.Status, Matches: matches})
			}
			if recs == nil {
				recs = []blockRecommendation{}
			}
			if !wantsHumanTable(cmd.OutOrStdout(), flags) {
				return printJSONFiltered(cmd.OutOrStdout(), recs, flags)
			}
			if len(recs) == 0 {
				cmd.Println("No unmet requirement blocks matched (or none found).")
				return nil
			}
			for _, r := range recs {
				cmd.Printf("%s (%s):\n", r.Block, r.Status)
				for _, m := range r.Matches {
					cmd.Printf("  %s %s — rating %v\n", m.Code, m.Title, m.Rating)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flagBlock, "block", "", "Filter to requirement blocks whose title contains this substring")
	cmd.Flags().StringVar(&season, "season", "", "Season code to search synced courses in (required; run 'sync' first)")
	cmd.Flags().IntVar(&limit, "limit", 5, "Max recommended courses per block")
	cmd.Flags().StringVar(&dbPath, "db", "", "Local SQLite path (default: platform data dir)")
	return cmd
}

// recommendCoursesForBlock uses the block's own label plus its rules'
// labels as search keywords against the local FTS index of synced courses,
// then ranks the union of matches by average_rating descending.
func recommendCoursesForBlock(db *store.Store, season string, block yale.AuditBlockView, limit int) ([]recommendedCourse, error) {
	keywords := []string{block.Title}
	for _, r := range block.Rules {
		keywords = append(keywords, r.Label)
	}
	seen := map[int]recommendedCourse{}
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		rows, err := db.Search(kw, 25, "course")
		if err != nil {
			continue
		}
		for _, row := range rows {
			var c struct {
				CourseID      int      `json:"course_id"`
				SeasonCode    string   `json:"season_code"`
				Code          string   `json:"code"`
				Title         string   `json:"title"`
				AverageRating *float64 `json:"average_rating"`
				Credits       *float64 `json:"credits"`
			}
			if json.Unmarshal(row, &c) != nil || c.SeasonCode != season {
				continue
			}
			if _, ok := seen[c.CourseID]; !ok {
				seen[c.CourseID] = recommendedCourse{CourseID: c.CourseID, Code: c.Code, Title: c.Title, Rating: c.AverageRating, Credits: c.Credits}
			}
		}
	}
	out := make([]recommendedCourse, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := ratingOrZero(out[i].Rating), ratingOrZero(out[j].Rating)
		return ri > rj
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func ratingOrZero(r *float64) float64 {
	if r == nil {
		return 0
	}
	return *r
}
