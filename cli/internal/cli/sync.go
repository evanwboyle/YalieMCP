// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written Priority-0 data layer: syncs CourseTable courses/evaluations
// and scraped catalog majors/certificates into the local SQLite mirror so
// 'courses search' and the transcendence commands (audit recommend,
// worksheet syllabus-search) can work offline / cross-source.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/store"
	"yalie-pp-cli/internal/yale"
)

func newSyncCmd(flags *rootFlags) *cobra.Command {
	var resources []string
	var season string
	var dbPath string

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Populate the local cache for offline search and cross-source commands",
		Long: "Sync CourseTable courses/evaluations for a season, plus the scraped catalog's " +
			"majors/certificates, into a local SQLite mirror. Populating the mirror is what makes " +
			"'courses search' work offline and enables the cross-source transcendence commands " +
			"('audit recommend', 'worksheet syllabus-search'). Public CourseTable data needs no " +
			"auth; COURSETABLE_COOKIE is only used to enrich account-scoped fields when present.",
		Example: strings.Trim(`
  yalie-pp-cli sync --resources courses,evaluations --season 202603
  yalie-pp-cli sync --resources majors,certificates
`, "\n"),
		Annotations: map[string]string{"mcp:read-only": "false", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "sync")
			}
			if len(resources) == 0 {
				return usageErr(fmt.Errorf("--resources is required, e.g. --resources courses,evaluations"))
			}
			needsSeason := containsStr(resources, "courses") || containsStr(resources, "evaluations")
			if needsSeason && !yale.IsValidSeasonCode(season) {
				return usageErr(fmt.Errorf("--season is required (6-digit season code) when syncing courses or evaluations"))
			}
			if dbPath == "" {
				dbPath = defaultDBPath("yalie-pp-cli")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			db, err := store.OpenWithContext(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("opening local store: %w", err)
			}
			defer db.Close()

			report := map[string]any{}
			for _, r := range resources {
				switch strings.TrimSpace(r) {
				case "courses":
					n, err := syncCourses(ctx, db, season)
					if err != nil {
						return apiErr(err)
					}
					report["courses"] = n
				case "evaluations":
					n, err := syncEvaluations(ctx, db, season)
					if err != nil {
						return apiErr(err)
					}
					report["evaluations"] = n
				case "majors":
					n, err := syncMajors(ctx, db)
					if err != nil {
						return apiErr(err)
					}
					report["majors"] = n
				case "certificates":
					n, err := syncCertificates(ctx, db)
					if err != nil {
						return apiErr(err)
					}
					report["certificates"] = n
				default:
					return usageErr(fmt.Errorf("unknown resource %q; valid: courses, evaluations, majors, certificates", r))
				}
			}
			report["db_path"] = dbPath
			return printJSONFiltered(cmd.OutOrStdout(), report, flags)
		},
	}
	cmd.Flags().StringSliceVar(&resources, "resources", nil, "Resources to sync: courses, evaluations, majors, certificates")
	cmd.Flags().StringVar(&season, "season", "", "Season code e.g. '202603' (required for courses/evaluations)")
	cmd.Flags().StringVar(&dbPath, "db", "", "Local SQLite path (default: platform data dir)")
	return cmd
}

func containsStr(list []string, target string) bool {
	for _, s := range list {
		if strings.TrimSpace(s) == target {
			return true
		}
	}
	return false
}

const syncCourseLimit = 3000

func syncCourses(ctx context.Context, db *store.Store, season string) (int, error) {
	var data struct {
		Courses []yale.Course `json:"courses"`
	}
	where := map[string]any{"season_code": map[string]any{"_eq": season}}
	if err := yale.GQL(ctx, courseTableCookie(), yale.SyncSearchQuery, map[string]any{"where": where, "limit": syncCourseLimit}, &data); err != nil {
		return 0, err
	}
	for _, c := range data.Courses {
		raw, err := json.Marshal(map[string]any{
			"course_id": c.CourseID, "season_code": season, "code": c.PrimaryCode(),
			"title": c.Title, "description": c.Description, "credits": c.Credits,
			"average_rating": c.AverageRating, "average_workload": c.AverageWorkload,
			"areas": c.Areas, "skills": c.Skills, "flags": c.Flags(),
			"syllabus_url": c.SyllabusURL,
			"listings":     c.Listings,
		})
		if err != nil {
			return 0, err
		}
		if err := db.Upsert("course", strconv.Itoa(c.CourseID), raw); err != nil {
			return 0, err
		}
	}
	return len(data.Courses), nil
}

func syncEvaluations(ctx context.Context, db *store.Store, season string) (int, error) {
	ids, err := listCachedCourseIDsForSeason(db, season)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, id := range ids {
		var data struct {
			EvaluationRatings []yale.EvalRating `json:"evaluation_ratings"`
		}
		if err := yale.GQL(ctx, courseTableCookie(), yale.GetEvalRatingsQuery, map[string]any{"course_id": id}, &data); err != nil {
			continue // best-effort: some courses have no eval data
		}
		if len(data.EvaluationRatings) == 0 {
			continue
		}
		raw, err := json.Marshal(map[string]any{"course_id": id, "ratings": data.EvaluationRatings})
		if err != nil {
			return count, err
		}
		if err := db.Upsert("evaluation", strconv.Itoa(id), raw); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func listCachedCourseIDsForSeason(db *store.Store, season string) ([]int, error) {
	rows, err := db.List("course", 0)
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, row := range rows {
		var c struct {
			CourseID   int    `json:"course_id"`
			SeasonCode string `json:"season_code"`
		}
		if json.Unmarshal(row, &c) == nil && c.SeasonCode == season {
			ids = append(ids, c.CourseID)
		}
	}
	return ids, nil
}

func syncMajors(ctx context.Context, db *store.Store) (int, error) {
	majors, err := listMajors(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range majors {
		raw, err := json.Marshal(m)
		if err != nil {
			return 0, err
		}
		if err := db.Upsert("major", m.Slug, raw); err != nil {
			return 0, err
		}
	}
	return len(majors), nil
}

func syncCertificates(ctx context.Context, db *store.Store) (int, error) {
	html, err := yale.FetchRawHTML(ctx, yale.CatalogBase+"/ycps/programs_certificates/")
	if err != nil {
		return 0, err
	}
	certs := yale.ExtractCertificateLinks(html)
	for _, c := range certs {
		raw, err := json.Marshal(c)
		if err != nil {
			return 0, err
		}
		if err := db.Upsert("certificate", c.Slug, raw); err != nil {
			return 0, err
		}
	}
	return len(certs), nil
}
