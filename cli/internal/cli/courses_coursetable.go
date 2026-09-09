// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's CourseTable GraphQL tools (search_courses,
// get_course, get_course_by_code, compare_courses, get_course_evaluations,
// get_evaluation_ratings, get_syllabus_content — src/tools.ts) to Cobra.

package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

const subjectEligibilityNote = "\n\nIMPORTANT — subject code is NOT major eligibility: filtering or reading by subject " +
	"finds courses listed under that code, but does NOT determine major eligibility. Not all " +
	"CPSC courses count toward the CS major, and courses cross-listed under other subjects may " +
	"also count. Course number digits also do NOT indicate region or category eligibility — only " +
	"course flags (e.g. 'YC HIST Europe') and major requirements text are authoritative. Always " +
	"verify via 'majors requirements' and 'courses get' (flags field)."

const creditsConventionNote = "\n\nNOTE on Yale credits: Lectures and seminars typically carry 1 credit. Discussion " +
	"sections often carry 0 credits, and labs often carry 0.5 credits — but these are " +
	"conventions, not rules. Sections and labs are frequently required companions to a parent " +
	"lecture/seminar and do not count as standalone credits. Always use the credits field as " +
	"the authoritative value; never assume credit value from course type alone."

const courseNumberMigrationNote = "\n\nYale is migrating course numbers from 3-digit to 4-digit (e.g. CPSC 223 → CPSC 2230); " +
	"some courses split into multiple new codes (e.g. CPSC 223 → CPSC 2231 + CPSC 2232). Prefer " +
	"'courses get-by-code' for code-specific lookups — it handles this automatically."

const subjectAliasNote = "\n\nCommon student abbreviations are resolved automatically: 'CS'→'CPSC', 'PHILO'/'PHILOS'→'PHIL', " +
	"'PSYCH'→'PSYC', 'POLISCI'/'POLI'/'POL'/'POLSC'/'POLY'→'PLSC', 'BIO'→'BIOL', 'BIOCHEM'→'MB&B', " +
	"'NEURO'/'NEUROSC'/'NEURSCI'→'NSCI', 'STATS'/'STAT'/'SDS'→'S&DS', 'ANTHRO'→'ANTH', 'ASTRO'→'ASTR'."

const crossSeasonFallbackNote = "\n\nCROSS-SEASON FALLBACK: if the course is not found in the requested season, this command " +
	"automatically searches all seasons and returns the most recent offering(s) with a note " +
	"explaining which season results came from — you do not need to manually iterate seasons. " +
	"syllabus_url returns 'Not available' when no syllabus is posted for that specific offering; " +
	"check prior seasons' offerings via 'courses get-by-code' without --season for a past syllabus."

const deepLinkNote = "\n\nTIP: Link directly to a course in the catalog with: " +
	"https://coursetable.com/catalog?course-modal={season}-{crn}"

const canvasFetchCaution = "\n\nAlways cite the source URL when presenting syllabus content. Do NOT fetch Canvas URLs " +
	"yourself outside this CLI — they require authentication cookies/tokens this CLI manages internally."

func newCoursesCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "courses",
		Short: "Search, inspect, and compare CourseTable courses",
		Long: "Search, look up, and compare Yale courses via CourseTable's public course catalog and " +
			"evaluation data." + deepLinkNote,
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newCoursesSearchCmd(flags))
	cmd.AddCommand(newCoursesGetCmd(flags))
	cmd.AddCommand(newCoursesGetByCodeCmd(flags))
	cmd.AddCommand(newCoursesCompareCmd(flags))
	cmd.AddCommand(newCoursesEvalsCmd(flags))
	cmd.AddCommand(newCoursesEvalRatingsCmd(flags))
	cmd.AddCommand(newCoursesSyllabusCmd(flags))
	return cmd
}

type searchResultView struct {
	CourseID    int      `json:"course_id"`
	Code        string   `json:"code"`
	CRN         *int     `json:"crn"`
	Title       string   `json:"title"`
	Description *string  `json:"description"`
	Credits     *float64 `json:"credits"`
	Rating      *float64 `json:"rating"`
	Workload    *float64 `json:"workload"`
	Professors  []string `json:"professors"`
	Schedule    *string  `json:"schedule"`
	Areas       []string `json:"areas,omitempty"`
	Skills      []string `json:"skills,omitempty"`
	Flags       []string `json:"flags,omitempty"`
}

func newCoursesSearchCmd(flags *rootFlags) *cobra.Command {
	var season, subject, title, description, professor string
	var crn int
	var minRating, maxWorkload, credits float64
	var areas, skills, courseFlags []string
	var limit int

	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search CourseTable courses with filters",
		Long: "Search CourseTable courses with filters. Returns a compact list of matching courses. " +
			"--season is required — use 'seasons list' to get valid values." +
			deepLinkNote + courseNumberMigrationNote + subjectEligibilityNote + creditsConventionNote,
		Example: strings.Trim(`
  yalie-pp-cli courses search --season 202303 --subject CPSC --min-rating 4
  yalie-pp-cli courses search --season 202303 --title "data structures" --json
`, "\n"),
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses search")
			}
			if season == "" || !yale.IsValidSeasonCode(season) {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("--season is required and must be a 6-digit season code (see 'seasons list')"))
			}
			if limit <= 0 || limit > 50 {
				limit = 20
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()

			conditions := []map[string]any{{"season_code": map[string]any{"_eq": season}}}
			if crn > 0 {
				conditions = append(conditions, map[string]any{"listings": map[string]any{"crn": map[string]any{"_eq": crn}}})
			}
			if title != "" {
				conditions = append(conditions, map[string]any{"title": map[string]any{"_ilike": "%" + title + "%"}})
			}
			if description != "" {
				conditions = append(conditions, map[string]any{"description": map[string]any{"_ilike": "%" + description + "%"}})
			}
			if professor != "" {
				conditions = append(conditions, map[string]any{"course_professors": map[string]any{"professor": map[string]any{"name": map[string]any{"_ilike": "%" + professor + "%"}}}})
			}
			if cmd.Flags().Changed("min-rating") {
				conditions = append(conditions, map[string]any{"average_rating": map[string]any{"_gte": minRating}})
			}
			if cmd.Flags().Changed("max-workload") {
				conditions = append(conditions, map[string]any{"average_workload": map[string]any{"_lte": maxWorkload}})
			}
			if cmd.Flags().Changed("credits") {
				conditions = append(conditions, map[string]any{"credits": map[string]any{"_eq": credits}})
			}
			if subject != "" {
				conditions = append(conditions, map[string]any{"listings": map[string]any{"course_code": map[string]any{"_ilike": yale.NormalizeSubject(subject) + " %"}}})
			}
			if len(areas) > 0 {
				conditions = append(conditions, orContainsCondition("areas", areas))
			}
			if len(skills) > 0 {
				conditions = append(conditions, orContainsCondition("skills", skills))
			}
			if len(courseFlags) > 0 {
				conditions = append(conditions, orFlagCondition(courseFlags))
			}

			var data struct {
				Courses []yale.Course `json:"courses"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.SearchQuery, map[string]any{
				"where": yale.BuildWhere(conditions), "limit": limit,
			}, &data); err != nil {
				return apiErr(err)
			}

			results := make([]searchResultView, 0, len(data.Courses))
			for _, c := range data.Courses {
				var sched *string
				if s := c.Schedule(); s != "" {
					sched = &s
				}
				var profs []string
				for _, p := range c.Professors() {
					profs = append(profs, p.Name)
				}
				results = append(results, searchResultView{
					CourseID: c.CourseID, Code: c.PrimaryCode(), CRN: c.PrimaryCRN(),
					Title: c.Title, Description: c.Description, Credits: c.Credits,
					Rating: yale.Round1(c.AverageRating), Workload: yale.Round1(c.AverageWorkload),
					Professors: profs, Schedule: sched, Areas: c.Areas, Skills: c.Skills, Flags: c.Flags(),
				})
			}
			if !wantsHumanTable(cmd.OutOrStdout(), flags) {
				return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": len(results), "courses": results}, flags)
			}
			if len(results) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No matching courses found.")
				return nil
			}
			items := make([]map[string]any, 0, len(results))
			for _, r := range results {
				items = append(items, map[string]any{
					"code": r.Code, "title": r.Title, "credits": r.Credits, "rating": r.Rating, "workload": r.Workload,
				})
			}
			return printAutoTable(cmd.OutOrStdout(), items)
		},
	}
	cmd.Flags().StringVar(&season, "season", "", "Season code e.g. '202303' for Fall 2023 (required; see 'seasons list')")
	cmd.Flags().StringVar(&subject, "subject", "", "Department code e.g. 'CPSC', 'ENGL', 'MATH'"+subjectAliasNote)
	cmd.Flags().IntVar(&crn, "crn", 0, "Exact CRN to look up")
	cmd.Flags().StringVar(&title, "title", "", "Partial case-insensitive title match")
	cmd.Flags().StringVar(&description, "description", "", "Partial case-insensitive match against course description text")
	cmd.Flags().StringVar(&professor, "professor", "", "Partial professor name match")
	cmd.Flags().Float64Var(&minRating, "min-rating", 0, "Minimum average student rating (1-5)")
	cmd.Flags().Float64Var(&maxWorkload, "max-workload", 0, "Maximum workload rating (1-5, lower = easier)")
	cmd.Flags().Float64Var(&credits, "credits", 0, "Exact number of credits e.g. 1, 0.5")
	cmd.Flags().StringSliceVar(&areas, "areas", nil, "Yale distributional areas e.g. Hu,So,Sc")
	cmd.Flags().StringSliceVar(&skills, "skills", nil, "Course skills e.g. QR,WR,L")
	cmd.Flags().StringSliceVar(&courseFlags, "flags", nil, "Filter by flag text (partial match, OR logic), e.g. 'YC CPSC Elective'")
	cmd.Flags().IntVar(&limit, "limit", 20, "Max results (default 20, max 50)")
	return cmd
}

func orContainsCondition(field string, values []string) map[string]any {
	if len(values) == 1 {
		return map[string]any{field: map[string]any{"_contains": []string{values[0]}}}
	}
	var ors []map[string]any
	for _, v := range values {
		ors = append(ors, map[string]any{field: map[string]any{"_contains": []string{v}}})
	}
	return map[string]any{"_or": ors}
}

func orFlagCondition(flags []string) map[string]any {
	if len(flags) == 1 {
		return map[string]any{"course_flags": map[string]any{"flag": map[string]any{"flag_text": map[string]any{"_ilike": "%" + flags[0] + "%"}}}}
	}
	var ors []map[string]any
	for _, f := range flags {
		ors = append(ors, map[string]any{"course_flags": map[string]any{"flag": map[string]any{"flag_text": map[string]any{"_ilike": "%" + f + "%"}}}})
	}
	return map[string]any{"_or": ors}
}

func newCoursesGetCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <course_id>",
		Short: "Get full details for a specific course by course_id",
		Long: "Get full details for a specific course by course_id. Use 'courses search' or " +
			"'courses get-by-code' first to find course_id values. Returns full description, " +
			"professor ratings, meeting schedule with rooms, cross-listings (CRNs), " +
			"distributional areas/skills, flags, requirements, and syllabus URL." +
			deepLinkNote + creditsConventionNote + subjectEligibilityNote +
			"\n\nCross-listings are incidental and do NOT determine eligibility; do not cite them " +
			"as the reason a course counts. Course codes only matter if the major requirements " +
			"text explicitly says they do.",
		Example:     "  yalie-pp-cli courses get 12345",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses get")
			}
			id, err := parsePositiveInt(args[0], "course_id")
			if err != nil {
				return usageErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var data struct {
				CoursesByPk *yale.Course `json:"courses_by_pk"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.GetCourseQuery, map[string]any{"id": id}, &data); err != nil {
				return apiErr(err)
			}
			if data.CoursesByPk == nil {
				return notFoundErr(fmt.Errorf("no course found with ID %d", id))
			}
			c := *data.CoursesByPk
			seasonCode := ""
			if c.Season != nil {
				seasonCode = c.Season.SeasonCode
			}
			var crns []int
			for _, l := range c.Listings {
				crns = append(crns, l.CRN)
			}
			var friends []string
			cookie := courseTableCookie()
			if cookie != "" && seasonCode != "" {
				friends = yale.GetFriendsInCourse(ctx, cookie, seasonCode, crns)
			} else {
				friends = []string{}
			}
			syllabus := "Not available"
			if c.SyllabusURL != nil && *c.SyllabusURL != "" {
				syllabus = *c.SyllabusURL
			}
			var profs []map[string]any
			for _, p := range c.Professors() {
				profs = append(profs, map[string]any{"name": p.Name, "avg_rating": yale.Round1(p.AverageRating)})
			}
			var meetings []map[string]any
			for _, m := range c.CourseMeetings {
				var location any
				if m.Location != nil {
					name := m.Location.Building.Code
					if m.Location.Building.BuildingName != nil {
						name = *m.Location.Building.BuildingName
					}
					if m.Location.Room != nil && *m.Location.Room != "" {
						name = strings.TrimSpace(name + " " + *m.Location.Room)
					}
					location = name
				}
				meetings = append(meetings, map[string]any{
					"days": yale.DecodeDays(m.DaysOfWeek), "time": yale.FormatTime(m.StartTime) + "–" + yale.FormatTime(m.EndTime), "location": location,
				})
			}
			var listings []map[string]any
			for _, l := range c.Listings {
				listings = append(listings, map[string]any{"code": l.CourseCode, "section": l.Section, "crn": l.CRN})
			}
			result := map[string]any{
				"course_id": c.CourseID, "season": yale.SeasonLabel(seasonCode), "listings": listings,
				"title": c.Title, "description": c.Description, "credits": c.Credits, "syllabus_url": syllabus,
				"ratings": map[string]any{
					"overall": yale.Round1(c.AverageRating), "workload": yale.Round1(c.AverageWorkload),
					"professor": yale.Round1(c.AverageProfessorRating), "gut": yale.Round1(c.AverageGutRating),
				},
				"areas": c.Areas, "skills": c.Skills, "flags": c.Flags(), "requirements": c.Requirements,
				"friends_in_course": friends, "professors": profs, "meetings": meetings,
			}
			return printJSONFiltered(cmd.OutOrStdout(), result, flags)
		},
	}
	return cmd
}

func newCoursesGetByCodeCmd(flags *rootFlags) *cobra.Command {
	var season string
	var limit int
	cmd := &cobra.Command{
		Use:   "get-by-code <course_code>",
		Short: "Look up courses by subject + number code within a season",
		Long: "Look up courses by subject + number code within a season. Use this instead of " +
			"'courses search' when you know the specific code, e.g. 'CS 323', 'CPSC 223', " +
			"'MATH 115'." + courseNumberMigrationNote + subjectAliasNote + crossSeasonFallbackNote +
			deepLinkNote,
		Example:     "  yalie-pp-cli courses get-by-code \"CPSC 223\" --season 202303",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses get-by-code")
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			cookie := courseTableCookie()

			resolvedSeason := season
			if resolvedSeason == "" {
				var sd struct {
					Seasons []struct {
						SeasonCode string `json:"season_code"`
					} `json:"seasons"`
				}
				if err := yale.GQL(ctx, cookie, yale.LatestSeasonAtOrBeforeQuery, map[string]any{"max": yale.CurrentSeasonCode(time.Now())}, &sd); err != nil {
					return apiErr(err)
				}
				if len(sd.Seasons) == 0 {
					return notFoundErr(fmt.Errorf("could not determine current season"))
				}
				resolvedSeason = sd.Seasons[0].SeasonCode
			}

			normalized, pattern := normalizeCourseCode(args[0])
			if limit <= 0 || limit > 20 {
				limit = 10
			}

			var data struct {
				Courses []yale.Course `json:"courses"`
			}
			where := map[string]any{"_and": []map[string]any{
				{"season_code": map[string]any{"_eq": resolvedSeason}},
				{"listings": map[string]any{"course_code": map[string]any{"_ilike": pattern}}},
			}}
			if err := yale.GQL(ctx, cookie, yale.GetCourseByCodeQuery, map[string]any{"where": where, "limit": limit}, &data); err != nil {
				return apiErr(err)
			}

			crossSeasonFallback := false
			if len(data.Courses) == 0 {
				fallbackWhere := map[string]any{"listings": map[string]any{"course_code": map[string]any{"_ilike": pattern}}}
				if err := yale.GQL(ctx, cookie, yale.GetCourseByCodeQuery, map[string]any{"where": fallbackWhere, "limit": limit}, &data); err != nil {
					return apiErr(err)
				}
				if len(data.Courses) == 0 {
					if !wantsHumanTable(cmd.OutOrStdout(), flags) {
						return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": 0, "courses": []any{}, "note": fmt.Sprintf("No courses found matching %q in any season.", normalized)}, flags)
					}
					fmt.Fprintf(cmd.OutOrStdout(), "No courses found matching %q in any season.\n", normalized)
					return nil
				}
				crossSeasonFallback = true
			}

			results := make([]map[string]any, 0, len(data.Courses))
			for _, c := range data.Courses {
				seasonCode := ""
				if c.Season != nil {
					seasonCode = c.Season.SeasonCode
				}
				var friends []string
				if cookie != "" {
					var crns []int
					for _, l := range c.Listings {
						crns = append(crns, l.CRN)
					}
					friends = yale.GetFriendsInCourse(ctx, cookie, seasonCode, crns)
				} else {
					friends = []string{}
				}
				syllabus := "Not available"
				if c.SyllabusURL != nil && *c.SyllabusURL != "" {
					syllabus = *c.SyllabusURL
				}
				var sections []map[string]any
				codesSeen := map[string]bool{}
				var codes []string
				for _, l := range c.Listings {
					sections = append(sections, map[string]any{"code": l.CourseCode, "section": l.Section, "crn": l.CRN})
					if !codesSeen[l.CourseCode] {
						codesSeen[l.CourseCode] = true
						codes = append(codes, l.CourseCode)
					}
				}
				var profs []map[string]any
				for _, p := range c.Professors() {
					profs = append(profs, map[string]any{"name": p.Name, "avg_rating": yale.Round1(p.AverageRating)})
				}
				var meetings []map[string]any
				for _, m := range c.CourseMeetings {
					meetings = append(meetings, map[string]any{
						"days": yale.DecodeDays(m.DaysOfWeek), "time": yale.FormatTime(m.StartTime) + "–" + yale.FormatTime(m.EndTime),
					})
				}
				results = append(results, map[string]any{
					"course_id": c.CourseID, "season": yale.SeasonLabel(seasonCode), "codes": codes, "sections": sections,
					"title": c.Title, "credits": c.Credits, "syllabus_url": syllabus,
					"rating": yale.Round1(c.AverageRating), "workload": yale.Round1(c.AverageWorkload),
					"areas": c.Areas, "skills": c.Skills, "friends_in_course": friends, "professors": profs, "meetings": meetings,
				})
			}
			out := map[string]any{"count": len(results), "courses": results}
			if crossSeasonFallback {
				out["note"] = fmt.Sprintf("Not found in season %s — showing most recent offering(s) across all seasons. Use 'seasons list' to find other available seasons.", resolvedSeason)
			}
			return printJSONFiltered(cmd.OutOrStdout(), out, flags)
		},
	}
	cmd.Flags().StringVar(&season, "season", "", "Season code e.g. '202503'. Defaults to the most recent season.")
	cmd.Flags().IntVar(&limit, "limit", 10, "Max results (default 10, max 20)")
	return cmd
}

// normalizeCourseCode mirrors tools.ts's inline normalization in
// get_course_by_code: "cpsc223" -> "CPSC 223", "cs323" -> "CPSC 323", with a
// trailing "%" so "CPSC 223" also matches "CPSC 2230"/"CPSC 2231" (the
// 3-to-4-digit course number migration).
func normalizeCourseCode(raw string) (normalized, pattern string) {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	// Split into a leading subject (letters/&) and trailing number.
	i := 0
	for i < len(upper) && (isLetterOrAmp(rune(upper[i])) || upper[i] == ' ') {
		i++
	}
	subjectPart := strings.TrimSpace(upper[:i])
	numberPart := strings.TrimSpace(upper[i:])
	subject := yale.NormalizeSubject(subjectPart)
	if numberPart != "" {
		normalized = subject + " " + numberPart
	} else {
		normalized = subject
	}
	return normalized, normalized + "%"
}

func isLetterOrAmp(r rune) bool {
	return (r >= 'A' && r <= 'Z') || r == '&'
}

func newCoursesCompareCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compare <course_id> <course_id...>",
		Short: "Compare multiple courses side-by-side",
		Long: "Compare 2-10 courses side-by-side: ratings, workload, gut rating, professor ratings, " +
			"schedule, areas, skills, and syllabus URLs. Use 'courses search' or " +
			"'courses get-by-code' to find course_id values first.",
		Example:     "  yalie-pp-cli courses compare 12345 67890",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses compare")
			}
			if len(args) < 2 {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("at least 2 course IDs are required"))
			}
			ids := make([]int, 0, len(args))
			for _, a := range args {
				id, err := parsePositiveInt(a, "course_id")
				if err != nil {
					return usageErr(err)
				}
				ids = append(ids, id)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var data struct {
				Courses []yale.Course `json:"courses"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.CompareCoursesQuery, map[string]any{"ids": ids}, &data); err != nil {
				return apiErr(err)
			}
			byID := map[int]yale.Course{}
			for _, c := range data.Courses {
				byID[c.CourseID] = c
			}
			results := make([]map[string]any, 0, len(ids))
			for _, id := range ids {
				c, ok := byID[id]
				if !ok {
					continue
				}
				var profs []map[string]any
				for _, p := range c.Professors() {
					profs = append(profs, map[string]any{"name": p.Name, "avg_rating": yale.Round1(p.AverageRating)})
				}
				syllabus := "Not available"
				if c.SyllabusURL != nil && *c.SyllabusURL != "" {
					syllabus = *c.SyllabusURL
				}
				var sched *string
				if s := c.Schedule(); s != "" {
					sched = &s
				}
				results = append(results, map[string]any{
					"course_id": c.CourseID, "code": c.PrimaryCode(), "title": c.Title, "credits": c.Credits,
					"ratings": map[string]any{
						"overall": yale.Round1(c.AverageRating), "workload": yale.Round1(c.AverageWorkload),
						"professor": yale.Round1(c.AverageProfessorRating), "gut": yale.Round1(c.AverageGutRating),
					},
					"areas": c.Areas, "skills": c.Skills, "flags": c.Flags(), "syllabus_url": syllabus,
					"professors": profs, "schedule": sched,
				})
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": len(results), "courses": results}, flags)
		},
	}
	return cmd
}

func newCoursesEvalsCmd(flags *rootFlags) *cobra.Command {
	var maxComments int
	cmd := &cobra.Command{
		Use:   "evals <course_id>",
		Short: "Get student evaluation narratives for a course",
		Long: "Get student evaluation data for a course: AI-generated summaries and top individual " +
			"comments per question. Use course_id from 'courses search' or 'courses get'.",
		Example:     "  yalie-pp-cli courses evals 12345 --max-comments 5",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses evals")
			}
			id, err := parsePositiveInt(args[0], "course_id")
			if err != nil {
				return usageErr(err)
			}
			if maxComments <= 0 || maxComments > 20 {
				maxComments = 5
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var data struct {
				EvaluationNarrativeSummaries []yale.EvalNarrativeSummary `json:"evaluation_narrative_summaries"`
				EvaluationNarratives         []yale.EvalNarrative        `json:"evaluation_narratives"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.GetEvalsQuery, map[string]any{"course_id": id, "limit": maxComments * 6}, &data); err != nil {
				return apiErr(err)
			}
			byQuestion := map[string][]string{}
			for _, n := range data.EvaluationNarratives {
				if len(byQuestion[n.QuestionCode]) < maxComments {
					byQuestion[n.QuestionCode] = append(byQuestion[n.QuestionCode], n.Comment)
				}
			}
			if len(data.EvaluationNarrativeSummaries) == 0 && len(byQuestion) == 0 {
				if !wantsHumanTable(cmd.OutOrStdout(), flags) {
					return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"course_id": id, "evaluations": []any{}}, flags)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "No evaluation data available for this course.")
				return nil
			}
			seen := map[string]bool{}
			var evaluations []map[string]any
			for _, s := range data.EvaluationNarrativeSummaries {
				seen[s.QuestionCode] = true
				evaluations = append(evaluations, map[string]any{
					"question": s.EvaluationQuestion.QuestionText, "code": s.QuestionCode, "top_comments": byQuestion[s.QuestionCode],
				})
			}
			for code, comments := range byQuestion {
				if !seen[code] {
					evaluations = append(evaluations, map[string]any{"question": code, "code": code, "top_comments": comments})
				}
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"course_id": id, "evaluations": evaluations}, flags)
		},
	}
	cmd.Flags().IntVar(&maxComments, "max-comments", 5, "Max comments per question (default 5, max 20)")
	return cmd
}

func newCoursesEvalRatingsCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eval-ratings <course_id>",
		Short: "Get quantitative evaluation rating distributions for a course",
		Long: "Get quantitative (numerical) evaluation rating distributions for a course: per-question " +
			"rating arrays showing how students distributed their responses across the scale. " +
			"Complements 'courses evals', which returns narrative comments.",
		Example:     "  yalie-pp-cli courses eval-ratings 12345",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses eval-ratings")
			}
			id, err := parsePositiveInt(args[0], "course_id")
			if err != nil {
				return usageErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			var data struct {
				EvaluationRatings []yale.EvalRating `json:"evaluation_ratings"`
			}
			if err := yale.GQL(ctx, courseTableCookie(), yale.GetEvalRatingsQuery, map[string]any{"course_id": id}, &data); err != nil {
				return apiErr(err)
			}
			if len(data.EvaluationRatings) == 0 {
				if !wantsHumanTable(cmd.OutOrStdout(), flags) {
					return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"course_id": id, "ratings": []any{}}, flags)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "No quantitative rating data available for this course.")
				return nil
			}
			var ratings []map[string]any
			for _, r := range data.EvaluationRatings {
				ratings = append(ratings, map[string]any{"question": r.EvaluationQuestion.QuestionText, "code": r.QuestionCode, "distribution": r.Rating})
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"course_id": id, "ratings": ratings}, flags)
		},
	}
	return cmd
}

func newCoursesSyllabusCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "syllabus <syllabus_url>",
		Short: "Fetch the full text of a Canvas syllabus for a Yale course",
		Long: "Fetch the full text of a Canvas syllabus for a Yale course. The syllabus_url comes " +
			"from 'courses get' or 'courses get-by-code' (field: syllabus_url). Returns the " +
			"rendered syllabus as plain text, prefixed with the source URL." +
			canvasFetchCaution + crossSeasonFallbackNote +
			"\n\nWhen the syllabus links a PDF (a Canvas-hosted file, or an external .pdf URL) " +
			"the first 2 such attachments are downloaded and their text is extracted and " +
			"appended inline in the returned text under a labeled '--- Attached PDF ---' " +
			"section; a failed attachment degrades to a labeled note instead of failing the " +
			"whole command.",
		Example:     "  yalie-pp-cli courses syllabus https://yale.instructure.com/courses/89687/assignments/syllabus",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "courses syllabus")
			}
			auth, authErr := requireCanvasAuth()
			if authErr != nil {
				return authErr
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			result, err := yale.FetchSyllabus(ctx, auth, args[0])
			if err != nil {
				return apiErr(err)
			}
			var attachments []map[string]any
			for _, a := range result.Attachments {
				entry := map[string]any{"url": a.URL, "label": a.Label, "is_canvas": a.IsCanvas}
				switch {
				case a.FetchError != "":
					entry["extracted"] = false
					entry["error"] = a.FetchError
				case a.Text != "":
					entry["extracted"] = true
					entry["truncated"] = a.Truncated
				}
				attachments = append(attachments, entry)
			}
			// Best-effort local cache so 'worksheet syllabus-search' can search
			// across every already-fetched syllabus at once. Never fails the
			// command — a caching miss just means that command has less to
			// search over, not a syllabus-fetch failure.
			cacheSyllabusLocally(result)
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
				"source_url": result.SourceURL, "text": result.Text, "truncated": result.Truncated, "attachments": attachments,
			}, flags)
		},
	}
	return cmd
}

func parsePositiveInt(s, name string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", name, s)
	}
	return n, nil
}
