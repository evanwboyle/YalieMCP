// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

// Listing is one CRN/section listing for a course.
type Listing struct {
	CourseCode string `json:"course_code"`
	Section    string `json:"section,omitempty"`
	SeasonCode string `json:"season_code,omitempty"`
	CRN        int    `json:"crn"`
}

// ProfessorRef names a professor and their average rating.
type ProfessorRef struct {
	Name          string   `json:"name"`
	AverageRating *float64 `json:"average_rating"`
}

type courseProfessor struct {
	Professor ProfessorRef `json:"professor"`
}

// Location is a course meeting's room/building.
type Location struct {
	Room     *string `json:"room"`
	Building struct {
		Code         string  `json:"code"`
		BuildingName *string `json:"building_name"`
	} `json:"building"`
}

// Meeting is one course meeting time.
type Meeting struct {
	DaysOfWeek int64     `json:"days_of_week"`
	StartTime  string    `json:"start_time"`
	EndTime    string    `json:"end_time"`
	Location   *Location `json:"location"`
}

type courseFlag struct {
	Flag struct {
		FlagText string `json:"flag_text"`
	} `json:"flag"`
}

// Course is the GraphQL courses row shape, a superset of every field used
// across search/get/get-by-code/compare, ported from tools.ts's per-query
// TypeScript row types.
type Course struct {
	CourseID                int               `json:"course_id"`
	Title                   string            `json:"title"`
	Description             *string           `json:"description"`
	Credits                 *float64          `json:"credits"`
	AverageRating           *float64          `json:"average_rating"`
	AverageWorkload         *float64          `json:"average_workload"`
	AverageProfessorRating  *float64          `json:"average_professor_rating"`
	AverageGutRating        *float64          `json:"average_gut_rating"`
	Areas                   []string          `json:"areas"`
	Skills                  []string          `json:"skills"`
	Colsem                  bool              `json:"colsem"`
	Fysem                   bool              `json:"fysem"`
	Requirements            *string           `json:"requirements"`
	SyllabusURL             *string           `json:"syllabus_url"`
	Season                  *struct{ SeasonCode string `json:"season_code"` } `json:"season"`
	Listings                []Listing         `json:"listings"`
	CourseProfessors        []courseProfessor `json:"course_professors"`
	CourseMeetings          []Meeting         `json:"course_meetings"`
	CourseFlags             []courseFlag      `json:"course_flags"`
}

// Professors flattens CourseProfessors into ProfessorRef values.
func (c Course) Professors() []ProfessorRef {
	out := make([]ProfessorRef, 0, len(c.CourseProfessors))
	for _, p := range c.CourseProfessors {
		out = append(out, p.Professor)
	}
	return out
}

// Flags flattens colsem/fysem plus course_flags into a plain string list,
// matching tools.ts's inline flag-flattening in search_courses/get_course.
func (c Course) Flags() []string {
	var out []string
	if c.Colsem {
		out = append(out, "ColSem")
	}
	if c.Fysem {
		out = append(out, "FrYrSem")
	}
	for _, f := range c.CourseFlags {
		out = append(out, f.Flag.FlagText)
	}
	return out
}

// Schedule renders course_meetings as "Mon/Wed 1:30 PM–2:20 PM, ..." joined
// by commas, matching tools.ts's inline schedule formatting.
func (c Course) Schedule() string {
	var parts []string
	for _, m := range c.CourseMeetings {
		parts = append(parts, DecodeDays(m.DaysOfWeek)+" "+FormatTime(m.StartTime)+"–"+FormatTime(m.EndTime))
	}
	if len(parts) == 0 {
		return ""
	}
	joined := ""
	for i, p := range parts {
		if i > 0 {
			joined += ", "
		}
		joined += p
	}
	return joined
}

// PrimaryCode returns the first listing's course_code, or "—" (em dash)
// when there is no listing, matching tools.ts's `c.listings[0]?.course_code ?? "—"`.
func (c Course) PrimaryCode() string {
	if len(c.Listings) == 0 {
		return "—"
	}
	return c.Listings[0].CourseCode
}

// PrimaryCRN returns the first listing's CRN, or nil.
func (c Course) PrimaryCRN() *int {
	if len(c.Listings) == 0 {
		return nil
	}
	crn := c.Listings[0].CRN
	return &crn
}

// EvalNarrativeSummary is one evaluation_narrative_summaries row.
type EvalNarrativeSummary struct {
	QuestionCode        string `json:"question_code"`
	Summary             string `json:"summary"`
	EvaluationQuestion  struct {
		QuestionText string `json:"question_text"`
	} `json:"evaluation_question"`
}

// EvalNarrative is one evaluation_narratives row.
type EvalNarrative struct {
	QuestionCode string `json:"question_code"`
	Comment      string `json:"comment"`
}

// EvalRating is one evaluation_ratings row. Rating is left as raw JSON
// because CourseTable's distribution shape varies by question type.
type EvalRating struct {
	QuestionCode       string `json:"question_code"`
	Rating             any    `json:"rating"`
	EvaluationQuestion struct {
		QuestionText string `json:"question_text"`
	} `json:"evaluation_question"`
}

// Professor is a professors table row plus recent course_professors.
type Professor struct {
	ProfessorID      int      `json:"professor_id"`
	Name             string   `json:"name"`
	AverageRating    *float64 `json:"average_rating"`
	CourseProfessors []struct {
		Course struct {
			CourseID int    `json:"course_id"`
			Title    string `json:"title"`
			Season   struct {
				SeasonCode string `json:"season_code"`
			} `json:"season"`
			Listings []struct {
				CourseCode string `json:"course_code"`
			} `json:"listings"`
		} `json:"course"`
	} `json:"course_professors"`
}
