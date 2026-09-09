// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

// The GraphQL query strings below are ported verbatim (field-for-field) from
// YalieMCP's src/tools.ts so the generated CLI's requests are
// byte-for-byte compatible with the original, already-working MCP server.

const SeasonsQuery = `query { seasons(order_by: { season_code: desc }) { season_code } }`

const LatestSeasonAtOrBeforeQuery = `query ($max: String!) { seasons(where: { season_code: { _lte: $max } }, order_by: { season_code: desc }, limit: 1) { season_code } }`

const SearchQuery = `
  query SearchCourses($where: courses_bool_exp!, $limit: Int!) {
    courses(where: $where, limit: $limit) {
      course_id title description credits average_rating average_workload areas skills colsem fysem
      listings(limit: 1, order_by: { crn: asc }) { course_code crn }
      course_professors { professor { name } }
      course_meetings { days_of_week start_time end_time }
      course_flags { flag { flag_text } }
    }
  }
`

// SyncSearchQuery is SearchQuery plus syllabus_url, used only by the local
// sync command so the offline mirror can serve 'worksheet syllabus-search'
// (which needs each course's syllabus_url to look up cached syllabus text).
const SyncSearchQuery = `
  query SyncCourses($where: courses_bool_exp!, $limit: Int!) {
    courses(where: $where, limit: $limit) {
      course_id title description credits average_rating average_workload areas skills colsem fysem
      syllabus_url
      listings(order_by: { crn: asc }) { course_code crn }
      course_professors { professor { name } }
      course_meetings { days_of_week start_time end_time }
      course_flags { flag { flag_text } }
    }
  }
`

const GetCourseQuery = `
  query GetCourse($id: Int!) {
    courses_by_pk(course_id: $id) {
      course_id title description credits average_rating average_workload
      average_professor_rating average_gut_rating areas skills colsem fysem requirements
      syllabus_url
      season { season_code }
      listings { course_code section season_code crn }
      course_professors { professor { name average_rating } }
      course_meetings {
        days_of_week start_time end_time
        location { room building { code building_name } }
      }
      course_flags { flag { flag_text } }
    }
  }
`

const GetEvalsQuery = `
  query GetEvals($course_id: Int!, $limit: Int!) {
    evaluation_narrative_summaries(where: { course_id: { _eq: $course_id } }) {
      question_code summary
      evaluation_question { question_text }
    }
    evaluation_narratives(
      where: { course_id: { _eq: $course_id } }
      order_by: { comment_compound: desc }
      limit: $limit
    ) { question_code comment }
  }
`

const GetCourseByCodeQuery = `
  query GetCourseByCode($where: courses_bool_exp!, $limit: Int!) {
    courses(where: $where, limit: $limit, order_by: [{ season_code: desc }, { listings_aggregate: { count: desc } }]) {
      course_id title credits average_rating average_workload areas skills colsem fysem
      syllabus_url
      season { season_code }
      listings(order_by: { crn: asc }) { course_code section crn }
      course_professors { professor { name average_rating } }
      course_meetings {
        days_of_week start_time end_time
        location { room building { code building_name } }
      }
    }
  }
`

const SearchProfessorsQuery = `
  query SearchProfessors($name: String!, $limit: Int!) {
    professors(
      where: { name: { _ilike: $name } }
      limit: $limit
      order_by: { average_rating: desc_nulls_last }
    ) {
      professor_id name average_rating
      course_professors(order_by: { course: { season_code: desc } }, limit: 8) {
        course {
          course_id title
          season { season_code }
          listings(limit: 1, order_by: { crn: asc }) { course_code }
        }
      }
    }
  }
`

const CompareCoursesQuery = `
  query CompareCourses($ids: [Int!]!) {
    courses(where: { course_id: { _in: $ids } }) {
      course_id title credits
      average_rating average_workload average_gut_rating average_professor_rating
      areas skills colsem fysem
      syllabus_url
      listings(limit: 1, order_by: { crn: asc }) { course_code }
      course_professors { professor { name average_rating } }
      course_meetings { days_of_week start_time end_time }
    }
  }
`

const GetWorksheetCoursesQuery = `
  query GetWorksheetCourses($crns: [Int!]!) {
    courses(where: { listings: { crn: { _in: $crns } } }) {
      title credits season_code
      listings { crn }
    }
  }
`

const GetEvalRatingsQuery = `
  query GetEvalRatings($course_id: Int!) {
    evaluation_ratings(where: { course_id: { _eq: $course_id } }) {
      question_code
      rating
      evaluation_question { question_text }
    }
  }
`
