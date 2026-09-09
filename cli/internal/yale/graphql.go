// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

// Package yale hand-ports the CourseTable GraphQL/REST clients, the Yale
// Catalog HTML scraper, and the Degree Audit two-step fetch+parse logic from
// the original YalieMCP TypeScript server (src/tools.ts in the YalieMCP
// repo) into Go. Every query string, parsing rule, and domain caveat here is
// a direct port — not a re-derivation — of that proven, already-working
// source, per the printing-press build brief for yalie-pp-cli.
package yale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"yalie-pp-cli/internal/cliutil"
)

// GraphQLURL is CourseTable's single Hasura GraphQL endpoint. Public/anonymous
// for catalog and evaluation queries; account-scoped queries (worksheets,
// wishlist, friends) require a CAS-derived session cookie.
const GraphQLURL = "https://api.coursetable.com/ferry/v1/graphql"

// APIBase is CourseTable's plain REST API base.
const APIBase = "https://api.coursetable.com"

// CatalogBase is the public, unauthenticated Yale course catalog.
const CatalogBase = "https://catalog.yale.edu"

// courseTableLimiter paces outbound GraphQL requests to api.coursetable.com
// so a burst of queries backs off on a 429 instead of hammering CourseTable.
var courseTableLimiter = cliutil.NewAdaptiveLimiterAuto(4.0)

type graphQLError struct {
	Message    string `json:"message"`
	Extensions struct {
		Code string `json:"code"`
	} `json:"extensions"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []graphQLError  `json:"errors"`
}

// GQL runs a GraphQL query/mutation against CourseTable. cookie may be empty
// for the public, anonymous-reachable queries (seasons, course search,
// evaluations); account-scoped queries require a real session cookie.
// Ported verbatim from the TS gql<T>() helper in tools.ts, including its
// error-message scrubbing (raw GraphQL errors are never forwarded — they can
// leak schema details).
func GQL(ctx context.Context, cookie string, query string, variables map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return fmt.Errorf("encoding GraphQL request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, GraphQLURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building GraphQL request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://coursetable.com")
	req.Header.Set("User-Agent", "yalie-pp-cli/1.0")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	if err := courseTableLimiter.Wait(ctx); err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("CourseTable GraphQL request failed: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		courseTableLimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(resp)
		resp.Body.Close()
		return &cliutil.RateLimitError{URL: req.URL.String(), RetryAfter: retryAfter}
	}
	courseTableLimiter.OnSuccess()
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading CourseTable GraphQL response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == 405 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			return fmt.Errorf("authentication required (HTTP %d); your CourseTable session cookie may have expired — re-copy document.cookie from a logged-in coursetable.com tab", resp.StatusCode)
		}
		return fmt.Errorf("HTTP %d from CourseTable GraphQL", resp.StatusCode)
	}

	var parsed graphQLResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("parsing CourseTable GraphQL response: %w", err)
	}
	if len(parsed.Errors) > 0 {
		for _, e := range parsed.Errors {
			if strings.Contains(e.Message, "not found in type") {
				return fmt.Errorf("session expired or invalid — your CourseTable cookie no longer authenticates you; re-authenticate to refresh it")
			}
		}
		// Don't forward raw GraphQL error messages verbatim — they may leak schema details.
		return fmt.Errorf("course data request failed")
	}
	if len(parsed.Data) == 0 {
		return fmt.Errorf("empty response from CourseTable GraphQL")
	}
	if out != nil {
		if err := json.Unmarshal(parsed.Data, out); err != nil {
			return fmt.Errorf("decoding CourseTable GraphQL data: %w", err)
		}
	}
	return nil
}

// SubjectAliases maps common student abbreviations to official Yale subject
// codes, ported verbatim from tools.ts's SUBJECT_ALIASES map. Yale students
// often shorten subjects (e.g. "CS" for "CPSC", "PHILO" for "PHIL").
var SubjectAliases = map[string]string{
	"CS": "CPSC", "COMPSCI": "CPSC", "COMP": "CPSC",
	"PHILO": "PHIL", "PHILOS": "PHIL",
	"PSYCH": "PSYC",
	"POLY":  "PLSC", "POLISCI": "PLSC", "POLI": "PLSC", "POL": "PLSC", "POLSC": "PLSC",
	"BIO":     "BIOL",
	"BIOCHEM": "MB&B",
	"NEURO":   "NSCI", "NEUROSC": "NSCI", "NEURSCI": "NSCI",
	"STATS": "S&DS", "STAT": "S&DS", "SDS": "S&DS",
	"ANTHRO": "ANTH",
	"ASTRO":  "ASTR",
	"ECON":   "ECON",
	"ENGL":   "ENGL",
	"HIST":   "HIST",
	"MATH":   "MATH",
	"CHEM":   "CHEM",
	"PHYS":   "PHYS",
}

// NormalizeSubject expands a user-supplied subject abbreviation to the
// official Yale code, per SubjectAliases. Ported from tools.ts normalizeSubject().
func NormalizeSubject(subject string) string {
	upper := strings.ToUpper(strings.TrimSpace(subject))
	if v, ok := SubjectAliases[upper]; ok {
		return v
	}
	return upper
}

// SeasonLabel converts a 6-digit season code (e.g. "202303") into a human
// label (e.g. "Fall 2023"). Ported from tools.ts seasonLabel().
func SeasonLabel(code string) string {
	if len(code) != 6 {
		return code
	}
	year := code[:4]
	term := code[4:]
	label := term
	switch term {
	case "01":
		label = "Spring"
	case "02":
		label = "Summer"
	case "03":
		label = "Fall"
	}
	return fmt.Sprintf("%s %s", label, year)
}

// CurrentSeasonCode returns the current season code based on today's date,
// e.g. "202601" for Spring 2026. Ported from tools.ts currentSeasonCode().
func CurrentSeasonCode(now time.Time) string {
	year := now.Year()
	month := int(now.Month())
	term := "03"
	switch {
	case month <= 5:
		term = "01"
	case month <= 7:
		term = "02"
	}
	return fmt.Sprintf("%d%s", year, term)
}

var seasonCodeRE = regexp.MustCompile(`^\d{6}$`)

// IsValidSeasonCode reports whether code looks like a 6-digit season code.
func IsValidSeasonCode(code string) bool {
	return seasonCodeRE.MatchString(code)
}

// DecodeDays turns a day-of-week bitmask (bit 0 = Monday ... bit 6 = Sunday)
// into a slash-joined day list, e.g. "Mon/Wed/Fri". Ported from tools.ts
// decodeDays().
func DecodeDays(bits int64) string {
	days := []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
	var out []string
	for i, d := range days {
		if bits&(1<<uint(i)) != 0 {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return "TBA"
	}
	return strings.Join(out, "/")
}

// FormatTime converts a 24-hour "H:MM" or "HH:MM" string into 12-hour
// clock time with AM/PM, e.g. "13:30" -> "1:30 PM". Ported from tools.ts
// formatTime().
func FormatTime(t string) string {
	parts := strings.SplitN(t, ":", 2)
	if len(parts) != 2 {
		return t
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return t
	}
	suffix := "AM"
	if h >= 12 {
		suffix = "PM"
	}
	h12 := h % 12
	if h12 == 0 {
		h12 = 12
	}
	return fmt.Sprintf("%d:%02d %s", h12, m, suffix)
}

// Round1 rounds a float to one decimal place, matching tools.ts round1(). A
// nil input (no rating data) returns nil.
func Round1(n *float64) *float64 {
	if n == nil {
		return nil
	}
	r := float64(int((*n)*10+0.5)) / 10
	return &r
}

// BuildWhere combines a list of GraphQL bool_exp condition maps with an
// implicit AND, dropping empty conditions. A single non-empty condition is
// returned unwrapped, matching tools.ts buildWhere() so generated queries are
// byte-for-byte compatible with the original MCP's filter shapes.
func BuildWhere(conditions []map[string]any) map[string]any {
	var truthy []map[string]any
	for _, c := range conditions {
		if len(c) > 0 {
			truthy = append(truthy, c)
		}
	}
	switch len(truthy) {
	case 0:
		return map[string]any{}
	case 1:
		return truthy[0]
	default:
		return map[string]any{"_and": truthy}
	}
}
