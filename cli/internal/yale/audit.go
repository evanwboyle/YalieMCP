// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"yalie-pp-cli/internal/cliutil"
)

const auditBase = "https://degreeaudit.yale.edu"

// auditLimiter paces outbound requests to degreeaudit.yale.edu so a burst of
// audit fetches backs off on a 429 instead of hammering Yale's backend.
var auditLimiter = cliutil.NewAdaptiveLimiterAuto(2.0)

// ATTRIBUTE_LABELS maps DegreeWorks attribute codes to human labels for
// Yale's distributional requirements, ported verbatim from tools.ts
// ATTRIBUTE_LABELS.
var AttributeLabels = map[string]string{
	"YCQR": "Quantitative Reasoning",
	"YCWR": "Writing",
	"YCSH": "Science",
	"YCSO": "Social Science",
	"YCHU": "Humanities & Arts",
	"YCLA": "Language",
	"YCQE": "Quantitative Reasoning Equivalent",
	"YCSC": "Science (no lab)",
}

// DecodeAttributes maps a list of attribute codes through AttributeLabels,
// dropping any code with no known label. Ported from tools.ts decodeAttributes().
func DecodeAttributes(codes []string) []string {
	out := make([]string, 0, len(codes))
	for _, c := range codes {
		if label, ok := AttributeLabels[c]; ok {
			out = append(out, label)
		}
	}
	return out
}

// ResolveGrade reconstructs a modifier-bearing letter grade (A-, B+, ...)
// from DegreeWorks' numericGrade, since letterGrade truncates modifiers.
// Ported verbatim from tools.ts resolveGrade().
func ResolveGrade(letterGrade, numericGrade string, passFail, inProgress bool) string {
	if inProgress {
		return "N/A"
	}
	if passFail {
		if letterGrade != "" {
			return letterGrade
		}
		return "P/F"
	}
	if numericGrade == "" {
		return letterGrade
	}
	n, err := strconv.ParseFloat(numericGrade, 64)
	if err != nil {
		return letterGrade
	}
	rounded := float64(int(n*10+0.5)) / 10
	gradeMap := map[float64]string{
		4.0: "A", 3.7: "A-", 3.3: "B+", 3.0: "B", 2.7: "B-",
		2.3: "C+", 2.0: "C", 1.7: "C-", 1.3: "D+", 1.0: "D", 0.7: "D-", 0.0: "F",
	}
	if label, ok := gradeMap[rounded]; ok {
		return label
	}
	return letterGrade
}

// RuleStatus is complete/in_progress/incomplete, matching tools.ts's
// ruleStatus() return union.
type RuleStatus string

const (
	StatusComplete   RuleStatus = "complete"
	StatusInProgress RuleStatus = "in_progress"
	StatusIncomplete RuleStatus = "incomplete"
)

// Rule mirrors DegreeWorks' nested rule shape (a subset of fields used by
// the audit parser).
type Rule struct {
	Label                string  `json:"label"`
	PercentComplete      string  `json:"percentComplete"`
	InProgressIncomplete string  `json:"inProgressIncomplete"`
	Requirement          *struct {
		RuleComplete string `json:"ruleComplete"`
	} `json:"requirement"`
	RuleArray []Rule `json:"ruleArray"`
}

// ComputeRuleStatus reports a rule's completion status, ported verbatim from
// tools.ts ruleStatus().
func ComputeRuleStatus(r Rule) RuleStatus {
	if (r.Requirement != nil && r.Requirement.RuleComplete == "Y") || parsePercent(r.PercentComplete) >= 100 {
		return StatusComplete
	}
	if r.InProgressIncomplete == "Y" {
		return StatusInProgress
	}
	return StatusIncomplete
}

// ComputeBlockStatus reports a requirement block's completion status from
// its percentComplete string, ported verbatim from tools.ts blockStatus().
func ComputeBlockStatus(percentComplete string) RuleStatus {
	n := parsePercent(percentComplete)
	if n >= 100 {
		return StatusComplete
	}
	if n > 0 {
		return StatusInProgress
	}
	return StatusIncomplete
}

func parsePercent(s string) float64 {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return n
}

// FlatRule is one flattened, indented rule row for display.
type FlatRule struct {
	Indent int        `json:"indent"`
	Label  string     `json:"label"`
	Status RuleStatus `json:"status"`
}

// FlattenRules depth-first flattens a rule tree into indent/label/status
// rows, ported verbatim from tools.ts flattenRules().
func FlattenRules(rules []Rule, depth int) []FlatRule {
	var out []FlatRule
	for _, r := range rules {
		if r.Label != "" {
			out = append(out, FlatRule{Indent: depth, Label: r.Label, Status: ComputeRuleStatus(r)})
		}
		if len(r.RuleArray) > 0 {
			out = append(out, FlattenRules(r.RuleArray, depth+1)...)
		}
	}
	return out
}

// Block is one degree-audit requirement block.
type Block struct {
	Title           string `json:"title"`
	PercentComplete string `json:"percentComplete"`
	CreditsApplied  string `json:"creditsApplied"`
	RuleArray       []Rule `json:"ruleArray"`
}

// Advisor is one goalArray entry with code == "ADVISOR".
type Advisor struct {
	Name  *string `json:"name"`
	Email *string `json:"email"`
	Role  *string `json:"role"`
}

// AuditCourse is one flattened classArray course-history entry.
type AuditCourse struct {
	Code          string   `json:"code"`
	Title         string   `json:"title"`
	Credits       string   `json:"credits"`
	Grade         string   `json:"grade"`
	Term          string   `json:"term"`
	InProgress    bool     `json:"in_progress"`
	Preregistered bool     `json:"preregistered"`
	PassFail      bool     `json:"pass_fail"`
	Attributes    []string `json:"attributes"`
}

// AuditBlockView is one requirement block's flattened view for display.
type AuditBlockView struct {
	Title           string     `json:"title"`
	Status          RuleStatus `json:"status"`
	CreditsApplied  string     `json:"credits_applied"`
	Rules           []FlatRule `json:"rules"`
}

// AuditResult is the fully parsed degree audit, matching tools.ts's
// get_degree_audit response shape field-for-field.
type AuditResult struct {
	Student struct {
		Name               string `json:"name"`
		GPA                string `json:"gpa"`
		DWGPA              string `json:"dw_gpa"`
		OverallStatus      RuleStatus `json:"overall_status"`
		CreditsApplied     string `json:"credits_applied"`
		CreditsInProgress  string `json:"credits_in_progress"`
		TransferCredits    string `json:"transfer_credits"`
		ExamCredits        string `json:"exam_credits"`
		AuditDate          string `json:"audit_date"`
	} `json:"student"`
	Degree struct {
		Degree              string `json:"degree"`
		School              string `json:"school"`
		Major               string `json:"major"`
		ClassYear           string `json:"class_year"`
		CatalogYear         string `json:"catalog_year"`
		ActiveTerm          string `json:"active_term"`
		ExpectedGraduation  string `json:"expected_graduation"`
		TotalCreditsEarned  string `json:"total_credits_earned"`
	} `json:"degree"`
	Advisors          []Advisor        `json:"advisors"`
	RequirementBlocks []AuditBlockView `json:"requirement_blocks"`
	Courses           []AuditCourse    `json:"courses,omitempty"`
}

type rawAuditHeader struct {
	PercentComplete            string `json:"percentComplete"`
	StudentSystemGpa           string `json:"studentSystemGpa"`
	DegreeworksGpa             string `json:"degreeworksGpa"`
	ResidentApplied            string `json:"residentApplied"`
	ResidentAppliedInProgress  string `json:"residentAppliedInProgress"`
	TransferApplied            string `json:"transferApplied"`
	ExamAppliedCredits         string `json:"examAppliedCredits"`
	DateYear                   string `json:"dateYear"`
	DateMonth                  string `json:"dateMonth"`
	DateDay                    string `json:"dateDay"`
}

type rawDegreeData struct {
	DegreeLiteral                             string `json:"degreeLiteral"`
	SchoolLiteral                             string `json:"schoolLiteral"`
	CatalogYearLit                            string `json:"catalogYearLit"`
	ActiveTermLiteral                         string `json:"activeTermLiteral"`
	DegreeTerm                                string `json:"degreeTerm"`
	StudentLevelLiteral                       string `json:"studentLevelLiteral"`
	StudentSystemCumulativeTotalCreditsEarned string `json:"studentSystemCumulativeTotalCreditsEarned"`
}

type rawGoal struct {
	Code         string `json:"code"`
	ValueLiteral string `json:"valueLiteral"`
	AdvisorName  string `json:"advisorName"`
	AdvisorEmail string `json:"advisorEmail"`
	AttachCode   string `json:"attachCode"`
}

type rawClass struct {
	Discipline    string `json:"discipline"`
	Number        string `json:"number"`
	CourseTitle   string `json:"courseTitle"`
	Credits       string `json:"credits"`
	LetterGrade   string `json:"letterGrade"`
	NumericGrade  string `json:"numericGrade"`
	Term          string `json:"term"`
	TermLiteral   string `json:"termLiteral"`
	InProgress    string `json:"inProgress"`
	Preregistered string `json:"preregistered"`
	Passfail      string `json:"passfail"`
	AttributeArray []struct {
		Code  string `json:"code"`
		Value string `json:"value"`
	} `json:"attributeArray"`
}

type rawAudit struct {
	AuditHeader        rawAuditHeader `json:"auditHeader"`
	DegreeInformation  struct {
		DegreeDataArray []rawDegreeData `json:"degreeDataArray"`
		GoalArray       []rawGoal       `json:"goalArray"`
	} `json:"degreeInformation"`
	BlockArray         []Block `json:"blockArray"`
	ClassInformation   struct {
		ClassArray []rawClass `json:"classArray"`
	} `json:"classInformation"`
}

// FetchDegreeAudit performs the two-step degree-audit fetch (student ID,
// then the audit itself) and parses the result, ported verbatim from
// tools.ts get_degree_audit's fetch + parse logic.
func FetchDegreeAudit(ctx context.Context, cookie, school, degree string, includeCourses bool) (*AuditResult, error) {
	client := &http.Client{Timeout: 20 * time.Second}

	meReq, err := http.NewRequestWithContext(ctx, http.MethodGet, auditBase+"/responsive/api/users/myself", nil)
	if err != nil {
		return nil, err
	}
	meReq.Header.Set("Cookie", cookie)
	meReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
	meReq.Header.Set("Accept", "application/json")
	if err := auditLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	meResp, err := client.Do(meReq)
	if err != nil {
		return nil, fmt.Errorf("fetching degree audit user info: %w", err)
	}
	if meResp.StatusCode == http.StatusTooManyRequests {
		auditLimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(meResp)
		meResp.Body.Close()
		return nil, &cliutil.RateLimitError{URL: meReq.URL.String(), RetryAfter: retryAfter}
	}
	auditLimiter.OnSuccess()
	defer meResp.Body.Close()
	if meResp.StatusCode == 401 || meResp.StatusCode == 403 || meResp.StatusCode == 302 {
		return nil, fmt.Errorf("degree audit authentication failed; your cookie may have expired — re-authenticate to update it")
	}
	if meResp.StatusCode < 200 || meResp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to fetch user info: HTTP %d", meResp.StatusCode)
	}
	var me struct {
		ID     string `json:"id"`
		UserID string `json:"userId"`
		Name   string `json:"name"`
	}
	meBody, err := io.ReadAll(meResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading degree audit user info: %w", err)
	}
	if err := json.Unmarshal(meBody, &me); err != nil {
		return nil, fmt.Errorf("parsing degree audit user info: %w", err)
	}
	studentID := me.ID
	if studentID == "" {
		studentID = me.UserID
	}
	if studentID == "" {
		return nil, fmt.Errorf("could not determine student ID from degree audit")
	}

	auditURL := fmt.Sprintf(
		"%s/responsive/api/audit?studentId=%s&school=%s&degree=%s&is-process-new=false&audit-type=AA&auditId=&include-inprogress=true&include-preregistered=true&aid-term=",
		auditBase, url.QueryEscape(studentID), url.QueryEscape(school), url.QueryEscape(degree),
	)
	auditReq, err := http.NewRequestWithContext(ctx, http.MethodGet, auditURL, nil)
	if err != nil {
		return nil, err
	}
	auditReq.Header.Set("Cookie", cookie)
	auditReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
	auditReq.Header.Set("Accept", "application/vnd.net.hedtech.degreeworks.dashboard.audit.v1+json")
	if err := auditLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	auditResp, err := client.Do(auditReq)
	if err != nil {
		return nil, fmt.Errorf("fetching degree audit: %w", err)
	}
	if auditResp.StatusCode == http.StatusTooManyRequests {
		auditLimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(auditResp)
		auditResp.Body.Close()
		return nil, &cliutil.RateLimitError{URL: auditReq.URL.String(), RetryAfter: retryAfter}
	}
	auditLimiter.OnSuccess()
	defer auditResp.Body.Close()
	if auditResp.StatusCode < 200 || auditResp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to fetch degree audit: HTTP %d", auditResp.StatusCode)
	}
	var raw rawAudit
	if err := json.NewDecoder(auditResp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing degree audit: %w", err)
	}

	return parseAudit(me.Name, raw, includeCourses), nil
}

func parseAudit(name string, raw rawAudit, includeCourses bool) *AuditResult {
	result := &AuditResult{}
	h := raw.AuditHeader
	result.Student.Name = name
	result.Student.GPA = h.StudentSystemGpa
	result.Student.DWGPA = h.DegreeworksGpa
	result.Student.OverallStatus = ComputeBlockStatus(h.PercentComplete)
	result.Student.CreditsApplied = h.ResidentApplied
	result.Student.CreditsInProgress = h.ResidentAppliedInProgress
	result.Student.TransferCredits = h.TransferApplied
	result.Student.ExamCredits = h.ExamAppliedCredits
	result.Student.AuditDate = fmt.Sprintf("%s-%s-%s", h.DateYear, h.DateMonth, h.DateDay)

	var degData rawDegreeData
	if len(raw.DegreeInformation.DegreeDataArray) > 0 {
		degData = raw.DegreeInformation.DegreeDataArray[0]
	}
	major := "Undeclared"
	var advisors []Advisor
	for _, g := range raw.DegreeInformation.GoalArray {
		if g.Code == "MAJOR" {
			major = g.ValueLiteral
		}
		if g.Code == "ADVISOR" {
			n, e, r := g.AdvisorName, g.AdvisorEmail, g.AttachCode
			advisors = append(advisors, Advisor{Name: &n, Email: &e, Role: &r})
		}
	}
	result.Advisors = advisors
	if result.Advisors == nil {
		result.Advisors = []Advisor{}
	}

	result.Degree.Degree = degData.DegreeLiteral
	result.Degree.School = degData.SchoolLiteral
	result.Degree.Major = major
	result.Degree.ClassYear = degData.StudentLevelLiteral
	result.Degree.CatalogYear = degData.CatalogYearLit
	result.Degree.ActiveTerm = degData.ActiveTermLiteral
	result.Degree.ExpectedGraduation = degData.DegreeTerm
	result.Degree.TotalCreditsEarned = degData.StudentSystemCumulativeTotalCreditsEarned

	for _, b := range raw.BlockArray {
		result.RequirementBlocks = append(result.RequirementBlocks, AuditBlockView{
			Title:          b.Title,
			Status:         ComputeBlockStatus(b.PercentComplete),
			CreditsApplied: b.CreditsApplied,
			Rules:          FlattenRules(b.RuleArray, 0),
		})
	}
	if result.RequirementBlocks == nil {
		result.RequirementBlocks = []AuditBlockView{}
	}

	if includeCourses {
		for _, c := range raw.ClassInformation.ClassArray {
			var attrCodes []string
			for _, a := range c.AttributeArray {
				if a.Code == "ATTRIBUTE" {
					attrCodes = append(attrCodes, a.Value)
				}
			}
			result.Courses = append(result.Courses, AuditCourse{
				Code:          strings.TrimSpace(c.Discipline + " " + c.Number),
				Title:         c.CourseTitle,
				Credits:       c.Credits,
				Grade:         ResolveGrade(c.LetterGrade, c.NumericGrade, c.Passfail == "Y", c.InProgress == "Y" || c.Preregistered == "Y"),
				Term:          c.TermLiteral,
				InProgress:    c.InProgress == "Y",
				Preregistered: c.Preregistered == "Y",
				PassFail:      c.Passfail == "Y",
				Attributes:    DecodeAttributes(attrCodes),
			})
		}
		if result.Courses == nil {
			result.Courses = []AuditCourse{}
		}
	}

	return result
}
