// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"yalie-pp-cli/internal/cliutil"
)

// catalogLimiter paces outbound requests to the scraped catalog.yale.edu
// pages so a burst of catalog fetches backs off on a 429 instead of
// hammering Yale's backend.
var catalogLimiter = cliutil.NewAdaptiveLimiterAuto(3.0)

var (
	scriptTagRE  = regexp.MustCompile(`(?is)<script[\s\S]*?</script>`)
	styleTagRE   = regexp.MustCompile(`(?is)<style[\s\S]*?</style>`)
	anyTagRE     = regexp.MustCompile(`<[^>]+>`)
	whitespaceRE = regexp.MustCompile(`\s+`)
	numEntityRE  = regexp.MustCompile(`&#\d+;`)
)

// stripHTML renders HTML down to normalized plain text, ported from
// tools.ts's fetchCatalogText() cleanup pipeline (script/style removal, tag
// stripping, entity decoding, whitespace collapse).
func stripHTML(html string) string {
	s := scriptTagRE.ReplaceAllString(html, "")
	s = styleTagRE.ReplaceAllString(s, "")
	s = anyTagRE.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = numEntityRE.ReplaceAllString(s, " ")
	s = whitespaceRE.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// FetchRawHTML fetches url and returns its raw HTML body, unmodified. Used
// where callers need to run their own link-extraction regexes (e.g.
// list_majors, list_certificates) rather than the stripped-text form.
func FetchRawHTML(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
	client := &http.Client{Timeout: 10 * time.Second}
	if err := catalogLimiter.Wait(ctx); err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		catalogLimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(resp)
		resp.Body.Close()
		return "", &cliutil.RateLimitError{URL: req.URL.String(), RetryAfter: retryAfter}
	}
	catalogLimiter.OnSuccess()
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", url, err)
	}
	return string(body), nil
}

// FetchCatalogText fetches url and returns its normalized plain-text
// content. Ported from tools.ts fetchCatalogText().
func FetchCatalogText(ctx context.Context, url string) (string, error) {
	html, err := FetchRawHTML(ctx, url)
	if err != nil {
		return "", err
	}
	return stripHTML(html), nil
}

// CatalogLink is one href/text pair extracted from a catalog index page.
type CatalogLink struct {
	Href string
	Text string
}

var subjectsLinkRE = regexp.MustCompile(`(?i)href="(/ycps/subjects-of-instruction/[^"#?]+)"[^>]*>\s*([^<]{2,80})`)

// ExtractCatalogLinks extracts subjects-of-instruction href/text pairs from
// catalog index HTML (used by list_majors / catalog azindex scraping).
// Ported from tools.ts extractCatalogLinks().
func ExtractCatalogLinks(html string) []CatalogLink {
	var out []CatalogLink
	for _, m := range subjectsLinkRE.FindAllStringSubmatch(html, -1) {
		text := whitespaceRE.ReplaceAllString(strings.TrimSpace(m[2]), " ")
		text = strings.ReplaceAll(text, "&ndash;", "–")
		text = strings.ReplaceAll(text, "&amp;", "&")
		if text != "" {
			out = append(out, CatalogLink{Href: m[1], Text: text})
		}
	}
	return out
}

// Cert is one certificate program entry.
type Cert struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

var certLinkRE = regexp.MustCompile(`(?i)href="(/ycps/subjects-of-instruction/[^"#?]+)[^"]*"[^>]*>\s*([^<]{2,80})`)

// ExtractCertificateLinks parses the certificates index page into name/slug
// pairs, ported from tools.ts list_certificates's inline regex.
func ExtractCertificateLinks(html string) []Cert {
	seen := map[string]bool{}
	var out []Cert
	for _, m := range certLinkRE.FindAllStringSubmatch(html, -1) {
		slug := strings.TrimSuffix(strings.TrimPrefix(m[1], "/ycps/subjects-of-instruction/"), "/")
		name := whitespaceRE.ReplaceAllString(strings.TrimSpace(m[2]), " ")
		name = strings.ReplaceAll(name, "&amp;", "&")
		name = strings.ReplaceAll(name, "&ndash;", "–")
		if slug != "" && name != "" && !seen[slug] {
			seen[slug] = true
			out = append(out, Cert{Name: name, Slug: slug})
		}
	}
	return out
}

// CurriculumSections maps a friendly section slug to its catalog.yale.edu
// path, ported verbatim from tools.ts's CURRICULUM_SECTIONS map.
var CurriculumSections = map[string]string{
	"distributional-requirements": "/ycps/yale-college/distributional-requirements/",
	"major-programs":              "/ycps/yale-college/major-programs/",
	"certificates":                "/ycps/yale-college/certificates/",
	"international-experience":    "/ycps/yale-college/international-experience/",
	"experiential-learning":       "/ycps/yale-college/experiential-learning/",
	"yale-summer-session":         "/ycps/yale-college/yale-summer-session/",
	"special-academic-resources":  "/ycps/yale-college/special-academic-resources/",
	"special-programs":            "/ycps/yale-college/special-programs/",
	"honors":                      "/ycps/yale-college/honors/",
	"academic-regulations":        "/ycps/academic-regulations/",
	"majors-by-disciplines":       "/ycps/majors-by-disciplines/",
	"majors-in-yale-college":      "/ycps/majors-in-yale-college/",
	"roadmaps":                    "/ycps/roadmaps/",
	"attributes":                  "/ycps/attributes/",
	"general-information":         "/ycps/general-information/",
}

var slugCleanRE = regexp.MustCompile(`[^a-z0-9-]`)

// CleanSlug lowercases, hyphenates whitespace, and strips anything that
// isn't [a-z0-9-] from a user-supplied major/certificate/curriculum slug,
// matching tools.ts's inline slug normalization.
func CleanSlug(s string) string {
	lower := strings.ToLower(strings.TrimSpace(s))
	lower = whitespaceRE.ReplaceAllString(lower, "-")
	return slugCleanRE.ReplaceAllString(lower, "")
}
