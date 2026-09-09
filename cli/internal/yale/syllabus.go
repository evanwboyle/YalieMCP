// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"yalie-pp-cli/internal/cliutil"
)

// syllabusLimiter paces outbound requests to yale.instructure.com for
// syllabus HTML pages so a burst of fetches backs off on a 429 instead of
// hammering Canvas.
var syllabusLimiter = cliutil.NewAdaptiveLimiterAuto(3.0)

// CanvasAuth carries the caller's Canvas credential: a Bearer token when the
// user has one (Yale blocks self-service PAT generation for most students,
// confirmed directly by the user during research for this CLI), otherwise a
// yale.instructure.com session cookie exactly like the original YalieMCP
// used. Exactly one of Token/Cookie should be set; Token takes priority.
type CanvasAuth struct {
	Token  string
	Cookie string
}

func (a CanvasAuth) apply(req *http.Request) {
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
		return
	}
	if a.Cookie != "" {
		req.Header.Set("Cookie", a.Cookie)
	}
}

// Configured reports whether either credential is present.
func (a CanvasAuth) Configured() bool {
	return a.Token != "" || a.Cookie != ""
}

var divIDPattern = func(id string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)<div[^>]*id=["']` + regexp.QuoteMeta(id) + `["'][^>]*>`)
}

// extractDivContent extracts a div's inner HTML by id, tracking nested div
// depth (a regex alone can't balance nested tags). Ported verbatim from
// tools.ts's extractDivContent() closure inside get_syllabus_content.
func extractDivContent(h, id string) (string, bool) {
	pat := divIDPattern(id)
	loc := pat.FindStringIndex(h)
	if loc == nil {
		return "", false
	}
	depth := 1
	pos := loc[1]
	start := pos
	nextOpen := func(from int) int {
		p := from
		for p < len(h) {
			idx := strings.Index(h[p:], "<div")
			if idx == -1 {
				return -1
			}
			idx += p
			end := idx + 4
			if end < len(h) {
				c := h[end]
				if c == '>' || c == ' ' || c == '\n' || c == '\t' || c == '\r' {
					return idx
				}
			}
			p = idx + 4
		}
		return -1
	}
	for depth > 0 && pos < len(h) {
		op := nextOpen(pos)
		cl := strings.Index(h[pos:], "</div>")
		if cl == -1 {
			break
		}
		cl += pos
		if op != -1 && op < cl {
			depth++
			pos = op + 4
		} else {
			depth--
			if depth == 0 {
				return h[start:cl], true
			}
			pos = cl + 6
		}
	}
	return "", false
}

// SyllabusAttachment is one PDF/file link discovered inside the isolated
// syllabus section, plus (best-effort) its extracted content.
type SyllabusAttachment struct {
	URL        string
	Label      string
	IsCanvas   bool
	Text       string // extracted PDF text, if extraction succeeded
	Truncated  bool   // true if Text was cut at the 100,000-char cap
	FetchError string // set instead of Text when the attachment could not be retrieved/parsed
}

var syllabusLinkRE = regexp.MustCompile(`(?is)<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)</a>`)
var canvasFileURLRE = regexp.MustCompile(`(?i)(?:https?://yale\.instructure\.com)?(/courses/(\d+)/files/(\d+))`)
var pdfExtRE = regexp.MustCompile(`(?i)\.pdf(\?|#|$)`)
var tagStripRE = regexp.MustCompile(`<[^>]+>`)

// extractAttachmentLinks extracts PDF/Canvas file links from the isolated
// syllabus HTML section only (never the full page), ported from tools.ts's
// inline link-extraction loop in get_syllabus_content.
func extractAttachmentLinks(syllabusHTML string) []SyllabusAttachment {
	seen := map[string]bool{}
	var out []SyllabusAttachment
	for _, m := range syllabusLinkRE.FindAllStringSubmatch(syllabusHTML, -1) {
		rawHref := strings.TrimSpace(m[1])
		label := strings.TrimSpace(tagStripRE.ReplaceAllString(m[2], ""))
		if label == "" {
			label = "attachment"
		}
		if cm := canvasFileURLRE.FindStringSubmatch(rawHref); cm != nil {
			dlURL := fmt.Sprintf("https://yale.instructure.com/courses/%s/files/%s/download?download_frd=1", cm[2], cm[3])
			if !seen[dlURL] {
				seen[dlURL] = true
				out = append(out, SyllabusAttachment{URL: dlURL, Label: label, IsCanvas: true})
			}
			continue
		}
		if pdfExtRE.MatchString(rawHref) && strings.HasPrefix(strings.ToLower(rawHref), "http") {
			if !seen[rawHref] {
				seen[rawHref] = true
				out = append(out, SyllabusAttachment{URL: rawHref, Label: label, IsCanvas: false})
			}
		}
	}
	return out
}

var (
	brTagRE   = regexp.MustCompile(`(?i)<br\s*/?>`)
	pCloseRE  = regexp.MustCompile(`(?i)</p>`)
	liCloseRE = regexp.MustCompile(`(?i)</li>`)
	multiNLRE = regexp.MustCompile(`\n{3,}`)
)

func htmlToText(source string) string {
	s := scriptTagRE.ReplaceAllString(source, "")
	s = styleTagRE.ReplaceAllString(s, "")
	s = brTagRE.ReplaceAllString(s, "\n")
	s = pCloseRE.ReplaceAllString(s, "\n\n")
	s = liCloseRE.ReplaceAllString(s, "\n")
	s = anyTagRE.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = numEntityRE.ReplaceAllString(s, " ")
	s = multiNLRE.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// SyllabusResult is the fetched, parsed syllabus content.
type SyllabusResult struct {
	SourceURL   string
	Text        string
	Truncated   bool
	Attachments []SyllabusAttachment
}

// FetchSyllabus fetches a yale.instructure.com syllabus URL and extracts its
// plain-text content plus any linked PDF/Canvas-file attachments. Up to the
// first 2 attachments are downloaded and have their text extracted (via
// ExtractPDFText, a pure-Go PDF parser standing in for the original MCP's
// JS-only "unpdf" library) and appended to Text under a labeled
// `--- Attached PDF: "<label>" ---` header, exactly like the original
// get_syllabus_content handler. A per-attachment fetch/parse failure never
// fails the whole call — it degrades to a labeled failure note instead.
// Ported from tools.ts get_syllabus_content, including its single
// same-host redirect rule and its content-isolation strategy (never fall
// back to the full page for link extraction).
func FetchSyllabus(ctx context.Context, auth CanvasAuth, syllabusURL string) (*SyllabusResult, error) {
	parsed, err := url.Parse(syllabusURL)
	if err != nil || parsed.Hostname() != "yale.instructure.com" {
		return nil, fmt.Errorf("syllabus_url must be a yale.instructure.com URL")
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	doFetch := func(u string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		auth.apply(req)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
		req.Header.Set("Accept", "text/html")
		if err := syllabusLimiter.Wait(ctx); err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			syllabusLimiter.OnRateLimit()
			retryAfter := cliutil.RetryAfter(resp)
			resp.Body.Close()
			return nil, &cliutil.RateLimitError{URL: req.URL.String(), RetryAfter: retryAfter}
		}
		syllabusLimiter.OnSuccess()
		return resp, nil
	}

	resp, err := doFetch(syllabusURL)
	if err != nil {
		var rateErr *cliutil.RateLimitError
		if errors.As(err, &rateErr) {
			return nil, rateErr
		}
		return nil, fmt.Errorf("fetching syllabus: %w", err)
	}
	defer resp.Body.Close()

	final := resp
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil, fmt.Errorf("failed to fetch syllabus: unexpected redirect with no Location header")
		}
		redirectURL, err := url.Parse(location)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch syllabus: invalid redirect URL")
		}
		resolved := parsed.ResolveReference(redirectURL)
		if resolved.Hostname() != "yale.instructure.com" {
			return nil, fmt.Errorf("failed to fetch syllabus: redirect outside yale.instructure.com is not permitted")
		}
		resp.Body.Close()
		final, err = doFetch(resolved.String())
		if err != nil {
			var rateErr *cliutil.RateLimitError
			if errors.As(err, &rateErr) {
				return nil, rateErr
			}
			return nil, fmt.Errorf("fetching syllabus (redirected): %w", err)
		}
		defer final.Body.Close()
	}

	if final.StatusCode == 401 || final.StatusCode == 403 || strings.Contains(final.Header.Get("Location"), "/login") {
		return nil, fmt.Errorf("Canvas authentication failed; your Canvas cookie/token may have expired or be missing — re-authenticate to refresh it")
	}
	if final.StatusCode < 200 || final.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to fetch syllabus (HTTP %d)", final.StatusCode)
	}

	body, err := io.ReadAll(final.Body)
	if err != nil {
		return nil, fmt.Errorf("reading syllabus response: %w", err)
	}
	html := string(body)

	syllabusHTML, isolated := extractDivContent(html, "content")
	if !isolated {
		syllabusHTML, isolated = extractDivContent(html, "not_right_side")
	}
	source := html
	if isolated {
		source = syllabusHTML
	}

	var attachments []SyllabusAttachment
	if isolated {
		attachments = extractAttachmentLinks(syllabusHTML)
	}

	text := htmlToText(source)
	if len(text) < 50 && len(attachments) == 0 {
		return nil, fmt.Errorf("syllabus appears empty or could not be parsed; the course may not have a syllabus posted on Canvas")
	}

	truncated := false
	if len(text) > 8000 {
		text = text[:8000] + "\n\n[syllabus text truncated]"
		truncated = true
	}

	// Fetch and extract text from up to maxAttachmentFetches linked
	// PDFs/Canvas files, appending each as a labeled section — ported from
	// tools.ts get_syllabus_content's "Fetch and parse PDFs (max 2)" loop.
	var parts strings.Builder
	parts.WriteString(text)
	for i := range attachments {
		if i >= maxAttachmentFetches {
			break
		}
		a := &attachments[i]
		res, fetchErr := FetchAndExtractPDF(ctx, auth, a.IsCanvas, a.URL)
		if fetchErr != nil {
			a.FetchError = fetchErr.Error()
			note := fmt.Sprintf("\n\n--- Attached file: %q ---\n%s\n", a.Label, fetchErr.Error())
			if a.IsCanvas {
				note += fmt.Sprintf("URL: %s\nDo NOT attempt to fetch this URL directly — it requires authenticated cookies. Inform the user the attachment could not be loaded.", a.URL)
			} else {
				note += fmt.Sprintf("The user can try opening this URL directly: %s", a.URL)
			}
			parts.WriteString(note)
			continue
		}
		a.Text = res.Text
		a.Truncated = res.Truncated
		parts.WriteString(fmt.Sprintf("\n\n--- Attached PDF: %q ---\n%s", a.Label, res.Text))
	}
	text = parts.String()

	return &SyllabusResult{SourceURL: syllabusURL, Text: text, Truncated: truncated, Attachments: attachments}, nil
}
