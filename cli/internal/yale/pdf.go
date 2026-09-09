// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ledongthuc/pdf"
	"yalie-pp-cli/internal/cliutil"
)

// pdfLimiter paces outbound requests for linked PDF/Canvas-file attachments
// so a burst of downloads backs off on a 429 instead of hammering the host.
var pdfLimiter = cliutil.NewAdaptiveLimiterAuto(3.0)

// maxPDFTextChars mirrors the 100,000-character truncation the original
// TypeScript get_syllabus_content handler applied to extracted PDF text
// (via unpdf), so downstream consumers see the same cap.
const maxPDFTextChars = 100000

// maxAttachmentFetches mirrors the original handler's "max 2 linked
// files" limit — never fetch every attachment on a syllabus page.
const maxAttachmentFetches = 2

// ExtractPDFText extracts plain text from raw PDF bytes using a pure-Go
// parser (github.com/ledongthuc/pdf), replacing the original TypeScript
// implementation's use of the JS-only "unpdf" library. Returns the
// trimmed, concatenated text of every page.
func ExtractPDFText(data []byte) (string, error) {
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("parsing PDF: %w", err)
	}
	textReader, err := r.GetPlainText()
	if err != nil {
		return "", fmt.Errorf("extracting PDF text: %w", err)
	}
	buf, err := io.ReadAll(textReader)
	if err != nil {
		return "", fmt.Errorf("reading extracted PDF text: %w", err)
	}
	return strings.TrimSpace(string(buf)), nil
}

// TruncatePDFText applies the same 100,000-character cap (with a
// "[PDF truncated]" marker) the original TypeScript handler used.
func TruncatePDFText(text string) (out string, truncated bool) {
	if len(text) > maxPDFTextChars {
		return text[:maxPDFTextChars] + "\n[PDF truncated]", true
	}
	return text, false
}

// PDFFetchResult is the outcome of fetching and extracting one linked
// PDF/Canvas-file attachment.
type PDFFetchResult struct {
	Text      string
	Truncated bool
}

// FetchAndExtractPDF downloads fileURL (attaching the Canvas auth only when
// isCanvas is set, matching the original handler's cookie-vs-no-auth split
// between Canvas-hosted files and external PDF links), verifies the
// response looks like a PDF/binary payload, and extracts its text. Errors
// are always non-fatal to the caller: per the original handler's design,
// a failed attachment should degrade to a labeled note, never abort the
// whole response.
func FetchAndExtractPDF(ctx context.Context, auth CanvasAuth, isCanvas bool, fileURL string) (*PDFFetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
	req.Header.Set("Accept", "application/pdf,*/*")
	if isCanvas {
		auth.apply(req)
	}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if err := pdfLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		pdfLimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(resp)
		resp.Body.Close()
		return nil, &cliutil.RateLimitError{URL: req.URL.String(), RetryAfter: retryAfter}
	}
	pdfLimiter.OnSuccess()
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("could not retrieve (HTTP %d)", resp.StatusCode)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "pdf") && !strings.Contains(contentType, "octet-stream") {
		return nil, fmt.Errorf("unexpected content type (%s), could not parse as PDF", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	text, err := ExtractPDFText(body)
	if err != nil {
		return nil, err
	}
	trunc, truncated := TruncatePDFText(text)
	return &PDFFetchResult{Text: trunc, Truncated: truncated}, nil
}

// looksLikePDF reports whether a content-type/filename/URL combination
// indicates a PDF, for callers (like "canvas files get") that already have
// file metadata and just need to decide whether to attempt extraction.
func LooksLikePDF(contentType, filename, fileURL string) bool {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "pdf") {
		return true
	}
	return pdfExtRE.MatchString(filename) || pdfExtRE.MatchString(fileURL)
}
