// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// buildMinimalPDF constructs a tiny, valid single-page PDF (correct xref
// table computed from real byte offsets, not hand-typed) whose content
// stream draws the given text string. Used so PDF-extraction tests assert
// on real, known text content rather than merely "it didn't error."
func buildMinimalPDF(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	var offsets []int

	writeObj := func(s string) {
		offsets = append(offsets, buf.Len())
		buf.WriteString(s)
	}

	buf.WriteString("%PDF-1.4\n")
	writeObj("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	writeObj("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
	writeObj("3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
	writeObj("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

	content := fmt.Sprintf("BT /F1 24 Tf 100 700 Td (%s) Tj ET", text)
	writeObj(fmt.Sprintf("5 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(content), content))

	xrefStart := buf.Len()
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n", len(offsets)+1))
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}
	buf.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF", len(offsets)+1, xrefStart))

	return buf.Bytes()
}

func TestExtractPDFText(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{name: "simple word", text: "Hello World"},
		{name: "syllabus-like phrase", text: "Final Exam Policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildMinimalPDF(t, tc.text)
			got, err := ExtractPDFText(data)
			if err != nil {
				t.Fatalf("ExtractPDFText() error = %v", err)
			}
			if got == "" {
				t.Fatalf("ExtractPDFText() returned empty text, want real extracted content containing %q", tc.text)
			}
			// Assert on the actual extracted words, not just "no error" —
			// a placeholder/stub implementation would still pass a
			// bare no-error check but would never produce the real words.
			for _, word := range strings.Fields(tc.text) {
				if !strings.Contains(got, word) {
					t.Errorf("ExtractPDFText() = %q, want it to contain word %q from source PDF text %q", got, word, tc.text)
				}
			}
		})
	}
}

func TestExtractPDFTextInvalidData(t *testing.T) {
	_, err := ExtractPDFText([]byte("this is not a pdf file at all"))
	if err == nil {
		t.Fatal("ExtractPDFText() on non-PDF bytes: want error, got nil")
	}
}

func TestTruncatePDFText(t *testing.T) {
	short := "short text"
	if out, truncated := TruncatePDFText(short); truncated || out != short {
		t.Errorf("TruncatePDFText(short) = (%q, %v), want (%q, false)", out, truncated, short)
	}

	long := strings.Repeat("a", maxPDFTextChars+100)
	out, truncated := TruncatePDFText(long)
	if !truncated {
		t.Error("TruncatePDFText(long) truncated = false, want true")
	}
	if !strings.HasSuffix(out, "\n[PDF truncated]") {
		t.Errorf("TruncatePDFText(long) = %q, want suffix %q", out, "\n[PDF truncated]")
	}
	if len(out) != maxPDFTextChars+len("\n[PDF truncated]") {
		t.Errorf("TruncatePDFText(long) length = %d, want %d", len(out), maxPDFTextChars+len("\n[PDF truncated]"))
	}
}

func TestLooksLikePDF(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		filename    string
		url         string
		want        bool
	}{
		{name: "pdf content-type", contentType: "application/pdf", want: true},
		{name: "pdf filename", filename: "syllabus.pdf", want: true},
		{name: "pdf url with query", url: "https://example.com/reading.pdf?download=1", want: true},
		{name: "non-pdf", contentType: "text/html", filename: "page.html", url: "https://example.com/page", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikePDF(tc.contentType, tc.filename, tc.url); got != tc.want {
				t.Errorf("LooksLikePDF(%q, %q, %q) = %v, want %v", tc.contentType, tc.filename, tc.url, got, tc.want)
			}
		})
	}
}
