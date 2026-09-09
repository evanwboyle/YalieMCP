// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import "testing"

func TestStripHTML(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "strips script and style",
			in:   `<html><head><style>.a{color:red}</style><script>alert(1)</script></head><body><p>Hello &amp; welcome</p></body></html>`,
			want: "Hello & welcome",
		},
		{
			name: "collapses whitespace",
			in:   "<p>Line one</p>\n\n<p>Line   two</p>",
			want: "Line one Line two",
		},
		{
			name: "decodes numeric and named entities",
			in:   "<p>A&nbsp;B&#160;C &lt;tag&gt;</p>",
			want: "A B C <tag>",
		},
		{
			name: "empty input",
			in:   "",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripHTML(tc.in)
			if got != tc.want {
				t.Errorf("stripHTML(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestExtractCatalogLinks(t *testing.T) {
	html := `
	<a href="/ycps/subjects-of-instruction/computer-science/">Computer Science</a>
	<a href="/ycps/subjects-of-instruction/mathematics/">Mathematics</a>
	<a href="/ycps/azindex/">A-Z Index</a>
	`
	links := ExtractCatalogLinks(html)
	if len(links) != 2 {
		t.Fatalf("expected 2 links, got %d: %+v", len(links), links)
	}
	if links[0].Href != "/ycps/subjects-of-instruction/computer-science/" || links[0].Text != "Computer Science" {
		t.Errorf("unexpected first link: %+v", links[0])
	}
	if links[1].Text != "Mathematics" {
		t.Errorf("unexpected second link: %+v", links[1])
	}
}

func TestExtractCertificateLinks(t *testing.T) {
	html := `
	<a href="/ycps/subjects-of-instruction/data-science/">Data Science</a>
	<a href="/ycps/subjects-of-instruction/data-science/#overview">Data Science</a>
	<a href="/ycps/subjects-of-instruction/global-health/">Global Health &amp; Studies</a>
	`
	certs := ExtractCertificateLinks(html)
	if len(certs) != 2 {
		t.Fatalf("expected 2 deduplicated certs, got %d: %+v", len(certs), certs)
	}
	if certs[0].Slug != "data-science" {
		t.Errorf("unexpected slug: %+v", certs[0])
	}
	if certs[1].Name != "Global Health & Studies" {
		t.Errorf("unexpected entity decode: %+v", certs[1])
	}
}

func TestCleanSlug(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Computer Science", "computer-science"},
		{"  Data   Science  ", "data-science"},
		{"East Asian Studies!", "east-asian-studies"},
		{"already-a-slug", "already-a-slug"},
	}
	for _, tc := range cases {
		if got := CleanSlug(tc.in); got != tc.want {
			t.Errorf("CleanSlug(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSeasonLabel(t *testing.T) {
	cases := []struct{ code, want string }{
		{"202303", "Fall 2023"},
		{"202401", "Spring 2024"},
		{"202502", "Summer 2025"},
		{"bad", "bad"},
	}
	for _, tc := range cases {
		if got := SeasonLabel(tc.code); got != tc.want {
			t.Errorf("SeasonLabel(%q) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestDecodeDays(t *testing.T) {
	cases := []struct {
		bits int64
		want string
	}{
		{0, "TBA"},
		{1, "Mon"},
		{0b0010101, "Mon/Wed/Fri"},
		{0b1000000, "Sun"},
	}
	for _, tc := range cases {
		if got := DecodeDays(tc.bits); got != tc.want {
			t.Errorf("DecodeDays(%b) = %q, want %q", tc.bits, got, tc.want)
		}
	}
}

func TestFormatTime(t *testing.T) {
	cases := []struct{ in, want string }{
		{"13:30", "1:30 PM"},
		{"00:00", "12:00 AM"},
		{"12:00", "12:00 PM"},
		{"9:05", "9:05 AM"},
		{"garbage", "garbage"},
	}
	for _, tc := range cases {
		if got := FormatTime(tc.in); got != tc.want {
			t.Errorf("FormatTime(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeSubject(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cs", "CPSC"},
		{"CS", "CPSC"},
		{"philo", "PHIL"},
		{"cpsc", "CPSC"},
		{"stats", "S&DS"},
	}
	for _, tc := range cases {
		if got := NormalizeSubject(tc.in); got != tc.want {
			t.Errorf("NormalizeSubject(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
