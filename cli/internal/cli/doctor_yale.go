// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Extends the generated doctor command with checks for the three Yale data
// sources the generator's spec-based client doesn't cover: CourseTable
// (public + account), Degree Audit, and the Yale Catalog. Each check uses
// the cheapest real request for that source, per the yalie-pp-cli build
// brief's doctor requirement.

package cli

import (
	"context"
	"net/http"
	"time"

	"yalie-pp-cli/internal/yale"
)

func collectYaleSourcesReport(ctx context.Context, report map[string]any) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// CourseTable public: anonymous GraphQL seasons query. Reachable with no
	// auth at all — confirmed during research for this CLI.
	var seasons struct {
		Seasons []struct {
			SeasonCode string `json:"season_code"`
		} `json:"seasons"`
	}
	if err := yale.GQL(ctx, "", yale.SeasonsQuery, nil, &seasons); err != nil {
		report["coursetable_public"] = "ERROR unreachable: " + err.Error()
	} else {
		report["coursetable_public"] = "reachable (no auth required)"
	}

	// CourseTable account: /api/user/info requires a valid session cookie.
	if courseTableCookie() == "" {
		report["coursetable_account"] = "optional: COURSETABLE_COOKIE not set (only needed for worksheets/wishlist/friends/whoami)"
	} else if yale.ValidateCookie(ctx, courseTableCookie()) {
		report["coursetable_account"] = "configured and valid"
	} else {
		report["coursetable_account"] = "ERROR COURSETABLE_COOKIE set but not accepted — it may have expired"
	}

	// Degree Audit: /responsive/api/users/myself requires a valid CAS-derived
	// session cookie; there is no anonymous check for this source.
	if auditCookie() == "" {
		report["degree_audit"] = "optional: AUDIT_COOKIE not set (only needed for 'audit get'/'audit recommend'/'majors fit'/'certificates fit')"
	} else {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://degreeaudit.yale.edu/responsive/api/users/myself", nil)
		if err != nil {
			report["degree_audit"] = "ERROR building request: " + err.Error()
		} else {
			req.Header.Set("Cookie", auditCookie())
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				report["degree_audit"] = "ERROR unreachable: " + err.Error()
			} else {
				resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					report["degree_audit"] = "configured and valid"
				} else {
					report["degree_audit"] = "ERROR AUDIT_COOKIE set but not accepted (HTTP " + http.StatusText(resp.StatusCode) + ")"
				}
			}
		}
	}

	// Yale Catalog: plain public HTTP GET, no auth ever required.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, yale.CatalogBase+"/ycps/subjects-of-instruction/", nil)
	if err != nil {
		report["yale_catalog"] = "ERROR building request: " + err.Error()
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; yalie-pp-cli/1.0)")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			report["yale_catalog"] = "ERROR unreachable: " + err.Error()
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				report["yale_catalog"] = "reachable (no auth required)"
			} else {
				report["yale_catalog"] = "ERROR unexpected status from catalog"
			}
		}
	}
}
