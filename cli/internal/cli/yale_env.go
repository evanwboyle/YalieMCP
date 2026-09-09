// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"fmt"
	"os"

	"yalie-pp-cli/internal/yale"
)

// courseTableCookie reads the CourseTable session cookie. Required for
// account-scoped CourseTable calls (worksheets, wishlist, friends, user
// info); public catalog/evaluation queries work with an empty cookie too.
func courseTableCookie() string {
	return os.Getenv("COURSETABLE_COOKIE")
}

func requireCourseTableCookie() (string, error) {
	c := courseTableCookie()
	if c == "" {
		return "", fmt.Errorf("COURSETABLE_COOKIE not set. Copy document.cookie from a logged-in coursetable.com tab and export it as COURSETABLE_COOKIE")
	}
	return c, nil
}

// canvasAuth resolves dual-mode Canvas auth: an admin-issued Bearer token
// (CANVAS_TOKEN) if the account has one, falling back to a
// yale.instructure.com session cookie (CANVAS_COOKIE) — Yale blocks
// self-service Canvas token generation for most students, confirmed
// directly during research for this CLI.
func canvasAuth() yale.CanvasAuth {
	return yale.CanvasAuth{
		Token:  os.Getenv("CANVAS_TOKEN"),
		Cookie: os.Getenv("CANVAS_COOKIE"),
	}
}

func requireCanvasAuth() (yale.CanvasAuth, error) {
	a := canvasAuth()
	if !a.Configured() {
		return a, fmt.Errorf("no Canvas credential configured. Set CANVAS_TOKEN (if your Yale account has an admin-issued token) or CANVAS_COOKIE (copy document.cookie from a logged-in yale.instructure.com tab)")
	}
	return a, nil
}

// auditCookie reads the Degree Audit session cookie.
func auditCookie() string {
	return os.Getenv("AUDIT_COOKIE")
}

func requireAuditCookie() (string, error) {
	c := auditCookie()
	if c == "" {
		return "", fmt.Errorf("AUDIT_COOKIE not set. Copy document.cookie from a logged-in degreeaudit.yale.edu tab and export it as AUDIT_COOKIE")
	}
	return c, nil
}
