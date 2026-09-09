// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Local cache glue between 'courses syllabus' (which fetches one syllabus)
// and 'worksheet syllabus-search' (which searches every already-fetched
// syllabus for a worksheet at once). Best-effort: a caching failure never
// fails the syllabus-fetch command itself.

package cli

import (
	"context"
	"encoding/json"

	"yalie-pp-cli/internal/store"
	"yalie-pp-cli/internal/yale"
)

func cacheSyllabusLocally(result *yale.SyllabusResult) {
	if result == nil {
		return
	}
	db, err := store.OpenWithContext(context.Background(), defaultDBPath("yalie-pp-cli"))
	if err != nil {
		return
	}
	defer db.Close()
	raw, err := json.Marshal(map[string]any{
		"source_url": result.SourceURL, "text": result.Text, "truncated": result.Truncated,
	})
	if err != nil {
		return
	}
	_ = db.Upsert("syllabus", result.SourceURL, raw)
}
