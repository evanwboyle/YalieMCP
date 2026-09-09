// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"yalie-pp-cli/internal/cliutil"
)

// restAPILimiter paces outbound requests to CourseTable's plain REST
// endpoints (api.coursetable.com) so a burst of calls backs off on a 429
// instead of hammering CourseTable.
var restAPILimiter = cliutil.NewAdaptiveLimiterAuto(4.0)

// RestAPI performs a CourseTable REST call (GET or with a JSON body),
// ported from tools.ts's restApi<T>() helper. cookie is the user's
// CourseTable session cookie; all account-scoped endpoints require it.
func RestAPI(ctx context.Context, cookie, path, method string, body any) (json.RawMessage, error) {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		bodyBytes = b
	}
	if method == "" {
		method = http.MethodGet
	}

	var reqBody io.Reader
	if bodyBytes != nil {
		reqBody = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, APIBase+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Origin", "https://coursetable.com")
	req.Header.Set("User-Agent", "yalie-pp-cli/1.0")

	client := &http.Client{Timeout: 15 * time.Second}
	if err := restAPILimiter.Wait(ctx); err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CourseTable REST request failed: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		restAPILimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(resp)
		resp.Body.Close()
		return nil, &cliutil.RateLimitError{URL: req.URL.String(), RetryAfter: retryAfter}
	}
	restAPILimiter.OnSuccess()
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CourseTable REST response: %w", err)
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication required (HTTP %d); your CourseTable session cookie may have expired — re-authenticate", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("request failed (HTTP %d)", resp.StatusCode)
	}
	return respBody, nil
}

// ValidateCookie checks whether a CourseTable session cookie is currently
// valid by calling /api/user/info, which requires an authenticated session
// (unlike the GraphQL seasons query, which succeeds anonymously too).
// Ported from tools.ts validateCookie().
func ValidateCookie(ctx context.Context, cookie string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/api/user/info", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Origin", "https://coursetable.com")
	req.Header.Set("User-Agent", "yalie-pp-cli/1.0")
	client := &http.Client{Timeout: 10 * time.Second}
	if err := restAPILimiter.Wait(ctx); err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		restAPILimiter.OnRateLimit()
		resp.Body.Close()
		return false
	}
	restAPILimiter.OnSuccess()
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// FriendsWorksheetCourse is one course entry inside a friend's worksheet.
type FriendsWorksheetCourse struct {
	CRN    int     `json:"crn"`
	Color  string  `json:"color"`
	Hidden *bool   `json:"hidden"`
}

// FriendWorksheet is one named worksheet.
type FriendWorksheet struct {
	Name    string                   `json:"name"`
	Courses []FriendsWorksheetCourse `json:"courses"`
}

// Friend is one friend's full worksheet data, keyed by season then worksheet number.
type Friend struct {
	Name       *string                             `json:"name"`
	Worksheets map[string]map[string]FriendWorksheet `json:"worksheets"`
}

// FriendsData is the shape of /api/friends/worksheets.
type FriendsData struct {
	Friends map[string]Friend `json:"friends"`
}

// GetFriendsWorksheets fetches the caller's friends' worksheets.
func GetFriendsWorksheets(ctx context.Context, cookie string) (*FriendsData, error) {
	raw, err := RestAPI(ctx, cookie, "/api/friends/worksheets", http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	var data FriendsData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parsing friends worksheets: %w", err)
	}
	return &data, nil
}

// GetFriendsInCourse returns the display names of friends who have any of
// crns in a worksheet for season_code. Failures are swallowed to an empty
// list, matching tools.ts's getFriendsInCourse() best-effort behavior (it is
// an enrichment on top of get_course / get_course_by_code, not a primary
// data source, and CourseTable's own friends endpoint is documented as
// fragile/best-effort in the research brief).
func GetFriendsInCourse(ctx context.Context, cookie, seasonCode string, crns []int) []string {
	data, err := GetFriendsWorksheets(ctx, cookie)
	if err != nil {
		return []string{}
	}
	crnSet := make(map[int]bool, len(crns))
	for _, c := range crns {
		crnSet[c] = true
	}
	var matches []string
	for _, friend := range data.Friends {
		seasonWorksheets, ok := friend.Worksheets[seasonCode]
		if !ok {
			continue
		}
		inCourse := false
		for _, ws := range seasonWorksheets {
			for _, c := range ws.Courses {
				if crnSet[c.CRN] {
					inCourse = true
					break
				}
			}
			if inCourse {
				break
			}
		}
		if inCourse {
			name := "Unknown"
			if friend.Name != nil {
				name = *friend.Name
			}
			matches = append(matches, name)
		}
	}
	if matches == nil {
		matches = []string{}
	}
	return matches
}

// CatalogMetadata is the shape of /api/catalog/metadata.
type CatalogMetadata struct {
	LastUpdate string `json:"last_update"`
}

// GetCatalogMetadata fetches the CourseTable catalog's last-updated
// timestamp. No authentication required. Ported from tools.ts
// get_catalog_metadata.
func GetCatalogMetadata(ctx context.Context) (*CatalogMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIBase+"/api/catalog/metadata", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Origin", "https://coursetable.com")
	req.Header.Set("User-Agent", "yalie-pp-cli/1.0")
	client := &http.Client{Timeout: 10 * time.Second}
	if err := restAPILimiter.Wait(ctx); err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching catalog metadata: %w", err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		restAPILimiter.OnRateLimit()
		retryAfter := cliutil.RetryAfter(resp)
		resp.Body.Close()
		return nil, &cliutil.RateLimitError{URL: req.URL.String(), RetryAfter: retryAfter}
	}
	restAPILimiter.OnSuccess()
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d fetching catalog metadata", resp.StatusCode)
	}
	var data CatalogMetadata
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("parsing catalog metadata: %w", err)
	}
	return &data, nil
}

// UserInfo is the shape of /api/user/info.
type UserInfo struct {
	NetID     string  `json:"netId"`
	FirstName *string `json:"firstName"`
	LastName  *string `json:"lastName"`
	Email     *string `json:"email"`
	HasEvals  bool    `json:"hasEvals"`
	Year      *int    `json:"year"`
	School    *string `json:"school"`
	Major     *string `json:"major"`
}

// GetUserInfo fetches the authenticated user's Yale profile. Requires a
// CourseTable session cookie. Ported from tools.ts get_user_info.
func GetUserInfo(ctx context.Context, cookie string) (*UserInfo, error) {
	raw, err := RestAPI(ctx, cookie, "/api/user/info", http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	var info UserInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("parsing user info: %w", err)
	}
	return &info, nil
}

// WorksheetCourse is one course entry in the caller's own worksheet.
type WorksheetCourse struct {
	CRN     int     `json:"crn"`
	Color   string  `json:"color"`
	Hidden  *bool   `json:"hidden"`
}

// GetWorksheetsRaw fetches /api/user/worksheets, matching tools.ts
// get_worksheets's raw shape before title/credits enrichment.
func GetWorksheetsRaw(ctx context.Context, cookie string) (map[string]map[string]struct {
	Name    string            `json:"name"`
	Courses []WorksheetCourse `json:"courses"`
}, error) {
	raw, err := RestAPI(ctx, cookie, "/api/user/worksheets", http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Data map[string]map[string]struct {
			Name    string            `json:"name"`
			Courses []WorksheetCourse `json:"courses"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing worksheets: %w", err)
	}
	return wrapper.Data, nil
}

// GetWorksheetCoursesInfo batch-fetches title/credits for a list of CRNs via
// GraphQL, matching tools.ts's GET_WORKSHEET_COURSES_QUERY usage.
func GetWorksheetCoursesInfo(ctx context.Context, cookie string, crns []int) ([]struct {
	Title      string   `json:"title"`
	Credits    *float64 `json:"credits"`
	SeasonCode string   `json:"season_code"`
	Listings   []struct {
		CRN int `json:"crn"`
	} `json:"listings"`
}, error) {
	if len(crns) == 0 {
		return nil, nil
	}
	var out struct {
		Courses []struct {
			Title      string   `json:"title"`
			Credits    *float64 `json:"credits"`
			SeasonCode string   `json:"season_code"`
			Listings   []struct {
				CRN int `json:"crn"`
			} `json:"listings"`
		} `json:"courses"`
	}
	if err := GQL(ctx, cookie, GetWorksheetCoursesQuery, map[string]any{"crns": crns}, &out); err != nil {
		return nil, err
	}
	return out.Courses, nil
}

// WishlistItem is one entry in the caller's wishlist.
type WishlistItem struct {
	Season string `json:"season"`
	CRN    int    `json:"crn"`
}

// GetWishlist fetches /api/user/wishlist. Ported from tools.ts get_wishlist.
func GetWishlist(ctx context.Context, cookie string) ([]WishlistItem, error) {
	raw, err := RestAPI(ctx, cookie, "/api/user/wishlist", http.MethodGet, nil)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Data []WishlistItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing wishlist: %w", err)
	}
	return wrapper.Data, nil
}

// UpdateWorksheetCourse adds/removes/updates a course in a worksheet.
// Ported from tools.ts update_worksheet_course.
func UpdateWorksheetCourse(ctx context.Context, cookie, action, season string, crn, worksheetNumber int, color *string, hidden *bool) error {
	body := map[string]any{
		"action": action, "season": season, "crn": crn, "worksheetNumber": worksheetNumber,
	}
	if color != nil {
		body["color"] = *color
	}
	if hidden != nil {
		body["hidden"] = *hidden
	}
	_, err := RestAPI(ctx, cookie, "/api/user/updateWorksheetCourses", http.MethodPost, body)
	return err
}

// UpdateWishlistCourse adds/removes a course from the wishlist. Ported from
// tools.ts update_wishlist_course.
func UpdateWishlistCourse(ctx context.Context, cookie, action, season string, crn int) error {
	body := map[string]any{"action": action, "season": season, "crn": crn}
	_, err := RestAPI(ctx, cookie, "/api/user/updateWishlistCourses", http.MethodPost, body)
	return err
}

// UpdateWorksheetMetadataResult carries the newly created worksheet number,
// when the server returns one (action == "add").
type UpdateWorksheetMetadataResult struct {
	WorksheetNumber *int `json:"worksheetNumber"`
}

// UpdateWorksheetMetadata creates/deletes/renames a worksheet. Ported from
// tools.ts update_worksheet_metadata.
func UpdateWorksheetMetadata(ctx context.Context, cookie, action, season string, worksheetNumber *int, name *string) (*UpdateWorksheetMetadataResult, error) {
	body := map[string]any{"action": action, "season": season}
	if worksheetNumber != nil {
		body["worksheetNumber"] = *worksheetNumber
	}
	if name != nil {
		body["name"] = *name
	}
	raw, err := RestAPI(ctx, cookie, "/api/user/updateWorksheetMetadata", http.MethodPost, body)
	if err != nil {
		return nil, err
	}
	var result UpdateWorksheetMetadataResult
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &result)
	}
	return &result, nil
}
