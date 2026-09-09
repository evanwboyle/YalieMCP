// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-written: ports YalieMCP's get_friends_worksheets tool (src/tools.ts) to Cobra.

package cli

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"yalie-pp-cli/internal/yale"
)

func newFriendsCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:         "friends",
		Short:       "Access friends' CourseTable worksheets",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:parent-group": "true"},
		RunE:        parentNoSubcommandRunE(flags),
	}
	cmd.AddCommand(newFriendsWorksheetsCmd(flags))
	return cmd
}

var netIDRE = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

func newFriendsWorksheetsCmd(flags *rootFlags) *cobra.Command {
	var listFriends bool
	var netID, season string
	cmd := &cobra.Command{
		Use:   "worksheets",
		Short: "List friends, or view one friend's worksheet courses",
		Long: "Access friends' CourseTable worksheets. Two modes:\n" +
			"  --list-friends returns all friends' names and netIds\n" +
			"  --net-id <id> returns worksheet courses for a specific friend (--season optional)\n" +
			"Requires COURSETABLE_COOKIE." + deepLinkNote,
		Example: "  yalie-pp-cli friends worksheets --list-friends\n" +
			"  yalie-pp-cli friends worksheets --net-id ab123 --season 202503",
		Annotations: map[string]string{"mcp:read-only": "true", "pp:data-source": "live"},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && cmd.Flags().NFlag() == 0 {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return writeDryRun(cmd.OutOrStdout(), flags, "friends worksheets")
			}
			if !listFriends && netID == "" {
				_ = cmd.Usage()
				return usageErr(fmt.Errorf("either --list-friends or --net-id is required"))
			}
			if netID != "" && !netIDRE.MatchString(netID) {
				return usageErr(fmt.Errorf("--net-id must be alphanumeric"))
			}
			if season != "" && !yale.IsValidSeasonCode(season) {
				return usageErr(fmt.Errorf("--season must be a 6-digit season code"))
			}
			cookie, err := requireCourseTableCookie()
			if err != nil {
				return authErr(err)
			}
			ctx, cancel := boundCtx(cmd.Context(), flags)
			defer cancel()
			data, err := yale.GetFriendsWorksheets(ctx, cookie)
			if err != nil {
				return apiErr(err)
			}

			if listFriends {
				var friendsOut []map[string]any
				for id, f := range data.Friends {
					friendsOut = append(friendsOut, map[string]any{"net_id": id, "name": f.Name})
				}
				return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"count": len(friendsOut), "friends": friendsOut}, flags)
			}

			friend, ok := data.Friends[netID]
			if !ok {
				return notFoundErr(fmt.Errorf("no friend found with net_id %q", netID))
			}
			seasons := friend.Worksheets
			if season != "" {
				if ws, ok := friend.Worksheets[season]; ok {
					seasons = map[string]map[string]yale.FriendWorksheet{season: ws}
				} else {
					seasons = map[string]map[string]yale.FriendWorksheet{}
				}
			}
			var result []map[string]any
			for seasonCode, worksheetMap := range seasons {
				for wsNum, ws := range worksheetMap {
					result = append(result, map[string]any{
						"season": yale.SeasonLabel(seasonCode), "worksheet": wsNum, "name": ws.Name, "courses": ws.Courses,
					})
				}
			}
			if result == nil {
				result = []map[string]any{}
			}
			return printJSONFiltered(cmd.OutOrStdout(), map[string]any{"net_id": netID, "name": friend.Name, "worksheets": result}, flags)
		},
	}
	cmd.Flags().BoolVar(&listFriends, "list-friends", false, "List all friends' names and netIds")
	cmd.Flags().StringVar(&netID, "net-id", "", "Friend's netId to view worksheet courses for")
	cmd.Flags().StringVar(&season, "season", "", "Filter by season code e.g. '202503' (with --net-id)")
	return cmd
}
