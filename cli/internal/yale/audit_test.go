// Copyright 2026 evanwboyle and contributors. Licensed under Apache-2.0. See LICENSE.

package yale

import (
	"reflect"
	"testing"
)

func TestResolveGrade(t *testing.T) {
	cases := []struct {
		name                          string
		letterGrade, numericGrade     string
		passFail, inProgress          bool
		want                          string
	}{
		{"in progress wins", "A", "4.0", false, true, "N/A"},
		{"pass/fail with letter", "P", "", true, false, "P"},
		{"pass/fail without letter", "", "", true, false, "P/F"},
		{"no numeric grade falls back to letter", "B", "", false, false, "B"},
		{"reconstructs A-", "A", "3.7", false, false, "A-"},
		{"reconstructs B+", "B", "3.3", false, false, "B+"},
		{"exact A", "A", "4.0", false, false, "A"},
		{"exact F", "F", "0.0", false, false, "F"},
		{"unmapped numeric falls back to letter", "X", "2.5", false, false, "X"},
		{"unparseable numeric falls back to letter", "C", "not-a-number", false, false, "C"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveGrade(tc.letterGrade, tc.numericGrade, tc.passFail, tc.inProgress)
			if got != tc.want {
				t.Errorf("ResolveGrade(%q,%q,%v,%v) = %q, want %q", tc.letterGrade, tc.numericGrade, tc.passFail, tc.inProgress, got, tc.want)
			}
		})
	}
}

func TestDecodeAttributes(t *testing.T) {
	cases := []struct {
		name  string
		codes []string
		want  []string
	}{
		{"known codes", []string{"YCQR", "YCWR"}, []string{"Quantitative Reasoning", "Writing"}},
		{"unknown code dropped", []string{"YCQR", "ZZZZ"}, []string{"Quantitative Reasoning"}},
		{"empty input", []string{}, []string{}},
		{"all unknown", []string{"ZZZZ"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeAttributes(tc.codes)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("DecodeAttributes(%v) = %v, want %v", tc.codes, got, tc.want)
			}
		})
	}
}

func TestComputeRuleStatus(t *testing.T) {
	yes := "Y"
	cases := []struct {
		name string
		rule Rule
		want RuleStatus
	}{
		{"explicit complete", Rule{Requirement: &struct {
			RuleComplete string `json:"ruleComplete"`
		}{RuleComplete: yes}}, StatusComplete},
		{"percent 100", Rule{PercentComplete: "100"}, StatusComplete},
		{"in progress", Rule{PercentComplete: "50", InProgressIncomplete: "Y"}, StatusInProgress},
		{"incomplete", Rule{PercentComplete: "0"}, StatusIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ComputeRuleStatus(tc.rule); got != tc.want {
				t.Errorf("ComputeRuleStatus(%+v) = %q, want %q", tc.rule, got, tc.want)
			}
		})
	}
}

func TestComputeBlockStatus(t *testing.T) {
	cases := []struct {
		pct  string
		want RuleStatus
	}{
		{"100", StatusComplete},
		{"100.0", StatusComplete},
		{"50", StatusInProgress},
		{"0", StatusIncomplete},
		{"", StatusIncomplete},
	}
	for _, tc := range cases {
		if got := ComputeBlockStatus(tc.pct); got != tc.want {
			t.Errorf("ComputeBlockStatus(%q) = %q, want %q", tc.pct, got, tc.want)
		}
	}
}

func TestFlattenRules(t *testing.T) {
	rules := []Rule{
		{
			Label:           "Top Level",
			PercentComplete: "100",
			RuleArray: []Rule{
				{Label: "Nested A", PercentComplete: "0"},
				{Label: "Nested B", PercentComplete: "50", InProgressIncomplete: "Y"},
			},
		},
	}
	got := FlattenRules(rules, 0)
	want := []FlatRule{
		{Indent: 0, Label: "Top Level", Status: StatusComplete},
		{Indent: 1, Label: "Nested A", Status: StatusIncomplete},
		{Indent: 1, Label: "Nested B", Status: StatusInProgress},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FlattenRules() = %+v, want %+v", got, want)
	}
}
