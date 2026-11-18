package main

import "testing"

func TestFold(t *testing.T) {
	cases := map[string]string{
		"گزارش‌های مالی":     "گزارشهای مالی", // ZWNJ removed
		"نهايي":              "نهایی",         // Arabic yeh
		"كتاب":               "کتاب",          // Arabic kaf
		"سال ۱۴۰۳":           "سال 1403",      // Persian digits
		"Budget_Report-2024": "budget report 2024",
		"  a..b  ":           "a b",
	}
	for in, want := range cases {
		if got := fold(in); got != want {
			t.Errorf("fold(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScore(t *testing.T) {
	type c struct {
		q, name, dir string
		match        bool
	}
	for _, x := range []c{
		{"گزارش", "گزارش نهایی.pdf", "", true},
		{"نهایی", "گزارش نهايي.pdf", "", true},
		{"budget report", "Budget_Report-2024.xlsx", "", true},
		{"report budget", "Budget_Report-2024.xlsx", "", true}, // any order
		{"bdgt", "Budget_Report-2024.xlsx", "", true},          // letters in order
		{"1403", "سال ۱۴۰۳", "", true},
		{"حسابدرای", "حسابداری", "", true},                       // swapped letters
		{"گزارش عمیق", "گزارش نهایی.pdf", "/بایگانی/عمیق", true}, // one word in a parent folder
		{"عمیق بایگانی", "نهایی.pdf", "/بایگانی/عمیق", false},    // no word in the name itself
		{"zzz", "notes.txt", "", false},
	} {
		q := newQuery(x.q)
		if got := q.score(fold(x.name), fold(x.dir)) > 0; got != x.match {
			t.Errorf("score(%q, %q) match=%v, want %v", x.q, x.name, got, x.match)
		}
	}
	// exact order ranks above the same words scattered
	q := newQuery("سند 12-3-7")
	a, b := q.score(fold("سند شماره 12-3-7"), ""), q.score(fold("سند شماره 7-3-12"), "")
	if a <= b {
		t.Errorf("ordered %d <= scattered %d", a, b)
	}
	// exact name first
	q = newQuery("notes")
	if q.score("notes", "") <= q.score("notes 2", "") {
		t.Error("exact name should rank first")
	}
}
