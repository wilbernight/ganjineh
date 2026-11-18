package main

import "testing"

func TestJunkName(t *testing.T) {
	for n, want := range map[string]bool{
		"~$گزارش.pdf": true, "~$port.docx": true, "Thumbs.db": true, "desktop.ini": true, ".DS_Store": true,
		"گزارش.pdf": false, "$گزارش.pdf": false, "a~$b.pdf": false, "~report.pdf": false,
	} {
		if got := junkName(n); got != want {
			t.Errorf("junkName(%q) = %v, want %v", n, got, want)
		}
	}
}
