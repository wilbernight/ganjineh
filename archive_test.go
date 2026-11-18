package main

import (
	"archive/zip"
	"bytes"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestListZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range []string{"گزارش/سال ۱۴۰۳/نهایی.pdf", "readme.txt"} {
		w, _ := zw.Create(n)
		w.Write([]byte("x"))
	}
	zw.Close()
	got := names(listZip(bytes.NewReader(buf.Bytes()), int64(buf.Len())))
	want := "readme.txt|گزارش|گزارش/سال ۱۴۰۳|گزارش/سال ۱۴۰۳/نهایی.pdf"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// RAR_FILES=a.rar:b.rar go test -run TestListRarFiles -v   (prints the names)
func TestListRarFiles(t *testing.T) {
	for _, p := range strings.Split(os.Getenv("RAR_FILES"), ":") {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var files []string
		for _, e := range listRar(bytes.NewReader(b), int64(len(b))) {
			if !e.IsDir {
				files = append(files, e.Path)
			}
		}
		sort.Strings(files)
		os.WriteFile(p+".mine.txt", []byte(strings.Join(files, "\n")+"\n"), 0o600)
	}
}

func names(l []archEntry) string {
	var s []string
	for _, e := range l {
		s = append(s, e.Path)
	}
	sort.Strings(s)
	return strings.Join(s, "|")
}
