package main

import (
	"archive/zip"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// handleZip streams a zip of selected items (?path=/dir&n=a&n=b) or of the
// whole folder when no names are given. Files are decrypted on the fly.
func handleZip(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	dir, _, err := resolve(r, q.Get("path"), accRead)
	if err != nil {
		http.Error(w, "not allowed", 403)
		return
	}
	items, err := listDir(dir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if want := q["n"]; len(want) > 0 {
		set := map[string]bool{}
		for _, n := range want {
			set[n] = true
		}
		sel := items[:0]
		for _, it := range items {
			if set[it.Name] {
				sel = append(sel, it)
			}
		}
		items = sel
	}
	zipName := path.Base(path.Clean("/" + strings.ReplaceAll(q.Get("path"), "\\", "/")))
	if zipName == "/" || zipName == "." || zipName == "" {
		zipName = "files"
	}
	if len(q["n"]) == 1 {
		zipName = q["n"][0]
	}
	for _, it := range items {
		if n := decoyIn(it.phys); n != "" {
			decoyHit(r, n, "دانلود zip", q.Get("path"))
		}
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlEscape(zipName+".zip"))

	zw := zip.NewWriter(w)
	defer zw.Close()
	for _, it := range items {
		if addZip(zw, it, it.Name) != nil {
			return
		}
	}
}

func addZip(zw *zip.Writer, it vEntry, rel string) error {
	hdr := &zip.FileHeader{Name: rel, Method: zip.Store, Modified: time.Unix(it.ModTime, 0).In(time.Local)}
	if it.IsDir {
		hdr.Name += "/"
		if _, err := zw.CreateHeader(hdr); err != nil {
			return err
		}
		kids, _ := listDir(it.phys)
		for _, k := range kids {
			if err := addZip(zw, k, rel+"/"+k.Name); err != nil {
				return err
			}
		}
		return nil
	}
	f, _, err := openEncrypted(it.phys)
	if err != nil {
		return nil
	}
	defer f.Close()
	wr, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(wr, f)
	return err
}
