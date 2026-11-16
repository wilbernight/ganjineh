package main

// withBase serves the app below a URL prefix such as /Temporary_Listen_Addresses
// (Windows' own web server on port 80 only hands that path to programs run
// without admin rights). The prefix is removed before the app sees the path;
// redirects and the absolute links in our HTML pages get it added back.

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
)

func withBase(base string, h http.Handler) http.Handler {
	base = strings.TrimSuffix(base, "/")
	rep := strings.NewReplacer(
		`href="/`, `href="`+base+`/`,
		`src="/`, `src="`+base+`/`,
		`fetch("/`, `fetch("`+base+`/`,
		`api("/`, `api("`+base+`/`,
		`location.href = "/`, `location.href = "`+base+`/`,
		`"/dl" +`, `"`+base+`/dl" +`,
		`x.open("POST", "/`, `x.open("POST", "`+base+`/`,
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if len(p) < len(base) || !strings.EqualFold(p[:len(base)], base) {
			http.NotFound(w, r)
			return
		}
		r2 := *r
		u := *r.URL
		u.Path = p[len(base):]
		if u.Path == "" {
			u.Path = "/"
		}
		if len(u.RawPath) >= len(base) {
			u.RawPath = u.RawPath[len(base):]
		} else {
			u.RawPath = ""
		}
		r2.URL = &u
		bw := &baseWriter{ResponseWriter: w, base: base, rep: rep, code: 200}
		h.ServeHTTP(bw, &r2)
		bw.finish()
	})
}

type baseWriter struct {
	http.ResponseWriter
	base  string
	rep   *strings.Replacer
	wrote bool
	html  bool
	code  int
	buf   bytes.Buffer
}

func (w *baseWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote, w.code = true, code
	h := w.Header()
	if l := h.Get("Location"); strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "//") {
		h.Set("Location", w.base+l)
	}
	if strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		w.html = true // small pages: buffer and fix links in finish
		h.Del("Content-Length")
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *baseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.html {
		return w.buf.Write(p)
	}
	return w.ResponseWriter.Write(p)
}

func (w *baseWriter) finish() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if !w.html {
		return
	}
	out := w.rep.Replace(w.buf.String())
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.ResponseWriter.WriteHeader(w.code)
	w.ResponseWriter.Write([]byte(out))
}
