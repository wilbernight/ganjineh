package main

// Search across every folder the client may open, and moving items between
// folders.
//
// Names are encrypted on disk, so finding a file by name means reading each
// item's header. nameCache keeps the real names in memory (keyed by the
// on-disk path plus its size and time), so after the first walk a search only
// lists folders and never opens files again.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

/* ---------- name cache ---------- */

type cachedName struct {
	name  string
	size  int64
	mtime int64 // on-disk time; for files it is part of the cache key
	fsize int64 // on-disk size, part of the cache key
	decoy bool  // honeypot file (decoy.go)
}

var (
	nameCacheMu sync.RWMutex
	nameCache   = map[string]cachedName{}
)

// itemInfo returns the real name (and size for files) of one encrypted item.
// fi is the on-disk info of p.
func itemInfo(p string, fi os.FileInfo) (string, int64, bool) {
	isD := fi.IsDir()
	nameCacheMu.RLock()
	c, ok := nameCache[p]
	nameCacheMu.RUnlock()
	if ok && (isD || (c.mtime == fi.ModTime().UnixNano() && c.fsize == fi.Size())) {
		return c.name, c.size, true
	}
	var n string
	var sz int64
	var dec bool
	if isD {
		var err error
		if n, err = readDirName(p); err != nil {
			return "", 0, false
		}
	} else {
		f, err := os.Open(p)
		if err != nil {
			return "", 0, false
		}
		m, err := readHeader(f)
		f.Close()
		if err != nil {
			return "", 0, false
		}
		n, sz, dec = m.Name, m.Size, m.Decoy
	}
	nameCacheMu.Lock()
	if len(nameCache) > 2_000_000 { // safety valve; it refills on the next walk
		nameCache = map[string]cachedName{}
	}
	nameCache[p] = cachedName{n, sz, fi.ModTime().UnixNano(), fi.Size(), dec}
	nameCacheMu.Unlock()
	return n, sz, true
}

// forgetTree drops cached names at or below p (after a move or delete).
func forgetTree(p string) {
	pre := p + string(filepath.Separator)
	nameCacheMu.Lock()
	for k := range nameCache {
		if k == p || strings.HasPrefix(k, pre) {
			delete(nameCache, k)
		}
	}
	nameCacheMu.Unlock()
}

// warmIndex reads every name once in the background so the first search is fast.
func warmIndex() {
	t0 := time.Now()
	n, na, inner := 0, 0, 0
	for _, d := range []string{root, filepath.Join(dataBase, "private"), inboxRoot()} {
		walkSpace(context.Background(), d, "", func(it wItem) bool {
			n++
			if !it.isDir && archKind(it.name) != "" {
				na++
				inner += len(archiveEntries(it.phys, it.name, it.fi))
			}
			return true
		})
	}
	log.Printf("search index ready: %d items, %d zip/rar files with %d names inside, in %s", n, na, inner, time.Since(t0).Round(time.Millisecond))
}

// wItem is one item found by walkSpace.
type wItem struct {
	rel, name   string // logical path ("/a/b.txt" below the walk root) and real name
	isDir       bool
	size, mtime int64
	phys        string
	fi          os.FileInfo
}

// walkSpace calls fn for every item below dir. rel is the logical path of dir
// ("" for a space root). fn returns false to stop.
func walkSpace(ctx context.Context, dir, rel string, fn func(wItem) bool) bool {
	des, err := os.ReadDir(dir)
	if err != nil {
		return true
	}
	for _, d := range des {
		if ctx.Err() != nil {
			return false
		}
		if !idRe.MatchString(d.Name()) {
			continue
		}
		p := filepath.Join(dir, d.Name())
		fi, err := d.Info()
		if err != nil {
			continue
		}
		name, size, ok := itemInfo(p, fi)
		if !ok {
			continue
		}
		r := rel + "/" + name
		if !fn(wItem{r, name, fi.IsDir(), size, fi.ModTime().Unix(), p, fi}) {
			return false
		}
		if fi.IsDir() && !walkSpace(ctx, p, r, fn) {
			return false
		}
	}
	return true
}

/* ---------- matching ---------- */

// fold makes the search key: lower case, one form of the Persian/Arabic
// letters, Latin digits, no diacritics, ZWNJ or tatweel, and separators as
// single spaces. It matches nz() in index.html.
func fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := true // drop leading spaces
	for _, r := range s {
		switch {
		case r == 'ي' || r == 'ى' || r == 'ی' || r == 'ې':
			r = 'ی'
		case r == 'ك' || r == 'ک':
			r = 'ک'
		case r == 'ة' || r == 'ۀ' || r == 'ہ' || r == 'ە':
			r = 'ه'
		case r == 'آ' || r == 'أ' || r == 'إ' || r == 'ٱ':
			r = 'ا'
		case r == 'ؤ':
			r = 'و'
		case r >= '۰' && r <= '۹':
			r = '0' + (r - '۰')
		case r >= '٠' && r <= '٩':
			r = '0' + (r - '٠')
		case (r >= 0x064B && r <= 0x065F) || r == 0x0670 || r == 0x0640 || r == 0x200C || r == 0x200D ||
			r == 0x200E || r == 0x200F || (r >= 0x202A && r <= 0x202E):
			continue
		case unicode.IsSpace(r) || r == '_' || r == '-' || r == '.' || r == '(' || r == ')' || r == '[' || r == ']' || r == ',':
			if !space {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		b.WriteRune(unicode.ToLower(r))
		space = false
	}
	return strings.TrimRight(b.String(), " ")
}

type query struct {
	raw    string // folded
	nosp   string // folded, without spaces
	tokens []string
}

func newQuery(s string) query {
	f := fold(s)
	return query{f, strings.ReplaceAll(f, " ", ""), strings.Fields(f)}
}

// wordStart reports whether sub starts a word in s at index i.
func wordStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	c, _ := utf8.DecodeRuneInString(s[i:])
	return r == ' ' || (unicode.IsDigit(r) != unicode.IsDigit(c))
}

// fuzzy: all runes of q appear in s in order; returns the number of gaps
// (fewer = closer), or -1.
func fuzzy(s, q string) int {
	gaps, run := 0, false
	qi := 0
	qr := []rune(q)
	for _, r := range s {
		if qi < len(qr) && r == qr[qi] {
			qi++
			run = true
		} else if run {
			gaps++
			run = false
		}
	}
	if qi < len(qr) {
		return -1
	}
	return gaps
}

// score ranks one item; 0 = no match. name and dir are folded.
func (q query) score(name, dir string) int {
	if q.raw == "" {
		return 0
	}
	switch i := strings.Index(name, q.raw); {
	case name == q.raw:
		return 1000
	case i == 0:
		return 900
	case i > 0 && wordStart(name, i):
		return 800
	case i > 0:
		return 650
	}
	if q.nosp != "" && strings.Contains(strings.ReplaceAll(name, " ", ""), q.nosp) {
		return 600
	}
	// every word somewhere in the name (any order) ...
	inName, starts := 0, 0
	for _, t := range q.tokens {
		if i := strings.Index(name, t); i >= 0 {
			inName++
			if wordStart(name, i) {
				starts++
			}
		}
	}
	if inName == len(q.tokens) {
		s := 500 + 10*starts
		for i := 0; i+1 < len(q.tokens); i++ { // words next to each other, in the typed order
			if strings.Contains(name, q.tokens[i]+" "+q.tokens[i+1]) {
				s += 25
			}
		}
		return s
	}
	// ... or in the name plus the folders above it ("report 1403" finds 1403/report.pdf)
	if len(q.tokens) > 1 && inName > 0 {
		all := true
		for _, t := range q.tokens {
			if !strings.Contains(name, t) && !strings.Contains(dir, t) {
				all = false
				break
			}
		}
		if all {
			return 350 + 20*inName
		}
	}
	// typo-tolerant: letters in order (only for queries of 3+ letters)
	if utf8.RuneCountInString(q.nosp) >= 3 {
		if g := fuzzy(strings.ReplaceAll(name, " ", ""), q.nosp); g >= 0 && g <= 3 {
			return 200 - 30*g
		}
	}
	// one wrong, missing, extra or swapped letter in each word of 4+ letters
	words := strings.Fields(name)
	for _, t := range q.tokens {
		tr := []rune(t)
		ok := false
		for _, w := range words {
			if strings.Contains(w, t) || (len(tr) >= 4 && near([]rune(w), tr)) {
				ok = true
				break
			}
		}
		if !ok {
			return 0
		}
	}
	return 150
}

// near: a and b differ by at most one edit (Damerau-Levenshtein distance <= 1).
func near(a, b []rune) bool {
	if d := len(a) - len(b); d > 1 || d < -1 {
		return false
	}
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	if i == len(a) && i == len(b) {
		return true
	}
	eq := func(x, y []rune) bool { return string(x) == string(y) }
	switch {
	case len(a) == len(b):
		return eq(a[i+1:], b[i+1:]) || // substitution
			(i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && eq(a[i+2:], b[i+2:])) // swap
	case len(a) > len(b):
		return eq(a[i+1:], b[i:])
	default:
		return eq(a[i:], b[i+1:])
	}
}

/* ---------- /api/search ---------- */

type hit struct {
	Path  string `json:"path"` // full client path of the item
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
	Inner string `json:"inner,omitempty"` // set when the item is inside the .zip/.rar at Path
	score int
}

type searchRoot struct {
	phys, client string // client: "" for shared, "/:id" for a private space
}

// searchRoots lists the spaces this client may read.
func searchRoots(r *http.Request) []searchRoot {
	out := []searchRoot{{root, ""}}
	usersMu.Lock()
	defer usersMu.Unlock()
	for i := range users {
		if canOpenSpace(r, &users[i]) {
			out = append(out, searchRoot{privRoot(users[i].ID), "/:" + users[i].ID})
		}
	}
	if canOpenInbox(r) {
		out = append(out, searchRoot{inboxRoot(), "/:" + inboxID})
	}
	return out
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	q := newQuery(r.URL.Query().Get("q"))
	if q.raw == "" {
		writeJSON(w, map[string]any{"results": []hit{}})
		return
	}
	limit := 200
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 && n < 1000 {
		limit = n
	}
	kind := r.URL.Query().Get("type")            // "", "folder" or "file"
	withArch := r.URL.Query().Get("arch") != "0" // also names inside .zip/.rar files
	var roots []searchRoot
	if p := r.URL.Query().Get("path"); p != "" && p != "/" || r.URL.Query().Get("here") != "" {
		// only below one folder
		full, _, err := resolve(r, p, accRead)
		if err != nil {
			resolveFail(w, err)
			return
		}
		roots = []searchRoot{{full, strings.TrimSuffix(path.Clean("/"+p), "/")}}
	} else {
		roots = searchRoots(r)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	var hits []hit
	scanned := 0
	for _, sr := range roots {
		walkSpace(ctx, sr.phys, "", func(it wItem) bool {
			scanned++
			add := func(name, dirPath string, isDir bool, size, mtime int64, inner string, penalty int) {
				if (kind == "folder" && !isDir) || (kind == "file" && isDir) {
					return
				}
				fn := fold(name)
				s := q.score(fn, fold(dirPath))
				if s == 0 {
					return
				}
				// small nudges: shallow items and folders first, short names
				s -= strings.Count(dirPath, "/")*3 + penalty
				if isDir {
					s += 5
				}
				s -= utf8.RuneCountInString(fn) / 8
				hits = append(hits, hit{sr.client + it.rel, name, isDir, size, mtime, inner, s})
			}
			add(it.name, path.Dir(it.rel), it.isDir, it.size, it.mtime, "", 0)
			if withArch && !it.isDir && archKind(it.name) != "" {
				for _, e := range archiveEntries(it.phys, it.name, it.fi) {
					scanned++
					mt := e.MTime
					if mt <= 0 {
						mt = it.mtime
					}
					// names inside an archive rank a little below real files
					add(path.Base(e.Path), it.rel+"/"+path.Dir(e.Path), e.IsDir, e.Size, mt, e.Path, 15)
				}
			}
			return true
		})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		if hits[i].MTime != hits[j].MTime {
			return hits[i].MTime > hits[j].MTime
		}
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].Inner < hits[j].Inner
	})
	total := len(hits)
	if total > limit {
		hits = hits[:limit]
	}
	if hits == nil {
		hits = []hit{}
	}
	writeJSON(w, map[string]any{
		"results":  hits,
		"total":    total,
		"scanned":  scanned,
		"ms":       time.Since(t0).Milliseconds(),
		"complete": ctx.Err() == nil,
	})
}

/* ---------- /api/move ---------- */

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(v)
}

type moveReq struct {
	Paths []string `json:"paths"`
	Dest  string   `json:"dest"`
}

// handleMove moves files/folders into another folder (any space the client
// may write to). Names that already exist there get " (1)" etc.
func handleMove(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	var q moveReq
	if err := decodeJSON(r, &q); err != nil || len(q.Paths) == 0 || len(q.Paths) > 5000 {
		fail(w, 400, "bad request")
		return
	}
	dest, _, err := resolve(r, q.Dest, accWrite)
	if errors.Is(err, errForbidden) {
		resolveFail(w, err)
		return
	}
	if err != nil || !isDir(dest) {
		fail(w, 400, "folder not found")
		return
	}
	if !diskOK() {
		diskFullFail(w)
		return
	}
	moved, skipped := 0, 0
	var firstErr string
	sep := string(filepath.Separator)
	for _, p := range q.Paths {
		src, sr, err := resolve(r, p, accModify)
		if err != nil || src == sr || !exists(src) {
			if firstErr == "" {
				if errors.Is(err, errForbidden) {
					firstErr = "private folder"
				} else {
					firstErr = "not found"
				}
			}
			continue
		}
		if filepath.Dir(src) == dest { // already there
			skipped++
			continue
		}
		if dest == src || strings.HasPrefix(dest+sep, src+sep) {
			if firstErr == "" {
				firstErr = "cannot move a folder into itself"
			}
			continue
		}
		if n := decoyIn(src); n != "" {
			decoyHit(r, n, "انتقال به "+q.Dest, path.Dir(p))
		}
		name, _, err := itemName(src)
		if err != nil {
			if firstErr == "" {
				firstErr = "cannot move"
			}
			continue
		}
		// a free name in the destination that is also free next to the source
		nn := name
		if exists(filepath.Join(dest, nameID(nn))) {
			ext := filepath.Ext(name)
			b := strings.TrimSuffix(name, ext)
			for i := 1; ; i++ {
				nn = b + " (" + strconv.Itoa(i) + ")" + ext
				if !exists(filepath.Join(dest, nameID(nn))) && !exists(filepath.Join(filepath.Dir(src), nameID(nn))) {
					break
				}
			}
			if err := renameItem(src, nn); err != nil {
				if firstErr == "" {
					firstErr = "cannot move"
				}
				continue
			}
			forgetTree(src)
			src = filepath.Join(filepath.Dir(src), nameID(nn))
		}
		if err := moveItem(src, filepath.Join(dest, nameID(nn))); err != nil {
			log.Printf("move %q -> %q: %v", p, q.Dest, err)
			if firstErr == "" {
				firstErr = "cannot move"
			}
			continue
		}
		forgetTree(src)
		moved++
	}
	if moved == 0 && skipped == 0 && firstErr != "" {
		fail(w, 400, firstErr)
		return
	}
	writeJSON(w, map[string]any{"moved": moved, "skipped": skipped, "failed": len(q.Paths) - moved - skipped, "error": firstErr})
}
