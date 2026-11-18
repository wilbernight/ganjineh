package main

// Activity log (who did what) and alerts for the admins.
//
// Every entry is sealed with a key from the master key before it is written,
// so file names in the log are as protected as the files themselves.
// Each line of audit.log is base64(seal(json)). When the file passes
// auditMax it is renamed to audit.1.log (the older one is dropped).
//
// auditMW writes one entry per action after the handler has run, from the
// URL, the JSON body and the status. Handlers can add detail with auditNote.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const auditMax = 20 << 20 // bytes per log file

var (
	auditKey  []byte
	auditMu   sync.Mutex
	auditFile *os.File

	alertMu   sync.Mutex
	alertList []auditEntry         // newest last, kept in memory for the admins' pages
	alertSeen = map[string]int64{} // ip+kind -> last alert time (no repeats within 10 min)
	alertsOff bool
)

type auditEntry struct {
	T      int64  `json:"t"`
	IP     string `json:"ip"`
	Who    string `json:"who,omitempty"`
	Act    string `json:"act"`
	Path   string `json:"path,omitempty"`
	Detail string `json:"detail,omitempty"`
	OK     bool   `json:"ok"`
	Alert  string `json:"alert,omitempty"` // set for alerts: "unknown-ip", "locked"
}

func auditPath(n int) string {
	if n == 0 {
		return filepath.Join(dataBase, "audit.log")
	}
	return filepath.Join(dataBase, "audit.1.log")
}

func alertCfgPath() string { return filepath.Join(dataBase, "alerts.json") }

// loadAudit reads the alert setting and the recent alerts (at startup).
func loadAudit() {
	if b, err := os.ReadFile(alertCfgPath()); err == nil {
		var c struct{ Off bool }
		if json.Unmarshal(b, &c) == nil {
			alertsOff = c.Off
		}
	}
	var al []auditEntry
	readAudit(func(e auditEntry) bool {
		if e.Alert != "" {
			al = append(al, e)
		}
		return true
	})
	slices.Reverse(al) // readAudit gives newest first
	if len(al) > 300 {
		al = al[len(al)-300:]
	}
	alertMu.Lock()
	alertList = al
	alertMu.Unlock()
}

func writeAudit(e auditEntry) {
	if auditKey == nil {
		return
	}
	b, _ := json.Marshal(e)
	line := base64.StdEncoding.EncodeToString(seal(auditKey, b, []byte("audit"))) + "\n"
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditFile != nil {
		if st, err := auditFile.Stat(); err == nil && st.Size() > auditMax {
			auditFile.Close()
			auditFile = nil
			os.Rename(auditPath(0), auditPath(1))
		}
	}
	if auditFile == nil {
		f, err := os.OpenFile(auditPath(0), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		auditFile = f
	}
	auditFile.WriteString(line)
}

// readAudit calls fn for every entry, newest first, until fn returns false.
func readAudit(fn func(auditEntry) bool) {
	auditMu.Lock()
	var files [][]byte
	for _, n := range []int{0, 1} {
		if b, err := os.ReadFile(auditPath(n)); err == nil {
			files = append(files, b)
		}
	}
	auditMu.Unlock()
	for _, data := range files {
		lines := bytes.Split(data, []byte("\n"))
		for i := len(lines) - 1; i >= 0; i-- {
			if len(lines[i]) == 0 {
				continue
			}
			ct, err := base64.StdEncoding.DecodeString(string(lines[i]))
			if err != nil {
				continue
			}
			pt, err := unseal(auditKey, ct, []byte("audit"))
			if err != nil {
				continue
			}
			var e auditEntry
			if json.Unmarshal(pt, &e) == nil && !fn(e) {
				return
			}
		}
	}
}

/* ---------- who is it ---------- */

// actor names the computer: its registered name, else the name typed at login.
func actor(r *http.Request) (ip, who string) {
	ip = normIP(clientIP(r))
	if isServer(r) {
		return ip, "خود سرور"
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	if u := userByIP(ip); u != nil {
		return ip, u.Name
	}
	if n := ipNames[ip]; n != "" {
		return ip, n + " (نام واردشده)"
	}
	return ip, ""
}

// knownIP: the server, an admin computer, a registered computer or a unit member.
func knownIP(r *http.Request) bool {
	if isAdmin(r) {
		return true
	}
	ip := normIP(clientIP(r))
	usersMu.Lock()
	defer usersMu.Unlock()
	for i := range users {
		if users[i].has(ip) {
			return true
		}
	}
	return false
}

func raiseAlert(r *http.Request, kind, act, detail string) {
	ip, who := actor(r)
	raiseAlertAs(ip, who, kind, ip+kind, 600, act, detail)
}

// raiseAlertAs records an alert unless the same key fired within quiet seconds.
func raiseAlertAs(ip, who, kind, key string, quiet int64, act, detail string) {
	alertMu.Lock()
	if (alertsOff && kind != "decoy") || time.Now().Unix()-alertSeen[key] < quiet { // decoy alerts cannot be turned off
		alertMu.Unlock()
		return
	}
	alertSeen[key] = time.Now().Unix()
	e := auditEntry{T: time.Now().UnixMilli(), IP: ip, Who: who, Act: act, Detail: detail, Alert: kind}
	alertList = append(alertList, e)
	if len(alertList) > 300 {
		alertList = alertList[len(alertList)-300:]
	}
	alertMu.Unlock()
	writeAudit(e)
	fmt.Printf(" !! ALERT %s: %s from %s %s - %s\n", time.Now().Format("15:04:05"), act, ip, who, detail)
}

/* ---------- middleware ---------- */

type auditKeyT struct{}

type auditCtx struct{ notes []string }

// auditNote adds detail (e.g. uploaded file names) to this request's entry.
func auditNote(r *http.Request, s string) {
	if c, ok := r.Context().Value(auditKeyT{}).(*auditCtx); ok && len(c.notes) < 200 {
		c.notes = append(c.notes, s)
	}
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) {
	if s.code == 0 {
		s.code = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = 200
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

var auditActs = map[string]string{
	"/api/login": "ورود", "/logout": "خروج", "/api/upload": "آپلود", "/api/mkdir": "ساخت پوشه",
	"/api/delete": "حذف (به سطل زباله)", "/api/rename": "تغییر نام", "/api/move": "انتقال",
	"/api/zip": "دانلود zip", "/api/archive-file": "دانلود از داخل فایل فشرده", "/api/trash": "سطل زباله",
	"/api/users": "تنظیمات", "/api/send": "ارسال از صفحه‌ی ارسال", "/api/enc": "تنظیمات رمزگذاری", "/api/alerts": "تنظیم هشدارها", "/api/decoys": "طعمه‌ها",
}

func auditMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		act, ok := auditActs[r.URL.Path]
		dl := strings.HasPrefix(r.URL.Path, "/dl/")
		if dl {
			// real downloads only: not previews/thumbnails (?view=1) and not the later parts of one download
			rg := r.Header.Get("Range")
			ok = r.URL.Query().Get("view") == "" && (rg == "" || strings.HasPrefix(rg, "bytes=0-"))
			act = "دانلود"
		}
		if !ok || (r.Method == http.MethodGet && !dl && r.URL.Path != "/api/zip" && r.URL.Path != "/api/archive-file" && r.URL.Path != "/logout") {
			next.ServeHTTP(w, r)
			return
		}
		var body []byte
		if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		c := &auditCtx{}
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), auditKeyT{}, c)))
		if sw.code == 0 {
			sw.code = 200
		}
		e := auditEntry{T: time.Now().UnixMilli(), Act: act, OK: sw.code < 300}
		e.IP, e.Who = actor(r)
		q := r.URL.Query()
		var j struct {
			Path, Name, Dest, Op, ID, Kind string
			Paths, IPs, IDs                []string
			Days                           *int
			Off                            *bool
		}
		json.Unmarshal(body, &j)
		switch {
		case dl:
			e.Path = strings.TrimPrefix(r.URL.Path, "/dl")
		case r.URL.Path == "/api/login":
			if !e.OK {
				e.Act = "ورود ناموفق (کد اشتباه)"
				if sw.code == http.StatusTooManyRequests {
					e.Act = "ورود ناموفق (قفل شده)"
				}
			}
		case r.URL.Path == "/api/upload", r.URL.Path == "/api/zip":
			e.Path = q.Get("path")
			e.Detail = strings.Join(append(q["n"], c.notes...), "، ")
		case r.URL.Path == "/api/archive-file":
			e.Path, e.Detail = q.Get("path"), q.Get("inner")
		case r.URL.Path == "/api/mkdir":
			e.Path = strings.TrimSuffix(j.Path, "/") + "/" + j.Name
		case r.URL.Path == "/api/rename":
			e.Path, e.Detail = j.Path, "← "+j.Name
		case r.URL.Path == "/api/move":
			e.Path, e.Detail = strings.Join(j.Paths, "، "), "به "+j.Dest
		case r.URL.Path == "/api/trash":
			e.Detail = map[string]string{"restore": "بازیابی", "purge": "حذف برای همیشه", "empty": "خالی کردن سطل", "days": "تغییر پاک شدن خودکار"}[j.Op] + " " + strings.Join(c.notes, "، ")
		case r.URL.Path == "/api/send":
			e.Detail = strings.Join(c.notes, "، ")
		default:
			e.Path = j.Path
			d := j.Op
			if j.Name != "" {
				d += " " + j.Name
			}
			if len(j.IPs) > 0 {
				d += " " + strings.Join(j.IPs, ",")
			}
			e.Detail = strings.TrimSpace(d + " " + strings.Join(c.notes, "، "))
		}
		writeAudit(e)
		if r.URL.Path == "/api/login" {
			switch {
			case e.OK && !knownIP(r):
				raiseAlert(r, "unknown-ip", "ورود موفق از IP ناشناس", "این IP به هیچ سیستم، واحد یا مدیری تعلق ندارد")
			case sw.code == http.StatusTooManyRequests || (!e.OK && !knownIP(r)):
				raiseAlert(r, "failed", "تلاش ناموفق برای ورود", "کد ورود اشتباه وارد شد")
			}
		}
	})
}

/* ---------- admin pages ---------- */

// GET /api/audit?q=&who=&act=&before=<ms>&limit=  (admins)  &csv=1 downloads a CSV
func handleAudit(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		fail(w, http.StatusForbidden, "admin only")
		return
	}
	qv := r.URL.Query()
	q := fold(qv.Get("q"))
	who, act := qv.Get("who"), qv.Get("act")
	before, _ := strconv.ParseInt(qv.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(qv.Get("limit"))
	asCSV := qv.Get("csv") != ""
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if asCSV {
		limit = 1 << 30
	}
	var out []auditEntry
	people := map[string]string{}
	acts := map[string]bool{}
	more := false
	readAudit(func(e auditEntry) bool {
		if len(people) < 500 {
			people[e.IP] = e.Who
		}
		acts[e.Act] = true
		if before > 0 && e.T >= before {
			return true
		}
		if (who != "" && e.IP != who) || (act != "" && e.Act != act) {
			return true
		}
		if q != "" && !strings.Contains(fold(e.Who+" "+e.IP+" "+e.Act+" "+e.Path+" "+e.Detail), q) {
			return true
		}
		if len(out) >= limit {
			more = true
			return len(people) < 500 // keep reading only to list the people
		}
		out = append(out, e)
		return true
	})
	if asCSV {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=activity-"+time.Now().Format("2006-01-02")+".csv")
		w.Write([]byte("\xef\xbb\xbf")) // BOM so Excel reads Persian
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "ip", "who", "action", "path", "detail", "ok", "alert"})
		for _, e := range out {
			cw.Write([]string{time.UnixMilli(e.T).Format("2006-01-02 15:04:05"), e.IP, e.Who, e.Act, e.Path, e.Detail, strconv.FormatBool(e.OK), e.Alert})
		}
		cw.Flush()
		return
	}
	if out == nil {
		out = []auditEntry{}
	}
	al := make([]string, 0, len(acts))
	for a := range acts {
		al = append(al, a)
	}
	slices.Sort(al)
	writeJSON(w, map[string]any{"items": out, "more": more, "people": people, "acts": al})
}

// GET /api/alerts?since=<ms> (admins): alerts after since.
// POST /api/alerts {"off": bool}: turn alerts off/on.
func handleAlerts(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		fail(w, http.StatusForbidden, "admin only")
		return
	}
	if r.Method == http.MethodPost {
		var q struct {
			Off bool `json:"off"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&q) != nil {
			fail(w, 400, "bad request")
			return
		}
		alertMu.Lock()
		alertsOff = q.Off
		alertMu.Unlock()
		b, _ := json.Marshal(map[string]bool{"Off": q.Off})
		os.WriteFile(alertCfgPath(), b, 0o600)
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	alertMu.Lock()
	var out []auditEntry
	for i := len(alertList) - 1; i >= 0 && len(out) < 100; i-- {
		if alertList[i].T > since {
			out = append(out, alertList[i])
		}
	}
	off := alertsOff
	alertMu.Unlock()
	if out == nil {
		out = []auditEntry{}
	}
	writeJSON(w, map[string]any{"items": out, "off": off, "now": time.Now().UnixMilli()})
}

// countLines is used by the encryption page (rough size of the log).
func countLines(p string) int {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		n++
	}
	return n
}
