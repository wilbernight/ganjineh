package main

// "Files sent to our unit": anyone on the network can send files from the
// login page without the Authenticator code, giving their personnel code
// (12345 or a12345) and branch code. They can only send, never look.
// Files are filed as  <inbox>/شعبه <branch>/<Jalali date>/<personnel>/...
// Only the admin and the members of the unit the admin picks can open it.
// The box on the login page is shown only after the admin sets a unit name.

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const inboxID = "inbox"

var (
	inboxUnit string // id of the unit whose members may open the inbox ("" = admin only)

	rePersonnel = regexp.MustCompile(`^[a-z]?[0-9]{5}$`)
	reBranch    = regexp.MustCompile(`^[a-z0-9]{1,10}$`)

	sendMu   sync.Mutex
	sendSeen = map[string][]time.Time{} // ip -> recent sends (limit)
)

func inboxRoot() string { return filepath.Join(dataBase, "inbox") }

// canOpenInbox is called with usersMu held.
func canOpenInbox(r *http.Request) bool {
	if isAdmin(r) {
		return true
	}
	if u := userByID(inboxUnit); u != nil && u.Kind == "unit" {
		return u.has(clientIP(r))
	}
	return false
}

// jalali converts a Gregorian date to the Persian (Solar Hijri) calendar.
func jalali(t time.Time) (int, int, int) {
	gy, gmm, gd := t.Date()
	gm := int(gmm)
	gdm := []int{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334}
	gy2 := gy
	if gm > 2 {
		gy2 = gy + 1
	}
	days := 355666 + 365*gy + (gy2+3)/4 - (gy2+99)/100 + (gy2+399)/400 + gd + gdm[gm-1]
	jy := -1595 + 33*(days/12053)
	days %= 12053
	jy += 4 * (days / 1461)
	days %= 1461
	if days > 365 {
		jy += (days - 1) / 365
		days = (days - 1) % 365
	}
	var jm, jd int
	if days < 186 {
		jm, jd = 1+days/31, 1+days%31
	} else {
		jm, jd = 7+(days-186)/30, 1+(days-186)%30
	}
	return jy, jm, jd
}

func normCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= '۰' && c <= '۹':
			b.WriteRune('0' + c - '۰')
		case c >= '٠' && c <= '٩':
			b.WriteRune('0' + c - '٠')
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ensureDirs creates (or reuses) the folders parts below base.
func ensureDirs(base string, parts ...string) (string, error) {
	cur := base
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if !validName(p) {
			return "", fmt.Errorf("invalid name")
		}
		next := filepath.Join(cur, nameID(p))
		if !isDir(next) {
			if err := makeDir(cur, p); err != nil && !isDir(next) {
				return "", err
			}
		}
		cur = next
	}
	return cur, nil
}

func sendAllowed(ip string) bool {
	sendMu.Lock()
	defer sendMu.Unlock()
	now := time.Now()
	ts := sendSeen[ip][:0]
	for _, t := range sendSeen[ip] {
		if now.Sub(t) < time.Hour {
			ts = append(ts, t)
		}
	}
	if len(ts) >= 5000 { // files per hour per computer
		sendSeen[ip] = ts
		return false
	}
	sendSeen[ip] = append(ts, now)
	return true
}

// handleSend: POST /api/send?pc=a12345&br=101&rel=folder/sub  (multipart "file"), no login.
const ownInboxName = "فایل‌های دریافتی از شعب"

func handleSend(w http.ResponseWriter, r *http.Request) {
	usersMu.Lock()
	on := unitTitle != ""
	root, lead := inboxRoot(), []string(nil)
	if c := r.URL.Query().Get("u"); c != "" { // a unit's own send page: into that unit's folder
		on = false
		if u := unitBySend(c); u != nil {
			on, root, lead = true, privRoot(u.ID), []string{ownInboxName}
		}
	}
	usersMu.Unlock()
	if !on {
		fail(w, 404, "not available")
		return
	}
	if r.Method != http.MethodPost || readOnly {
		fail(w, 405, "not allowed")
		return
	}
	q := r.URL.Query()
	pc, br := normCode(q.Get("pc")), normCode(q.Get("br"))
	if !rePersonnel.MatchString(pc) {
		fail(w, 400, "bad personnel code")
		return
	}
	if !reBranch.MatchString(br) {
		fail(w, 400, "bad branch code")
		return
	}
	if !diskOK() {
		diskFullFail(w)
		return
	}
	if !sendAllowed(normIP(clientIP(r))) {
		fail(w, 429, "too many files")
		return
	}
	jy, jm, jd := jalali(time.Now())
	parts := append(lead, "شعبه "+br, fmt.Sprintf("%04d-%02d-%02d", jy, jm, jd), pc)
	if rel := strings.Trim(path.Clean("/"+strings.ReplaceAll(q.Get("rel"), "\\", "/")), "/"); rel != "" {
		parts = append(parts, strings.Split(rel, "/")...)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		fail(w, 500, "cannot create folder")
		return
	}
	dir, err := ensureDirs(root, parts...)
	if err != nil {
		fail(w, 400, "invalid folder name")
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		fail(w, 400, "bad upload")
		return
	}
	count := 0
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		name := filepath.Base(strings.ReplaceAll(part.FileName(), "\\", "/"))
		if part.FormName() != "file" || !validName(name) || junkName(name) {
			part.Close()
			continue
		}
		name = uniqueLogical(dir, name)
		err = writeEncrypted(filepath.Join(dir, nameID(name)), name, part)
		part.Close()
		if err != nil {
			fail(w, 500, "upload failed")
			return
		}
		auditNote(r, name)
		count++
	}
	writeJSON(w, map[string]int{"uploaded": count})
}
