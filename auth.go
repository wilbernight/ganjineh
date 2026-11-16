package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

const cookieName = "lfs_session"

var (
	totpSecret []byte
	sessionTTL time.Duration

	mu       sync.Mutex
	sessions = map[string]*session{}  // token -> login
	failures = map[string]*failInfo{} // ip -> failures
)

type failInfo struct {
	count int
	level int // how many times this computer was locked (lock doubles)
	until time.Time
}

type session struct {
	exp  time.Time // absolute end
	last time.Time // last use (idle timeout)
	ip   string    // the computer that logged in
}

type config struct {
	Secret string `json:"totpSecret"`
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func secretB32() string { return b32.EncodeToString(totpSecret) }

func otpauthURI() string {
	host, _ := os.Hostname()
	label := url.PathEscape("LAN File Server:" + host)
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		label, secretB32(), url.QueryEscape("LAN File Server"))
}

func totpAt(t int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(t/30))
	m := hmac.New(sha1.New, totpSecret)
	m.Write(buf[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// verifyTOTP accepts the current code and one step before/after (clock drift).
func verifyTOTP(code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	now := time.Now().Unix()
	ok := false
	for _, d := range []int64{-30, 0, 30} {
		if hmac.Equal([]byte(totpAt(now+d)), []byte(code)) {
			ok = true
		}
	}
	return ok
}

func clientIP(r *http.Request) string {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

func isLoopback(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && ip.IsLoopback()
}

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	s, ok := sessions[c.Value]
	if !ok {
		return false
	}
	now := time.Now()
	if now.After(s.exp) || now.Sub(s.last) > sessionIdle {
		delete(sessions, c.Value)
		return false
	}
	if s.ip != normIP(clientIP(r)) { // a copied cookie does not work on another computer
		return false
	}
	s.last = now
	return true
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	ip := clientIP(r)
	mu.Lock()
	if blocked, wait := loginBlocked(r); blocked {
		mu.Unlock()
		fail(w, http.StatusTooManyRequests, fmt.Sprintf("locked:%d", wait))
		return
	}
	mu.Unlock()

	var q struct {
		Code string `json:"code"`
		Name string `json:"name"` // full name (browser login asks for it)
	}
	json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&q)

	if !verifyTOTP(q.Code) {
		mu.Lock()
		loginFailed(r)
		mu.Unlock()
		fail(w, http.StatusUnauthorized, "invalid")
		return
	}

	tok := newToken()
	mu.Lock()
	delete(failures, ip)
	now := time.Now()
	sessions[tok] = &session{exp: now.Add(sessionTTL), last: now, ip: normIP(ip)}
	for k, v := range sessions { // prune expired
		if now.After(v.exp) || now.Sub(v.last) > sessionIdle {
			delete(sessions, k)
		}
	}
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	rememberName(ip, q.Name)
	writeJSON(w, map[string]bool{"ok": true})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleSetup shows the QR code for the authenticator app. Only reachable from the server PC itself.
func handleSetup(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r) {
		http.Error(w, "Setup page is only available on the server computer (http://localhost)", http.StatusForbidden)
		return
	}
	if !setupOpen() {
		http.Error(w, "The Authenticator key is hidden. To show it for 15 minutes, start: LanFileServer.exe -show-key", http.StatusForbidden)
		return
	}
	png, err := qrcode.Encode(otpauthURI(), qrcode.Medium, 320)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	page := strings.NewReplacer(
		"{{QR}}", "data:image/png;base64,"+base64.StdEncoding.EncodeToString(png),
		"{{SECRET}}", groupSecret(secretB32()),
	).Replace(string(setupHTML))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(page))
}

func groupSecret(s string) string {
	var parts []string
	for i := 0; i < len(s); i += 4 {
		e := i + 4
		if e > len(s) {
			e = len(s)
		}
		parts = append(parts, s[i:e])
	}
	return strings.Join(parts, " ")
}

func authMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login", "/s", "/api/login", "/api/brand", "/api/send", "/setup", "/favicon.svg":
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") || strings.HasPrefix(r.URL.Path, "/s/") || isSendCodePath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if validSession(r) {
			noteClient(r)
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fail(w, http.StatusUnauthorized, "login required")
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}
