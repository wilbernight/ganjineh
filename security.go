package main

// Hardening:
//   - The Authenticator key is shown (console + /setup) only right after it
//     was created or changed, or when started with -show-key, for 15 minutes.
//   - Login guessing: per computer the lock doubles (1, 2, 4 … 60 min) and
//     after too many wrong codes from anywhere all logins from other
//     computers pause for 10 minutes (the server PC itself is never locked).
//   - A login (cookie) only works from the computer that logged in, and ends
//     after sessionIdle without use.
//   - Requests that change something must come from our own page (Origin).
//   - Pages get a strict Content-Security-Policy; API answers are not cached.
//   - Uploads stop when the disk is almost full.

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	sessionIdle   = 2 * time.Hour
	minFreeBytes  = 2 << 30 // keep 2 GB free on the data disk
	globalWindow  = 10 * time.Minute
	globalMaxFail = 40
	globalPause   = 10 * time.Minute
)

var (
	setupUntil time.Time // /setup and the key are visible until then

	gMu        sync.Mutex
	gFails     []time.Time
	gLockUntil time.Time
)

// loginBlocked reports whether ip may not try a code now (and for how long).
func loginBlocked(r *http.Request) (bool, int) {
	ip := clientIP(r)
	now := time.Now()
	if fi := failures[ip]; fi != nil && now.Before(fi.until) { // mu held by caller
		return true, int(time.Until(fi.until).Seconds()) + 1
	}
	if isLoopback(r) {
		return false, 0
	}
	gMu.Lock()
	defer gMu.Unlock()
	if now.Before(gLockUntil) {
		return true, int(time.Until(gLockUntil).Seconds()) + 1
	}
	return false, 0
}

// loginFailed records a wrong code (mu held by caller).
func loginFailed(r *http.Request) {
	ip := clientIP(r)
	f := failures[ip]
	if f == nil {
		f = &failInfo{}
		failures[ip] = f
	}
	f.count++
	if f.count >= 5 {
		f.count = 0
		lock := time.Minute << min(f.level, 6) // 1,2,4,…,64 min
		if lock > time.Hour {
			lock = time.Hour
		}
		f.level++
		f.until = time.Now().Add(lock)
		log.Printf("!! login: 5 wrong codes from %s, locked for %v", ip, lock)
	}
	gMu.Lock()
	defer gMu.Unlock()
	now := time.Now()
	keep := gFails[:0]
	for _, t := range gFails {
		if now.Sub(t) < globalWindow {
			keep = append(keep, t)
		}
	}
	gFails = append(keep, now)
	if len(gFails) >= globalMaxFail && now.After(gLockUntil) {
		gLockUntil = now.Add(globalPause)
		gFails = gFails[:0]
		log.Printf("!! login: %d wrong codes in %v from the network - logins paused for %v (possible attack)", globalMaxFail, globalWindow, globalPause)
	}
}

// sameOrigin: a browser request that changes something must come from our page.
func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	o := r.Header.Get("Origin")
	if o == "" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			return true // non-browser clients (LanUploader) send neither
		}
		o = ref
	}
	if o == "null" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
		"img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self'; connect-src 'self'; object-src 'none'; "+
		"base-uri 'none'; form-action 'self'; frame-ancestors 'self'")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		h.Set("Cache-Control", "no-store")
	}
}

func secureMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w, r)
		if !sameOrigin(r) {
			log.Printf("!! blocked request from another site: %s %s (Origin %q)", r.Method, r.URL.Path, r.Header.Get("Origin"))
			fail(w, http.StatusForbidden, "cross-site request")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// diskOK: false when the data disk has less than minFreeBytes free.
func diskOK() bool {
	free, err := diskFree(dataBase)
	return err != nil || free >= minFreeBytes
}

func diskFullFail(w http.ResponseWriter) {
	fail(w, http.StatusInsufficientStorage, "disk full")
}

func setupOpen() bool { return time.Now().Before(setupUntil) }

func showKeyHint() string {
	return fmt.Sprintf("hidden (to show it and the QR page for 15 minutes: LanFileServer.exe -show-key)")
}
