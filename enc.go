package main

// Encryption settings page for admins: status, a manual check for files that
// are not encrypted yet, and changing the encryption password (only on the
// server computer itself, and only with the current password).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
)

var (
	plainRunning   atomic.Bool
	plainMu        sync.Mutex
	plainLastStart time.Time
	plainLastEnd   time.Time
	plainLastDone  int
	plainLastBad   int

	pwMu sync.Mutex // one password change at a time
)

// runPlainScan encrypts files that were copied into the shared folder by hand.
// It prints progress every 10 seconds. Only one runs at a time.
func runPlainScan() bool {
	if !plainRunning.CompareAndSwap(false, true) {
		return false
	}
	defer plainRunning.Store(false)
	plainScanned.Store(0)
	plainDone.Store(0)
	plainMu.Lock()
	plainLastStart = time.Now()
	plainMu.Unlock()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				fmt.Printf(" (background) checking for unencrypted files: %d checked, %d encrypted so far...\n", plainScanned.Load(), plainDone.Load())
			}
		}
	}()
	n, bad := encryptPlain(root)
	close(stop)
	plainMu.Lock()
	plainLastEnd, plainLastDone, plainLastBad = time.Now(), n, bad
	plainMu.Unlock()
	if n > 0 || bad > 0 {
		fmt.Printf(" Encrypted %d existing item(s)", n)
		if bad > 0 {
			fmt.Printf(", %d could not be encrypted (still readable!)", bad)
		}
		fmt.Println()
	}
	return true
}

func validNewPassword(p string) string {
	if len(p) < 8 {
		return "too short"
	}
	for _, c := range p {
		if c > unicode.MaxASCII || !unicode.IsPrint(c) {
			return "english only"
		}
	}
	return ""
}

func handleEnc(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		fail(w, http.StatusForbidden, "admin only")
		return
	}
	vp := filepath.Join(dataBase, "vault.json")
	if r.Method == http.MethodGet {
		var v vaultFile
		if b, err := os.ReadFile(vp); err == nil {
			json.Unmarshal(b, &v)
		}
		nameCacheMu.RLock()
		items := len(nameCache)
		nameCacheMu.RUnlock()
		archMu.RLock()
		archs := len(archCache)
		archMu.RUnlock()
		plainMu.Lock()
		st := map[string]any{
			"cipher":     "AES-256-GCM",
			"kdf":        fmt.Sprintf("Argon2id (time %d, memory %d MiB, threads %d)", v.Time, v.Mem/1024, v.Threads),
			"names":      true,
			"items":      items,
			"archives":   archs,
			"running":    plainRunning.Load(),
			"scanned":    plainScanned.Load(),
			"encrypted":  plainDone.Load(),
			"lastStart":  plainLastStart.UnixMilli(),
			"lastEnd":    plainLastEnd.UnixMilli(),
			"lastDone":   plainLastDone,
			"lastBad":    plainLastBad,
			"server":     isServer(r),
			"autostart":  autostartEnabled(dataBase),
			"auditLines": countLines(auditPath(0)) + countLines(auditPath(1)),
			"root":       root,
			"data":       dataBase,
		}
		plainMu.Unlock()
		if fi, err := os.Stat(vp); err == nil {
			st["vaultTime"] = fi.ModTime().UnixMilli()
		}
		writeJSON(w, st)
		return
	}
	if readOnly {
		fail(w, 403, "read-only mode")
		return
	}
	var q struct {
		Op  string `json:"op"`
		Old string `json:"old"`
		New string `json:"new"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&q) != nil {
		fail(w, 400, "bad request")
		return
	}
	switch q.Op {
	case "scan":
		if plainRunning.Load() {
			fail(w, 409, "already running")
			return
		}
		go func() {
			if runPlainScan() {
				warmIndex()
			}
		}()
		auditNote(r, "بررسی فایل‌های رمزنشده")
		writeJSON(w, map[string]bool{"ok": true})
	case "password":
		// changing the password that opens everything: only on the server PC itself
		if !isServer(r) {
			fail(w, 403, "server only")
			return
		}
		auditNote(r, "تغییر رمز رمزگذاری")
		if e := validNewPassword(q.New); e != "" {
			fail(w, 400, e)
			return
		}
		pwMu.Lock()
		defer pwMu.Unlock()
		b, err := os.ReadFile(vp)
		var v vaultFile
		if err != nil || json.Unmarshal(b, &v) != nil {
			fail(w, 500, "vault.json is damaged")
			return
		}
		b64 := base64.StdEncoding
		salt, _ := b64.DecodeString(v.Salt)
		sealed, _ := b64.DecodeString(v.Key)
		mk, err := unseal(passKey(q.Old, &v, salt), sealed, []byte("master"))
		if err != nil {
			time.Sleep(time.Second) // slow down guessing
			fail(w, 400, "wrong password")
			return
		}
		// keep a copy of the old vault until the new one is written
		os.WriteFile(vp+".bak", b, 0o600)
		ns := randBytes(16)
		v.Salt = b64.EncodeToString(ns)
		v.Key = b64.EncodeToString(seal(passKey(q.New, &v, ns), mk, []byte("master")))
		if err := saveVault(vp, &v); err != nil {
			fail(w, 500, "cannot save")
			return
		}
		os.Remove(vp + ".bak")
		auto := ""
		if autostartEnabled(dataBase) { // the saved copy for start-with-Windows must follow
			if err := enableAutostart(dataBase, q.New); err != nil {
				auto = "autostart not updated"
			}
		}
		writeJSON(w, map[string]any{"ok": true, "warn": auto})
	default:
		fail(w, 400, "bad request")
	}
}
