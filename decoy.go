package main

// Honeypots ("طعمه"): three fake files that look like secrets - a database
// backup, a .env file and a list of cloud API keys. Nobody has a reason to
// open them, so any touch (download, preview, zip, FTP, rename, move, delete)
// raises an immediate alert for the admins.
//
// A decoy is an ordinary encrypted file with Decoy=true in its sealed header,
// so it stays a decoy after a rename, a move or a trip through the recycle
// bin, and nothing on disk tells it apart from a real file. The keys inside
// are random and fake: they work nowhere and do not call out to any service.

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// decoyIn returns the name of a decoy file at p or anywhere below it ("" = none).
func decoyIn(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	if !fi.IsDir() {
		if n, ok := decoyName(p, fi); ok {
			return n
		}
		return ""
	}
	found := ""
	filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !idRe.MatchString(d.Name()) {
			return nil
		}
		if i, err := d.Info(); err == nil {
			if n, ok := decoyName(q, i); ok {
				found = n
				return fs.SkipAll
			}
		}
		return nil
	})
	return found
}

func decoyName(p string, fi os.FileInfo) (string, bool) {
	n, _, ok := itemInfo(p, fi)
	if !ok {
		return "", false
	}
	nameCacheMu.RLock()
	c := nameCache[p]
	nameCacheMu.RUnlock()
	return n, c.decoy
}

// decoyHit raises the alert for a web request. how: what was done.
func decoyHit(r *http.Request, file, how, where string) {
	ip, who := actor(r)
	decoyHitAs(ip, who, file, how, where)
}

func decoyHitAs(ip, who, file, how, where string) {
	d := "«" + file + "» — " + how
	if where != "" {
		d += " — در " + where
	}
	raiseAlertAs(ip, who, "decoy", "decoy"+ip+file+how, 60, "دست‌زدن به فایل طعمه", d)
}

/* ---------- making decoys ---------- */

func randStr(n int, chars string) string {
	b := make([]byte, n)
	for i := range b {
		k, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b[i] = chars[k.Int64()]
	}
	return string(b)
}

const (
	upperNum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func fakeAWS() (id, secret string) {
	return "AKIA" + randStr(16, upperNum), randStr(40, alnum+"+/")
}

func decoyContents() map[string][]byte {
	id1, s1 := fakeAWS()
	id2, s2 := fakeAWS()
	id3, s3 := fakeAWS()
	day := time.Now().AddDate(0, 0, -37).Format("2006-01-02")

	var sql strings.Builder
	fmt.Fprintf(&sql, "-- MySQL dump 10.13  Distrib 8.0.36\n-- Host: db-prod-01    Database: core_prod\n-- Dump completed on %s 02:00:13\n\n", day)
	sql.WriteString("CREATE TABLE `users` (\n  `id` int NOT NULL AUTO_INCREMENT,\n  `username` varchar(64) NOT NULL,\n  `email` varchar(128) NOT NULL,\n  `password_hash` varchar(100) NOT NULL,\n  `role` varchar(16) NOT NULL DEFAULT 'user',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\nINSERT INTO `users` VALUES\n")
	for i := 1; i <= 40; i++ {
		role := "user"
		if i <= 3 {
			role = "admin"
		}
		sep := ","
		if i == 40 {
			sep = ";"
		}
		fmt.Fprintf(&sql, "(%d,'user%03d','user%03d@corp.local','$2b$12$%s','%s')%s\n", i, i, i, randStr(53, alnum+"./"), role, sep)
	}
	fmt.Fprintf(&sql, "\nCREATE TABLE `api_keys` (`service` varchar(32), `key_id` varchar(64), `secret` varchar(128));\nINSERT INTO `api_keys` VALUES ('s3-backup','%s','%s');\n", id1, s1)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Name = "prod-db-backup.sql"
	zw.Write([]byte(sql.String()))
	zw.Close()

	env := fmt.Sprintf(`# production - do not commit
APP_ENV=production
APP_KEY=base64:%s
DB_HOST=db-prod-01.corp.local
DB_PORT=3306
DB_DATABASE=core_prod
DB_USERNAME=core_admin
DB_PASSWORD=%s
REDIS_PASSWORD=%s
JWT_SECRET=%s
AWS_ACCESS_KEY_ID=%s
AWS_SECRET_ACCESS_KEY=%s
AWS_DEFAULT_REGION=eu-central-1
AWS_BUCKET=corp-prod-backups
MAIL_PASSWORD=%s
`, randStr(43, alnum)+"=", randStr(20, alnum), randStr(24, alnum), randStr(64, alnum), id2, s2, randStr(16, alnum))

	csv := fmt.Sprintf("User name,Password,Access key ID,Secret access key,Console login link\nbackup-svc,,%s,%s,https://corp-prod.signin.aws.amazon.com/console\nci-deploy,,%s,%s,https://corp-prod.signin.aws.amazon.com/console\n", id3, s3, id1, s1)

	return map[string][]byte{
		"prod-db-backup.sql.gz": gz.Bytes(),
		".env":                  []byte(env),
		"aws-access-keys.csv":   []byte(csv),
	}
}

type decoyItem struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"`
}

// listDecoys finds every decoy in the shared, private and inbox folders.
func listDecoys(r *http.Request) []decoyItem {
	out := []decoyItem{}
	for _, sr := range searchRoots(r) {
		walkSpace(r.Context(), sr.phys, "", func(it wItem) bool {
			if !it.isDir {
				if _, ok := decoyName(it.phys, it.fi); ok {
					out = append(out, decoyItem{sr.client + it.rel, it.name, it.size, it.mtime})
				}
			}
			return true
		})
	}
	return out
}

// GET /api/decoys: list. POST {op:"create", path:"/folder"} or {op:"remove", path}. Admins only.
func handleDecoys(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		fail(w, http.StatusForbidden, "admin only")
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"items": listDecoys(r)})
		return
	}
	if readOnly {
		fail(w, 403, "read-only mode")
		return
	}
	var q struct{ Op, Path string }
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&q) != nil {
		fail(w, 400, "bad request")
		return
	}
	switch q.Op {
	case "create":
		dir, _, err := resolve(r, q.Path, accWrite)
		if err != nil || !isDir(dir) {
			fail(w, 400, "folder not found")
			return
		}
		old := time.Now().AddDate(0, 0, -37)
		made := []string{}
		for name, data := range decoyContents() {
			name = uniqueLogical(dir, name)
			dst := filepath.Join(dir, nameID(name))
			if err := writeEncMeta(dst, fileMeta{Name: name, Decoy: true}, bytes.NewReader(data)); err != nil {
				fail(w, 500, "cannot save")
				return
			}
			os.Chtimes(dst, old, old) // look like an old forgotten file
			made = append(made, name)
			auditNote(r, name)
		}
		writeJSON(w, map[string]any{"made": made})
	case "remove": // the admin removes a decoy for good, without an alert
		full, sr, err := resolve(r, q.Path, accModify)
		if err != nil || full == sr || isDir(full) {
			fail(w, 400, "not found")
			return
		}
		fi, err := os.Stat(full)
		if err != nil {
			fail(w, 404, "not found")
			return
		}
		if _, ok := decoyName(full, fi); !ok {
			fail(w, 400, "not a decoy")
			return
		}
		auditNote(r, path.Base(q.Path))
		if err := os.Remove(full); err != nil {
			fail(w, 500, "cannot delete")
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	default:
		fail(w, 400, "bad request")
	}
}
