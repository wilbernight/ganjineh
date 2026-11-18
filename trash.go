package main

// Recycle bin: deleted files and folders are moved to <data>/trash/<id>/
// instead of being erased. Only admins see the bin; they can restore chosen
// items to where they were, delete them for good, or empty the bin. Items
// older than trashDays are erased automatically (0 = keep until emptied).
// The list (names, places, who deleted) is stored encrypted in trash.json.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type trashItem struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Dir    bool     `json:"dir"`
	Size   int64    `json:"size"`
	Orig   string   `json:"orig"`   // logical path of the folder it was in, e.g. "/:abc/a/b"
	Space  string   `json:"-"`      // physical root of that space (kept in the file)
	Segs   []string `json:"-"`      // folder names below the space root
	At     int64    `json:"at"`     // unix time deleted
	ByIP   string   `json:"byIp"`   // who deleted it
	ByName string   `json:"byName"` // name typed at login
}

// stored form (Space/Segs are kept on disk but not sent to browsers)
type trashRec struct {
	trashItem
	SpaceS string   `json:"space"`
	SegsS  []string `json:"segs"`
}

var (
	trashMu    sync.Mutex
	trashItems []trashItem
	trashDays  = 30 // auto delete after this many days (0 = never); saved in settings
)

func trashRoot() string { return filepath.Join(dataBase, "trash") }
func trashPath() string { return filepath.Join(dataBase, "trash.json") }

func loadTrash() {
	trashMu.Lock()
	defer trashMu.Unlock()
	b, err := os.ReadFile(trashPath())
	if err != nil {
		return
	}
	var f usersFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	ct, _ := base64.StdEncoding.DecodeString(f.Data)
	pt, err := unseal(usersKey, ct, []byte("trash"))
	if err != nil {
		return
	}
	var rs []trashRec
	if json.Unmarshal(pt, &rs) != nil {
		return
	}
	trashItems = trashItems[:0]
	for _, r := range rs {
		it := r.trashItem
		it.Space, it.Segs = r.SpaceS, r.SegsS
		if isDir(filepath.Join(trashRoot(), it.ID)) {
			trashItems = append(trashItems, it)
		}
	}
}

// saveTrash is called with trashMu held.
func saveTrash() error {
	rs := make([]trashRec, len(trashItems))
	for i, it := range trashItems {
		rs[i] = trashRec{it, it.Space, it.Segs}
	}
	pt, _ := json.Marshal(rs)
	b, _ := json.Marshal(usersFile{V: 1, Data: base64.StdEncoding.EncodeToString(seal(usersKey, pt, []byte("trash")))})
	tmp := trashPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, trashPath())
}

// moveItem renames src to dst; across disks it copies and then removes.
func moveItem(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyTree(src, dst); err != nil {
		os.RemoveAll(dst)
		return err
	}
	return os.RemoveAll(src)
}

func copyTree(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	des, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, d := range des {
		if err := copyTree(filepath.Join(src, d.Name()), filepath.Join(dst, d.Name())); err != nil {
			return err
		}
	}
	return nil
}

func treeSize(p string) int64 {
	var n int64
	filepath.Walk(p, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

// itemName reads the real (logical) name of an encrypted file or folder.
func itemName(phys string) (string, int64, error) {
	if isDir(phys) {
		n, err := readDirName(phys)
		return n, treeSize(phys), err
	}
	f, err := os.Open(phys)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	m, err := readHeader(f)
	return m.Name, m.Size, err
}

// toTrash moves phys (logical path logical, inside the space rooted at sr)
// into the bin. ip is the computer that deleted it.
func toTrash(phys, sr, logical, ip string) error {
	name, size, err := itemName(phys)
	if err != nil {
		return err
	}
	clean := path.Clean("/" + strings.ReplaceAll(logical, "\\", "/"))
	parent := path.Dir(clean)
	rel := parent
	if strings.HasPrefix(parent, "/:") { // strip the "/:id" space part
		_, rest, _ := strings.Cut(parent[2:], "/")
		rel = "/" + rest
	}
	var segs []string
	for _, s := range strings.Split(strings.Trim(rel, "/"), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	id := strings.ToLower(idEnc.EncodeToString(randBytes(10)))
	box := filepath.Join(trashRoot(), id)
	if err := os.MkdirAll(box, 0o700); err != nil {
		return err
	}
	if err := moveItem(phys, filepath.Join(box, filepath.Base(phys))); err != nil {
		os.RemoveAll(box)
		return err
	}
	ip = normIP(ip)
	usersMu.Lock()
	who := ipNames[ip]
	if who == "" {
		if u := userByIP(ip); u != nil {
			who = u.Name
		}
	}
	usersMu.Unlock()
	trashMu.Lock()
	defer trashMu.Unlock()
	trashItems = append(trashItems, trashItem{ID: id, Name: name, Dir: isDir(filepath.Join(box, filepath.Base(phys))),
		Size: size, Orig: parent, Space: sr, Segs: segs, At: time.Now().Unix(), ByIP: ip, ByName: who})
	return saveTrash()
}

// boxItem returns the physical item stored in a bin entry.
func boxItem(id string) (string, error) {
	box := filepath.Join(trashRoot(), id)
	des, err := os.ReadDir(box)
	if err != nil || len(des) != 1 {
		return "", errors.New("missing")
	}
	return filepath.Join(box, des[0].Name()), nil
}

// restoreOne puts an item back (trashMu held). Returns the name it got.
func restoreOne(it trashItem) (string, error) {
	src, err := boxItem(it.ID)
	if err != nil {
		return "", err
	}
	if !isDir(it.Space) {
		if err := os.MkdirAll(it.Space, 0o700); err != nil {
			return "", err
		}
	}
	dir, err := ensureDirs(it.Space, it.Segs...) // parent folders are recreated if they were deleted too
	if err != nil {
		return "", err
	}
	name := it.Name
	if exists(filepath.Join(dir, nameID(name))) {
		name = uniqueLogical(dir, name)
		if err := renameItem(src, name); err != nil {
			return "", err
		}
		src = filepath.Join(filepath.Dir(src), nameID(name))
	}
	if err := moveItem(src, filepath.Join(dir, nameID(name))); err != nil {
		return "", err
	}
	os.RemoveAll(filepath.Join(trashRoot(), it.ID))
	return name, nil
}

// purgeOld erases items older than trashDays.
func purgeOld() {
	trashMu.Lock()
	defer trashMu.Unlock()
	usersMu.Lock()
	days := trashDays
	usersMu.Unlock()
	if days <= 0 {
		return
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	keep, n := trashItems[:0], 0
	for _, it := range trashItems {
		if it.At < cut {
			os.RemoveAll(filepath.Join(trashRoot(), it.ID))
			n++
			continue
		}
		keep = append(keep, it)
	}
	trashItems = keep
	if n > 0 {
		saveTrash()
		log.Printf("recycle bin: %d item(s) older than %d days erased", n, days)
	}
}

func trashJanitor() {
	for {
		purgeOld()
		time.Sleep(time.Hour)
	}
}

// handleTrash: admins only.
// GET -> {items, days}; POST {op:"restore"|"purge"|"empty"|"days", ids, days}.
func handleTrash(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		fail(w, http.StatusForbidden, "admin only")
		return
	}
	if r.Method == http.MethodGet {
		trashMu.Lock()
		its := append([]trashItem{}, trashItems...)
		trashMu.Unlock()
		sort.Slice(its, func(i, j int) bool { return its[i].At > its[j].At })
		var total int64
		for _, it := range its {
			total += it.Size
		}
		usersMu.Lock()
		d := trashDays
		usersMu.Unlock()
		writeJSON(w, map[string]any{"items": its, "days": d, "total": total})
		return
	}
	var q struct {
		Op   string   `json:"op"`
		IDs  []string `json:"ids"`
		Days int      `json:"days"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil {
		fail(w, 400, "bad request")
		return
	}
	if q.Op == "days" {
		if q.Days < 0 || q.Days > 3650 {
			fail(w, 400, "invalid days")
			return
		}
		usersMu.Lock()
		trashDays = q.Days
		err := saveSettings()
		usersMu.Unlock()
		if err != nil {
			fail(w, 500, "cannot save")
			return
		}
		go purgeOld()
		writeJSON(w, map[string]bool{"ok": true})
		return
	}
	if readOnly {
		fail(w, 405, "read-only")
		return
	}
	trashMu.Lock()
	defer trashMu.Unlock()
	want := map[string]bool{}
	for _, id := range q.IDs {
		want[id] = true
	}
	keep := trashItems[:0:0]
	done, failed := 0, 0
	for _, it := range trashItems {
		hit := q.Op == "empty" || want[it.ID]
		if !hit {
			keep = append(keep, it)
			continue
		}
		switch q.Op {
		case "restore":
			if _, err := restoreOne(it); err != nil {
				log.Printf("recycle bin: cannot restore %q: %v", it.Name, err)
				keep = append(keep, it)
				failed++
				continue
			}
		case "purge", "empty":
			if err := os.RemoveAll(filepath.Join(trashRoot(), it.ID)); err != nil {
				keep = append(keep, it)
				failed++
				continue
			}
		default:
			fail(w, 400, "bad request")
			return
		}
		auditNote(r, it.Name)
		done++
	}
	trashItems = keep
	if err := saveTrash(); err != nil {
		fail(w, 500, "cannot save")
		return
	}
	writeJSON(w, map[string]int{"done": done, "failed": failed})
}
