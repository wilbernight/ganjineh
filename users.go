package main

// Per-computer names and private folders.
//   - The admin (someone on the server PC itself) gives a computer's IP a
//     name; that computer then gets its own private folder.
//   - Only computers with that IP (and the admin) can open the folder.
//     Everyone else may only send files/folders into it, without seeing it.
//   - Private folders live in <data>/private/<id>, encrypted like the rest.
//     In the API they are the path "/:<id>/..." (":" cannot be in a name).
//   - users.json is sealed with the master key (names and IPs not readable).

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	dataBase string
	usersKey []byte

	usersMu sync.Mutex
	users   []user
	recent  = map[string]time.Time{} // ip -> last request (this run only)
)

type user struct {
	ID   string   `json:"id"`
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
	Kind string   `json:"kind,omitempty"` // "" = one computer, "unit" = a department's shared folder
	Send string   `json:"send,omitempty"` // unit only: code of its own send page /s/<code> ("" = none)
}

func (u *user) has(ip string) bool {
	ip = normIP(ip)
	for _, x := range u.IPs {
		if x == ip {
			return true
		}
	}
	return false
}

type usersFile struct {
	V    int    `json:"v"`
	Data string `json:"data"`
}

var (
	errForbidden = errors.New("private folder")
	errNoUser    = errors.New("folder not found")
)

func usersPath() string { return filepath.Join(dataBase, "users.json") }

func loadUsers() error {
	b, err := os.ReadFile(usersPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var f usersFile
	if json.Unmarshal(b, &f) != nil {
		return errors.New("users.json is damaged")
	}
	ct, _ := base64.StdEncoding.DecodeString(f.Data)
	pt, err := unseal(usersKey, ct, []byte("users"))
	if err != nil {
		return errors.New("users.json is damaged or from another vault")
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	return json.Unmarshal(pt, &users)
}

func loadAll() error {
	loadSettings()
	return loadUsers()
}

// saveUsers is called with usersMu held.
func saveUsers() error {
	pt, _ := json.Marshal(users)
	b, _ := json.Marshal(usersFile{V: 1, Data: base64.StdEncoding.EncodeToString(seal(usersKey, pt, []byte("users")))})
	tmp := usersPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, usersPath())
}

// Login page heading: "ارسال فایل برای واحد <unitTitle>" (set by the admin).
var (
	ipNames   = map[string]string{} // ip -> full name the person typed at login
	unitTitle string
	netPrefix string // admin-set IP range for quick entry, e.g. "192.168.1."
)

func settingsPath() string { return filepath.Join(dataBase, "settings.json") }

func loadSettings() {
	b, err := os.ReadFile(settingsPath())
	if err != nil {
		return
	}
	var f usersFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	ct, _ := base64.StdEncoding.DecodeString(f.Data)
	pt, err := unseal(usersKey, ct, []byte("settings"))
	if err != nil {
		return
	}
	var st struct {
		Unit   string `json:"unit"`
		Inbox  string `json:"inbox"`
		Prefix string            `json:"prefix"`
		Names  map[string]string `json:"names"`
		Days   *int              `json:"trashDays"`
		Admins []string          `json:"admins"`
	}
	if json.Unmarshal(pt, &st) == nil {
		unitTitle, inboxUnit, netPrefix = st.Unit, st.Inbox, st.Prefix
		if st.Days != nil {
			trashDays = *st.Days
		}
		adminMu.Lock()
		adminIPs = st.Admins
		adminMu.Unlock()
		if st.Names != nil {
			ipNames = st.Names
		}
	}
}

func saveSettings() error {
	adminMu.RLock()
	ad := append([]string{}, adminIPs...)
	adminMu.RUnlock()
	pt, _ := json.Marshal(map[string]any{"unit": unitTitle, "inbox": inboxUnit, "prefix": netPrefix, "names": ipNames, "trashDays": trashDays, "admins": ad})
	b, _ := json.Marshal(usersFile{V: 1, Data: base64.StdEncoding.EncodeToString(seal(usersKey, pt, []byte("settings")))})
	tmp := settingsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, settingsPath())
}

// handleBrand (no login needed): what the login page shows.
func handleBrand(w http.ResponseWriter, r *http.Request) {
	usersMu.Lock()
	defer usersMu.Unlock()
	if c := r.URL.Query().Get("u"); c != "" { // a unit's own send page
		t := ""
		if u := unitBySend(c); u != nil {
			t = u.Name
		}
		writeJSON(w, map[string]string{"unit": t, "own": "1"})
		return
	}
	writeJSON(w, map[string]string{"unit": unitTitle})
}

var reSendCode = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)

// codes that are already addresses of the program
var reservedCodes = map[string]bool{"s": true, "login": true, "logout": true, "setup": true, "api": true, "assets": true, "dl": true, "favicon": true}

// isSendCodePath: p is "/<code>" (or "/<code>/") of a unit's send page.
func isSendCodePath(p string) bool {
	c := strings.Trim(p, "/")
	if c == "" || strings.Contains(c, "/") {
		return false
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	return unitBySend(c) != nil
}

// unitBySend finds the unit whose send page code is c (usersMu held).
func unitBySend(c string) *user {
	c = strings.ToLower(strings.TrimSpace(c))
	if c == "" {
		return nil
	}
	for i := range users {
		if users[i].Kind == "unit" && users[i].Send == c {
			return &users[i]
		}
	}
	return nil
}

// ipPrefix: the first three parts of this server's LAN address ("192.168.1.").
func ipPrefix() string {
	if netPrefix != "" {
		return netPrefix
	}
	for _, ip := range lanIPs() {
		if i := strings.LastIndex(ip, "."); i > 0 && strings.Count(ip, ".") == 3 {
			return ip[:i+1]
		}
	}
	return ""
}

var (
	adminMu  sync.RWMutex
	adminIPs []string // computers with admin rights besides the server itself
)

func privRoot(id string) string { return filepath.Join(dataBase, "private", id) }

var localIPs = func() map[string]bool {
	m := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			m[ipn.IP.String()] = true
		}
	}
	return m
}()

// isAdmin: requests from the server PC itself (localhost or its own LAN IP).
// isServer: the request comes from the server computer itself.
func isServer(r *http.Request) bool {
	ip := net.ParseIP(clientIP(r))
	return ip != nil && (ip.IsLoopback() || localIPs[ip.String()])
}

// isAdmin: the server itself, or a computer the admin gave admin rights to.
func isAdmin(r *http.Request) bool {
	if isServer(r) {
		return true
	}
	adminMu.RLock()
	defer adminMu.RUnlock()
	return slices.Contains(adminIPs, normIP(clientIP(r)))
}

func normIP(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return ""
}

func userByID(id string) *user {
	for i := range users {
		if users[i].ID == id {
			return &users[i]
		}
	}
	return nil
}

// userByIP: the computer (not unit) with this IP.
func userByIP(ip string) *user {
	for i := range users {
		if users[i].Kind == "" && users[i].has(ip) {
			return &users[i]
		}
	}
	return nil
}

// canOpenSpace: admin, the computer itself, or a member of the unit.
func canOpenSpace(r *http.Request, u *user) bool {
	if isAdmin(r) {
		return true
	}
	if u.Kind == "unit" {
		return u.has(clientIP(r))
	}
	return userByIP(clientIP(r)) == u
}

func noteClient(r *http.Request) {
	usersMu.Lock()
	recent[normIP(clientIP(r))] = time.Now()
	usersMu.Unlock()
}

const (
	accRead   = iota // list, download
	accWrite         // upload, new folder (allowed into anyone's private folder)
	accModify        // delete, rename
)

// resolve maps an API path to the folder/file on disk and checks access.
// spaceRoot is the root of the shared or private space the path is in.
func resolve(r *http.Request, p string, mode int) (full, spaceRoot string, err error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	if !strings.HasPrefix(clean, "/:") {
		full, err = mapPath(root, clean)
		return full, root, err
	}
	id, rest, _ := strings.Cut(clean[2:], "/")
	if id == inboxID { // files sent to our unit: members only, no sending in through here
		usersMu.Lock()
		ok := canOpenInbox(r)
		usersMu.Unlock()
		if !ok {
			return "", "", errForbidden
		}
		sr := inboxRoot()
		if err := os.MkdirAll(sr, 0o700); err != nil {
			return "", "", err
		}
		full, err = mapPath(sr, "/"+rest)
		return full, sr, err
	}
	usersMu.Lock()
	u := userByID(id)
	mine := u != nil && canOpenSpace(r, u)
	usersMu.Unlock()
	if u == nil {
		return "", "", errNoUser
	}
	if !mine && mode != accWrite {
		return "", "", errForbidden
	}
	sr := privRoot(id)
	if err := os.MkdirAll(sr, 0o700); err != nil {
		return "", "", err
	}
	full, err = mapPath(sr, "/"+rest)
	return full, sr, err
}

func resolveFail(w http.ResponseWriter, err error) {
	if errors.Is(err, errForbidden) {
		fail(w, http.StatusForbidden, "private folder")
		return
	}
	fail(w, 400, err.Error())
}

type person struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind,omitempty"`
	Member bool   `json:"member,omitempty"` // this client may open it
	Send   string `json:"send,omitempty"`   // unit's own send page code (members and admins only)
}

// infoUsers adds the user part of /api/info.
func infoUsers(r *http.Request, m map[string]any) {
	usersMu.Lock()
	defer usersMu.Unlock()
	admin := isAdmin(r)
	m["admin"] = admin
	m["ip"] = normIP(clientIP(r))
	m["myName"] = ipNames[normIP(clientIP(r))]
	if u := userByIP(clientIP(r)); u != nil {
		m["me"] = person{ID: u.ID, Name: u.Name}
	}
	ps := []person{}
	for i := range users {
		u := &users[i]
		p := person{ID: u.ID, Name: u.Name, Kind: u.Kind, Member: canOpenSpace(r, u)}
		if p.Member {
			p.Send = u.Send
		}
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	m["people"] = ps
	if unitTitle != "" && canOpenInbox(r) {
		m["inbox"] = map[string]string{"unit": unitTitle}
	}
}

// handleUsers: admin only. GET lists users and recently seen IPs;
// POST {op:"save"|"del", id, name, ips} changes them.
func handleUsers(w http.ResponseWriter, r *http.Request) {
	if !isAdmin(r) {
		fail(w, http.StatusForbidden, "admin only")
		return
	}
	usersMu.Lock()
	defer usersMu.Unlock()
	if r.Method == http.MethodGet {
		type seen struct {
			IP      string `json:"ip"`
			Ago     int64  `json:"ago"`
			Name    string `json:"name"`
			Claimed string `json:"claimed"` // name typed at login
		}
		rs := []seen{}
		for ip, t := range recent {
			if ip == "" || localIPs[ip] || net.ParseIP(ip).IsLoopback() {
				continue
			}
			n := ""
			if u := userByIP(ip); u != nil {
				n = u.Name
			}
			rs = append(rs, seen{ip, int64(time.Since(t).Seconds()), n, ipNames[ip]})
		}
		sort.Slice(rs, func(i, j int) bool { return rs[i].Ago < rs[j].Ago })
		us := users
		if us == nil {
			us = []user{}
		}
		adminMu.RLock()
		ad := append([]string{}, adminIPs...)
		adminMu.RUnlock()
		writeJSON(w, map[string]any{"users": us, "recent": rs, "unit": unitTitle, "inbox": inboxUnit, "prefix": ipPrefix(), "names": ipNames,
			"admins": ad, "server": isServer(r), "trashDays": trashDays})
		return
	}
	var q struct {
		Op   string   `json:"op"`
		Kind string   `json:"kind"`
		ID   string   `json:"id"`
		Name string   `json:"name"`
		IPs  []string `json:"ips"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&q) != nil {
		fail(w, 400, "bad request")
		return
	}
	switch q.Op {
	case "admins": // only the server computer itself may change who is admin
		if !isServer(r) {
			fail(w, http.StatusForbidden, "server only")
			return
		}
		ips := []string{}
		for _, x := range q.IPs {
			ip := normIP(x)
			if ip == "" {
				fail(w, 400, "invalid ip: "+x)
				return
			}
			if !slices.Contains(ips, ip) {
				ips = append(ips, ip)
			}
		}
		adminMu.Lock()
		adminIPs = ips
		adminMu.Unlock()
		if err := saveSettings(); err != nil {
			fail(w, 500, "cannot save")
			return
		}
		log.Printf("admin rights now: server + %v", ips)
		writeJSON(w, map[string]any{"ok": true, "admins": ips})
		return
	case "sendpage": // a unit's own send page: /s/<code>
		u := userByID(q.ID)
		if u == nil || u.Kind != "unit" {
			fail(w, 404, "not found")
			return
		}
		code := strings.ToLower(strings.TrimSpace(q.Name))
		if code != "" && (!reSendCode.MatchString(code) || reservedCodes[code]) {
			fail(w, 400, "invalid code")
			return
		}
		for i := range users {
			if code != "" && users[i].Send == code && users[i].ID != u.ID {
				fail(w, 400, "code already used by "+users[i].Name)
				return
			}
		}
		u.Send = code
	case "prefix":
		p := strings.TrimSuffix(strings.TrimSpace(q.Name), ".")
		if p != "" {
			if normIP(p+".1") == "" || strings.Count(p, ".") != 2 {
				fail(w, 400, "invalid range")
				return
			}
			p = strings.TrimSuffix(normIP(p+".1"), "1")
		}
		netPrefix = p
		if err := saveSettings(); err != nil {
			fail(w, 500, "cannot save")
			return
		}
		writeJSON(w, map[string]any{"ok": true, "prefix": ipPrefix()})
		return
	case "title":
		t := strings.TrimSpace(q.Name)
		if len([]rune(t)) > 60 {
			fail(w, 400, "invalid name")
			return
		}
		unitTitle = t
		if u := userByID(q.ID); u != nil && u.Kind == "unit" {
			inboxUnit = u.ID
		} else {
			inboxUnit = ""
		}
		if err := saveSettings(); err != nil {
			fail(w, 500, "cannot save")
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
		return
	case "save":
		name := strings.TrimSpace(q.Name)
		if name == "" || len([]rune(name)) > 60 {
			fail(w, 400, "invalid name")
			return
		}
		if u := userByID(q.ID); u != nil {
			q.Kind = u.Kind // the kind never changes
		}
		var ips []string
		for _, s := range q.IPs {
			ip := normIP(s)
			if ip == "" {
				fail(w, 400, "invalid ip: "+s)
				return
			}
			if o := userByIP(ip); q.Kind != "unit" && o != nil && o.ID != q.ID {
				fail(w, 400, "ip already used by "+o.Name)
				return
			}
			if !slices.Contains(ips, ip) {
				ips = append(ips, ip)
			}
		}
		if len(ips) == 0 {
			fail(w, 400, "ip required")
			return
		}
		kind := ""
		if q.Kind == "unit" {
			kind = "unit"
		}
		if u := userByID(q.ID); u != nil {
			u.Name, u.IPs = name, ips
		} else {
			users = append(users, user{ID: strings.ToLower(idEnc.EncodeToString(randBytes(5))), Name: name, IPs: ips, Kind: kind})
		}
	case "del":
		u := userByID(q.ID)
		if u == nil {
			fail(w, 404, "not found")
			return
		}
		if es, err := listDir(privRoot(u.ID)); err == nil && len(es) > 0 {
			fail(w, 400, "folder not empty")
			return
		}
		os.RemoveAll(privRoot(u.ID))
		for i := range users {
			if users[i].ID == q.ID {
				users = append(users[:i], users[i+1:]...)
				break
			}
		}
	default:
		fail(w, 400, "bad request")
		return
	}
	if err := saveUsers(); err != nil {
		fail(w, 500, "cannot save")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// rememberName stores the full name a person typed at login for their IP.
func rememberName(ip, name string) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" || len([]rune(name)) > 60 {
		return
	}
	ip = normIP(ip)
	usersMu.Lock()
	defer usersMu.Unlock()
	if ipNames[ip] == name {
		return
	}
	ipNames[ip] = name
	saveSettings()
}
