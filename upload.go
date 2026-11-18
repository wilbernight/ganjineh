// Uploader mode (LanFileServer.exe -upload, or files dropped on the exe): sends files and whole folders (with all sub-folders) to a
// LAN File Server. Drag files/folders onto the exe, into its window, or pick
// them in a dialog. Folder structure is recreated on the server; files that
// are already there with the same size are skipped, so an interrupted upload
// can simply be run again.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const upVersion = "1.0"

var (
	upIn     = bufio.NewReader(os.Stdin)
	upClient *http.Client
	upBase   *url.URL // server root, e.g. http://192.168.1.10/Temporary_Listen_Addresses/
)

type upItem struct {
	local  string // file on this computer
	remote string // folder on the server ("/a/b")
	name   string
	size   int64
}

type upEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
}

func runUploader(args []string) {
	fmt.Println("==============================================")
	fmt.Println(" LAN File Server - Uploader v" + upVersion)
	fmt.Println(" Sends files and folders (with sub-folders) to the server.")
	fmt.Println("==============================================")
	err := upRun(args)
	if err != nil {
		fmt.Println("\n !!", err)
	}
	fmt.Println("\nPress Enter to exit...")
	upIn.ReadString('\n')
	if err != nil {
		os.Exit(1)
	}
}

func upAsk(prompt string) string {
	fmt.Print(prompt)
	s, _ := upIn.ReadString('\n')
	return strings.TrimSpace(s)
}

func upRun(args []string) error {
	jar, _ := cookiejar.New(nil)
	upClient = &http.Client{Jar: jar, Transport: &http.Transport{
		Proxy:                 nil, // LAN only: never through the company proxy
		DialContext:           (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
		ResponseHeaderTimeout: 10 * time.Minute,
	}}
	cfg := upLoadConfig()

	// 1) server
	for upBase == nil {
		def := cfg.Server
		p := " Server address"
		if def != "" {
			p += " [Enter = " + def + "]"
		} else {
			p += " (e.g. 192.168.1.10)"
		}
		s := upAsk(p + ": ")
		if s == "" {
			s = def
		}
		if s == "" {
			continue
		}
		fmt.Println(" Looking for the server...")
		u, err := upFindServer(s)
		if err != nil {
			fmt.Println(" !!", err)
			continue
		}
		upBase = u
		cfg.Server = u.String()
		upSaveConfig(cfg)
	}
	fmt.Println(" Server:", upBase)

	// 2) login
	for {
		code := upAsk(" 6-digit Authenticator code: ")
		err := upLogin(code)
		if err == nil {
			break
		}
		fmt.Println(" !!", err)
	}
	fmt.Println(" Logged in.")

	// 3) what to send
	srcs := args
	for len(srcs) == 0 {
		fmt.Println()
		fmt.Println(" What do you want to send?")
		fmt.Println("   Drag files/folders into this window and press Enter,")
		if runtime.GOOS == "windows" {
			fmt.Println("   or type  1  = choose a folder,  2  = choose files.")
		}
		s := upAsk(" > ")
		switch s {
		case "1", "2":
			if runtime.GOOS == "windows" {
				srcs = upPick(s == "1")
			}
		default:
			srcs = upSplitPaths(s)
		}
	}
	var items []upItem
	var dirs []string // server folders to create, parents first
	var total int64
	for _, s := range srcs {
		s = filepath.Clean(s)
		st, err := os.Stat(s)
		if err != nil {
			fmt.Println(" !! not found:", s)
			continue
		}
		if !st.IsDir() {
			items = append(items, upItem{local: s, remote: "", name: filepath.Base(s), size: st.Size()})
			total += st.Size()
			continue
		}
		top := filepath.Base(s)
		if top == "." || top == string(filepath.Separator) || strings.HasSuffix(top, ":") || top == "" {
			top = strings.TrimSuffix(strings.ReplaceAll(s, ":", ""), string(filepath.Separator)) // drive root: D:\ -> "D"
		}
		filepath.WalkDir(s, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				fmt.Println(" !! cannot read:", p)
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(s, p)
			rel = filepath.ToSlash(rel)
			r := "/" + top
			if rel != "." {
				r += "/" + rel
			}
			if d.IsDir() {
				dirs = append(dirs, r)
				return nil
			}
			if !d.Type().IsRegular() {
				return nil // links, devices
			}
			if junkName(d.Name()) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			items = append(items, upItem{local: p, remote: path.Dir(r), name: d.Name(), size: info.Size()})
			total += info.Size()
			return nil
		})
	}
	if len(items) == 0 && len(dirs) == 0 {
		return errors.New("nothing to send")
	}
	fmt.Printf(" %d file(s) in %d folder(s), %s.\n", len(items), len(dirs), upHuman(total))

	// 4) where to
	dest := "/"
	if s := upAsk(" Folder on the server to put them in [Enter = top level]: "); s != "" {
		dest = "/" + strings.Trim(strings.ReplaceAll(s, "\\", "/"), "/")
	}
	if err := upEnsureDir(dest); err != nil {
		return err
	}

	// 5) send
	start := time.Now()
	for _, d := range dirs {
		if err := upEnsureDir(path.Join(dest, d)); err != nil {
			fmt.Println(" !!", err)
		}
	}
	listing := map[string]map[string]int64{}
	var sent, done int64
	var ok, skipped, failed int
	var failedList []string
	for i, it := range items {
		dir := path.Join(dest, it.remote)
		have, found := listing[dir]
		if !found {
			have = map[string]int64{}
			if es, err := upList(dir); err == nil {
				for _, e := range es {
					if !e.IsDir {
						have[e.Name] = e.Size
					}
				}
			}
			listing[dir] = have
		}
		label := fmt.Sprintf("[%d/%d] %s", i+1, len(items), path.Join(it.remote, it.name))
		if sz, ok := have[it.name]; ok && sz == it.size {
			fmt.Println(" skip " + label + "  (already there)")
			skipped++
			done += it.size
			continue
		}
		var err error
		for try := 0; try < 3; try++ {
			if try > 0 {
				fmt.Println("      retrying...")
				time.Sleep(2 * time.Second)
			}
			err = upUpload(it, dir, label, done, total, start)
			if err == nil || errors.Is(err, upErrLogin) {
				break
			}
		}
		if errors.Is(err, upErrLogin) {
			fmt.Println("\n Session expired. Log in again.")
			for {
				if e := upLogin(upAsk(" 6-digit Authenticator code: ")); e == nil {
					break
				} else {
					fmt.Println(" !!", e)
				}
			}
			err = upUpload(it, dir, label, done, total, start)
		}
		done += it.size
		if err != nil {
			fmt.Printf("\r !! %s: %v\n", label, err)
			failed++
			failedList = append(failedList, it.local)
			continue
		}
		have[it.name] = it.size
		sent += it.size
		ok++
	}
	el := time.Since(start)
	fmt.Println()
	fmt.Println("==============================================")
	fmt.Printf(" Done in %s: %d sent (%s), %d already there, %d failed.\n", el.Round(time.Second), ok, upHuman(sent), skipped, failed)
	if el.Seconds() > 1 && sent > 0 {
		fmt.Printf(" Speed: %s/s\n", upHuman(int64(float64(sent)/el.Seconds())))
	}
	for _, f := range failedList {
		fmt.Println("   failed:", f)
	}
	if failed > 0 {
		fmt.Println(" Run again to retry; files already sent are skipped.")
	}
	fmt.Println(" On the server they are in:", dest)
	return nil
}

// ---- server ----

func upFindServer(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	var cands []string
	if strings.Contains(s, "://") {
		cands = []string{strings.TrimSuffix(s, "/") + "/"}
	} else {
		h := strings.TrimSuffix(s, "/")
		if strings.Contains(h, "/") || strings.Contains(h, ":") {
			cands = []string{"http://" + h + "/"}
		} else {
			for _, c := range []string{"/Temporary_Listen_Addresses/", "/Temporary_Listen_Addresses/LanFileServer/", ":8080/", "/", ":9100/", ":631/", ":8000/", ":8888/", ":8081/", ":8090/", ":443/"} {
				cands = append(cands, "http://"+h+c)
			}
		}
	}
	c := &http.Client{Timeout: 4 * time.Second, Transport: upClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, cand := range cands {
		u, err := url.Parse(cand)
		if err != nil {
			continue
		}
		r, err := c.Get(u.JoinPath("login").String())
		if err != nil {
			continue
		}
		io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if v := r.Header.Get("X-LFS-Version"); v != "" {
			fmt.Println(" Found LAN File Server", v, "at", u)
			return u, nil
		}
	}
	return nil, fmt.Errorf("no LAN File Server found at %s (is it running? same address as in the browser?)", s)
}

var upErrLogin = errors.New("login required")

func upLogin(code string) error {
	code = strings.ReplaceAll(code, " ", "")
	b, _ := json.Marshal(map[string]string{"code": code})
	r, err := upClient.Post(upBase.JoinPath("api/login").String(), "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return upApiErr(r)
}

func upApiErr(r *http.Response) error {
	if r.StatusCode == http.StatusOK {
		return nil
	}
	var e struct {
		Error string `json:"error"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	json.Unmarshal(body, &e)
	switch {
	case r.StatusCode == 401 && e.Error == "invalid":
		return errors.New("wrong code")
	case r.StatusCode == 401:
		return upErrLogin
	case strings.HasPrefix(e.Error, "locked:"):
		return fmt.Errorf("too many wrong codes, wait %s seconds", strings.TrimPrefix(e.Error, "locked:"))
	case r.StatusCode == 403:
		return errors.New("the server is read-only (started with -readonly)")
	case e.Error != "":
		return errors.New(e.Error)
	}
	return fmt.Errorf("server answered %s", r.Status)
}

func upPostJSON(p string, v any) error {
	b, _ := json.Marshal(v)
	r, err := upClient.Post(upBase.JoinPath(p).String(), "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	return upApiErr(r)
}

func upList(dir string) ([]upEntry, error) {
	r, err := upClient.Get(upBase.JoinPath("api/list").String() + "?path=" + url.QueryEscape(dir))
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if err := upApiErr(r); err != nil {
		return nil, err
	}
	var es []upEntry
	return es, json.NewDecoder(r.Body).Decode(&es)
}

var upKnown = map[string]bool{"/": true}

// ensureDir creates a server folder and its parents if they do not exist.
func upEnsureDir(d string) error {
	d = path.Clean("/" + d)
	if upKnown[d] {
		return nil
	}
	if err := upEnsureDir(path.Dir(d)); err != nil {
		return err
	}
	parent, name := path.Dir(d), path.Base(d)
	es, err := upList(parent)
	if err != nil {
		return fmt.Errorf("folder %s: %w", parent, err)
	}
	for _, e := range es {
		if e.Name == name {
			if !e.IsDir {
				return fmt.Errorf("%s exists on the server as a file", d)
			}
			upKnown[d] = true
			return nil
		}
	}
	if err := upPostJSON("api/mkdir", map[string]string{"path": parent, "name": name}); err != nil {
		return fmt.Errorf("cannot create folder %s: %w", d, err)
	}
	upKnown[d] = true
	return nil
}

type upProgress struct {
	r              io.Reader
	n, done, total int64
	start, last    time.Time
	label          string
}

func (p *upProgress) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.n += int64(n)
	if time.Since(p.last) > 300*time.Millisecond {
		p.last = time.Now()
		pct := 100.0
		if p.total > 0 {
			pct = float64(p.done+p.n) * 100 / float64(p.total)
		}
		sp := float64(p.done+p.n) / time.Since(p.start).Seconds()
		fmt.Printf("\r %5.1f%%  %s/s  %s ", pct, upHuman(int64(sp)), upShort(p.label, 50))
	}
	return n, err
}

func upUpload(it upItem, dir, label string, done, total int64, start time.Time) error {
	f, err := os.Open(it.local)
	if err != nil {
		return err
	}
	defer f.Close()
	// Build the multipart envelope around the file so Content-Length is exact.
	var head bytes.Buffer
	mw := multipart.NewWriter(&head)
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, strings.NewReplacer(`"`, "%22", "\r", "", "\n", "").Replace(it.name)))
	h.Set("Content-Type", "application/octet-stream")
	if _, err := mw.CreatePart(h); err != nil {
		return err
	}
	headLen := head.Len()
	mw.Close()
	tail := bytes.Clone(head.Bytes()[headLen:]) // "\r\n--boundary--\r\n"
	body := io.MultiReader(bytes.NewReader(head.Bytes()[:headLen]),
		&upProgress{r: f, done: done, total: total, start: start, label: label}, bytes.NewReader(tail))
	req, err := http.NewRequest("POST", upBase.JoinPath("api/upload").String()+"?path="+url.QueryEscape(dir), body)
	if err != nil {
		return err
	}
	req.ContentLength = int64(headLen) + it.size + int64(len(tail))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	r, err := upClient.Do(req)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if err := upApiErr(r); err != nil {
		return err
	}
	fmt.Printf("\r  ok  %s  %s%s\n", label, upHuman(it.size), strings.Repeat(" ", 20))
	return nil
}

// ---- local ----

// splitPaths splits what was dragged into the console: "C:\a b\x" D:\y
func upSplitPaths(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if s[0] == '"' {
			if i := strings.IndexByte(s[1:], '"'); i >= 0 {
				out = append(out, s[1:i+1])
				s = s[i+2:]
				continue
			}
			out = append(out, s[1:])
			break
		}
		// unquoted: a path without spaces; if the whole rest exists, take it
		if _, err := os.Stat(s); err == nil {
			out = append(out, s)
			break
		}
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			out = append(out, s)
			break
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}

// pick shows the Windows folder or file dialog (through PowerShell, no admin).
func upPick(folder bool) []string {
	script := `[Console]::OutputEncoding=[Text.Encoding]::UTF8; Add-Type -AssemblyName System.Windows.Forms;
$f=New-Object System.Windows.Forms.Form -Property @{TopMost=$true; ShowInTaskbar=$false};`
	if folder {
		script += `$d=New-Object System.Windows.Forms.FolderBrowserDialog; $d.Description='Folder to send (with all sub-folders)'; $d.ShowNewFolderButton=$false;
if($d.ShowDialog($f) -eq 'OK'){ $d.SelectedPath }`
	} else {
		script += `$d=New-Object System.Windows.Forms.OpenFileDialog; $d.Multiselect=$true; $d.Title='Files to send';
if($d.ShowDialog($f) -eq 'OK'){ $d.FileNames }`
	}
	if folder {
		fmt.Println(" (a folder window opens; it may be behind this one)")
	} else {
		fmt.Println(" (a file window opens; select several with Ctrl or Shift)")
	}
	out, err := exec.Command("powershell", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	if err != nil {
		fmt.Println(" !! could not open the window; drag the files into this window instead.")
		return nil
	}
	var res []string
	for _, l := range strings.Split(strings.TrimPrefix(string(out), "\ufeff"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			res = append(res, l)
		}
	}
	if folder && len(res) > 0 {
		if s := upAsk(" Add another folder? (y/N): "); strings.EqualFold(s, "y") {
			res = append(res, upPick(true)...)
		}
	}
	return res
}

type upConfig struct {
	Server string `json:"server"`
}

func upConfigPath() string {
	d, err := os.UserConfigDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "LanFileServer", "uploader.json")
}

func upLoadConfig() upConfig {
	var c upConfig
	if b, err := os.ReadFile(upConfigPath()); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func upSaveConfig(c upConfig) {
	p := upConfigPath()
	os.MkdirAll(filepath.Dir(p), 0o700)
	b, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(p, b, 0o600)
}

func upHuman(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KB", "MB", "GB"} {
		if f < 1024 {
			if u == "B" {
				return fmt.Sprintf("%d %s", n, u)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return fmt.Sprintf("%.1f TB", f)
}

func upShort(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return "..." + string(r[len(r)-n+3:])
}
