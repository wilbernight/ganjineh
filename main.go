package main

import (
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

//go:embed index.html
var indexHTML []byte

//go:embed login.html
var loginHTML []byte

//go:embed setup.html
var setupHTML []byte

//go:embed favicon.svg
var faviconSVG []byte

//go:embed assets
var assetsFS embed.FS

const version = "5.0"

var (
	root     string
	readOnly bool
)

type entry struct {
	Name    string `json:"name"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"mtime"`
}

func main() {
	// Uploader mode: "LanFileServer.exe -upload [files...]", or files/folders
	// dragged onto the exe (or Uploader.bat).
	if len(os.Args) > 1 {
		a := strings.ToLower(strings.TrimLeft(os.Args[1], "-"))
		if a == "upload" || a == "uploader" || a == "send" {
			runUploader(os.Args[2:])
			return
		}
		if !strings.HasPrefix(os.Args[1], "-") {
			if _, err := os.Stat(os.Args[1]); err == nil {
				runUploader(os.Args[1:])
				return
			}
		}
	}
	exe, _ := os.Executable()
	dir := flag.String("dir", "", "folder to share (default: \"shared\" in the data folder)")
	dataFlag := flag.String("data", "", "folder that holds vault.json (default: found automatically)")
	setTOTP := flag.String("set-totp", "", "use this Authenticator key (base32) from now on")
	port := flag.Int("port", 0, "also serve on this direct port (default: only http://IP/Temporary_Listen_Addresses/)")
	noFTP := flag.Bool("noftp", true, "do not start the FTP server (ports 21 and 2121)")
	flag.BoolVar(&readOnly, "readonly", false, "disable upload/delete/rename")
	hours := flag.Int("session-hours", 12, "how long a login stays valid")
	reset := flag.Bool("reset-totp", false, "generate a new TOTP secret (old app codes stop working)")
	changePW := flag.Bool("change-password", false, "change the startup password")
	showKey := flag.Bool("show-key", false, "show the Authenticator key and QR page (/setup) for 15 minutes")
	autoStart := flag.String("autostart", "", "on = start with Windows for this user (no admin; password saved for this Windows user only), off = stop")
	minimized := flag.Bool("minimized", false, "start with the window minimized (used by start with Windows)")
	flag.Parse()
	if *minimized {
		minimizeConsole()
	}
	ftpEnabled = !*noFTP
	sessionTTL = time.Duration(*hours) * time.Hour

	if p, v := runningInstance(*port); p != 0 {
		fmt.Printf("\n !! Ganjineh (LAN File Server) %s is already running on port %d.\n", v, p)
		fmt.Println("    Close that window first (or end LanFileServer.exe in Task Manager),")
		fmt.Println("    otherwise browsers keep showing the old one.")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	base := findDataDir(filepath.Dir(exe), *dataFlag)
	dataBase = base
	if *dir == "" {
		*dir = filepath.Join(base, "shared")
	}
	created, err := unlockVault(base, *reset, *changePW, *setTOTP)
	if err != nil {
		fmt.Println("\n !!", err)
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		os.Exit(1)
	}

	switch strings.ToLower(*autoStart) {
	case "on":
		if err := enableAutostart(base, unlockedPW); err != nil {
			fmt.Println(" !! Start with Windows:", err)
		} else {
			fmt.Println(" Start with Windows: ON. It starts by itself when this Windows user signs in (no admin needed).")
			fmt.Println("    To stop it: run LanFileServer.exe -autostart off")
		}
	case "off":
		if err := disableAutostart(base); err != nil {
			fmt.Println(" !! Start with Windows:", err)
		} else {
			fmt.Println(" Start with Windows: OFF (saved password removed).")
		}
	case "":
		if *changePW && autostartEnabled(base) { // keep the saved copy in step with the new password
			enableAutostart(base, unlockedPW)
		}
	}
	unlockedPW = ""

	if !demoBuild { // the test build never touches the real settings
		rememberDataDir(base)
	}
	if err := loadAll(); err != nil {
		fmt.Println(" !!", err)
	}
	loadTrash()
	go trashJanitor()
	root, err = filepath.Abs(*dir)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		log.Fatal("cannot create shared folder (choose another with -dir): ", err)
	}
	fmt.Println(" Checking for unencrypted files...")
	if n, bad := encryptPlain(root); n > 0 || bad > 0 {
		fmt.Printf(" Encrypted %d existing item(s)", n)
		if bad > 0 {
			fmt.Printf(", %d could not be encrypted (still readable!)", bad)
		}
		fmt.Println()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			if isSendCodePath(r.URL.Path) { // a unit's short send address: /<code>
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.Write(loginHTML)
				return
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if validSession(r) {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(loginHTML)
	})
	mux.HandleFunc("/s/", func(w http.ResponseWriter, r *http.Request) { // a unit's own send page: /s/<code>
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(loginHTML)
	})
	mux.HandleFunc("/s", func(w http.ResponseWriter, r *http.Request) { // short address: send files
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(loginHTML)
	})
	mux.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(faviconSVG)
	})
	mux.HandleFunc("/assets/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800")
		http.FileServer(http.FS(assetsFS)).ServeHTTP(w, r)
	})
	mux.HandleFunc("/setup", handleSetup)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/api/info", func(w http.ResponseWriter, r *http.Request) {
		host, _ := os.Hostname()
		m := map[string]any{"readOnly": readOnly, "host": host, "version": version}
		infoUsers(r, m)
		if free, total, err := diskSpace(dataBase); err == nil {
			m["diskFree"], m["diskTotal"] = free, total
		}
		writeJSON(w, m)
	})
	mux.HandleFunc("/api/list", handleList)
	mux.HandleFunc("/api/upload", handleUpload)
	mux.HandleFunc("/api/mkdir", handleMkdir)
	mux.HandleFunc("/api/delete", handleDelete)
	mux.HandleFunc("/api/rename", handleRename)
	mux.HandleFunc("/dl/", handleDownload)
	mux.HandleFunc("/api/zip", handleZip)
	mux.HandleFunc("/api/users", handleUsers)
	mux.HandleFunc("/api/brand", handleBrand)
	mux.HandleFunc("/api/send", handleSend)
	mux.HandleFunc("/api/trash", handleTrash)

	handler := logMW(secureMW(authMW(mux)))
	// Port 80 through Windows' own web server (http.sys): on PCs whose firewall
	// drops everything else, this is the path that still gets through.
	sysBase, sysShort, sysErr := startHTTPSys(handler)
	sysOK := sysBase != "" || sysShort

	// Listen on several ports at once: if one is blocked somewhere on the
	// network (443 often is), another still works. IPv4 is bound explicitly so
	// a program already holding the port on IPv4 cannot hide behind IPv6.
	var open []int
	tlsCfg := selfSignedTLS()
	var lns []net.Listener
	try := func(p int) bool {
		l4, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", p))
		if err != nil {
			return false
		}
		markWebOpen(p)
		lns = append(lns, newDualListener(l4, tlsCfg))
		if l6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", p)); err == nil { // http://localhost
			lns = append(lns, newDualListener(l6, tlsCfg))
		}
		open = append(open, p)
		return true
	}
	if *port != 0 {
		if !try(*port) {
			fmt.Printf("\n !! Cannot use port %d: another program is using it (IIS, Skype, VMware, ...).\n", *port)
			fmt.Println("    Close it, or run with another port:  LanFileServer.exe -port 9000")
			fmt.Println("\nPress Enter to exit...")
			fmt.Scanln()
			os.Exit(1)
		}
	} else {
		// All at once, so whichever one the network lets through works.
		// 9100 (RAW/JetDirect) and 631 (IPP) are the ports Windows uses to
		// reach network printers, so network firewalls usually let them through.
		// (515/LPD is not used: browsers refuse to open that port.)
		for _, p := range webPorts {
			if sysOK {
				break // only http://IP/Temporary_Listen_Addresses/ (no admin, firewall lets it through)
			}
			try(p)
		}
		if len(open) == 0 && !sysOK { // everything busy: any free port
			l4, err := net.Listen("tcp4", "0.0.0.0:0")
			if err != nil {
				log.Fatal(err)
			}
			lns = append(lns, newDualListener(l4, tlsCfg))
			open = append(open, l4.Addr().(*net.TCPAddr).Port)
		}
	}
	if len(open) > 0 {
		*port = open[0]
	}
	pstr := func(p int) string {
		if p == 80 {
			return ""
		}
		return fmt.Sprintf(":%d", p)
	}
	ps := pstr(*port)
	fmt.Println("==============================================")
	fmt.Println(" Ganjineh - LAN File Server v" + version)
	fmt.Println(" Shared folder (encrypted):", root)
	fmt.Println(" Data (vault.json, key):", base)
	fmt.Println(" Listening on port(s):", open)
	fmt.Println(" Open in browser on other computers (try in this order):")
	ips := lanIPs()
	if len(ips) == 0 {
		fmt.Println("   !! No network connection found (only this computer can connect).")
	}
	if sysOK {
		fmt.Println("   -- port 80 via Windows web server (works when other ports are blocked):")
		for _, ip := range ips {
			if sysShort {
				fmt.Printf("   http://%s/        (short address)\n", ip)
			}
			if sysBase != "" {
				fmt.Printf("   http://%s%s/\n", ip, sysBase)
			}
		}
		if len(open) > 0 {
			fmt.Println("   -- direct:")
		}
	}
	for _, ip := range ips {
		for _, p := range []int{8080, 80, 443, 9100, 631, 8000, 8888, 8081, 8090} {
			for _, o := range open {
				if o == p {
					fmt.Printf("   http://%s%s\n", ip, pstr(p))
				}
			}
		}
		for _, o := range open {
			if !containsInt(webPorts, o) {
				fmt.Printf("   http://%s%s\n", ip, pstr(o))
			}
		}
		if tlsCfg != nil && len(open) > 0 && open[0] == 443 {
			fmt.Printf("   https://%s   (certificate warning: Advanced > Continue)\n", ip)
		}
	}
	if host, _ := os.Hostname(); host != "" && containsInt(open, 8080) {
		fmt.Printf("   http://%s:8080   (by computer name)\n", host)
	}
	if len(open) > 0 {
		fmt.Printf("   http://localhost%s\n", ps)
	} else if sysBase != "" {
		fmt.Printf("   http://localhost%s/\n", sysBase)
	}
	if sysErr != nil && runtime.GOOS == "windows" {
		fmt.Println("   (port 80 via Windows web server not available:", sysErr, ")")
	}
	if !*noFTP {
		fp := startFTP([]int{21, 2121})
		open = append(open, fp...)
		for _, p := range ftpSniffPorts {
			if containsInt(open, p) {
				fp = append(fp, p)
			}
		}
		if len(fp) > 0 {
			fmt.Println(" FTP (Win+R), user: anything, password: Authenticator code.")
			fmt.Println(" If one is blocked, use a port number that already works in the browser:")
			for _, ip := range ips {
				var ex []string
				for _, p := range fp {
					ex = append(ex, fmt.Sprintf("explorer ftp://%s%s", ip, map[bool]string{true: "", false: fmt.Sprintf(":%d", p)}[p == 21]))
				}
				for i := 0; i < len(ex); i += 3 {
					fmt.Println("   " + strings.Join(ex[i:min(i+3, len(ex))], "   "))
				}
			}
		} else {
			fmt.Println(" FTP: no free port; FTP is off.")
		}
	}
	fmt.Println(" Login: TOTP code (Google/Microsoft Authenticator)")
	_ = showKey // the QR page is now open for 15 minutes after every start
	{
		setupUntil = time.Now().Add(15 * time.Minute)
		if created {
			fmt.Println(" >> NEW secret created. Scan the QR code on THIS computer (next 15 minutes):")
		} else {
			fmt.Println(" Authenticator setup (QR) on this computer (next 15 minutes):")
		}
		setupURL := ""
		if sysBase != "" {
			setupURL = fmt.Sprintf("http://localhost%s/setup", sysBase)
			fmt.Println("  ", setupURL)
		}
		if len(open) > 0 {
			u := fmt.Sprintf("http://localhost%s/setup", ps)
			fmt.Println("  ", u)
			if setupURL == "" {
				setupURL = u
			}
		}
		fmt.Println("   Manual key:", groupSecret(secretB32()))
		if setupURL != "" && !*minimized {
			go func() {
				time.Sleep(time.Second) // let the listeners start first
				openBrowser(setupURL)
			}()
		}
	}
	if readOnly {
		fmt.Println(" Mode: read-only")
	}
	ensureFirewall(open)
	fmt.Println(" Close this window to stop the server.")
	fmt.Println("==============================================")

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10,
		ErrorLog: log.New(io.Discard, "", 0)} // hide TLS warnings from browsers that reject the self-signed cert
	startDemo(handler)
	if len(lns) == 0 {
		select {} // served only through http.sys
	}
	for _, l := range lns[1:] {
		go srv.Serve(l)
	}
	log.Fatal(srv.Serve(lns[0]))
}

// openBrowser opens url in the default browser on this computer.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
}

func lanIPs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

func logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-LFS-Version", version)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "SAMEORIGIN")
		h.Set("Referrer-Policy", "no-referrer")
		if r.URL.Path != "/api/list" && r.URL.Path != "/api/info" {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			log.Printf("%s %s %s", host, r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}

func validName(n string) bool {
	return n != "" && n != "." && n != ".." && !strings.ContainsAny(n, `/\:*?"<>|`)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST required")
		return false
	}
	if readOnly {
		fail(w, http.StatusForbidden, "read-only mode")
		return false
	}
	return true
}

func urlEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

type req struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

func readReq(w http.ResponseWriter, r *http.Request) (*req, bool) {
	var q req
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&q); err != nil {
		fail(w, 400, "bad request")
		return nil, false
	}
	return &q, true
}

func handleList(w http.ResponseWriter, r *http.Request) {
	dir, _, err := resolve(r, r.URL.Query().Get("path"), accRead)
	if err != nil {
		resolveFail(w, err)
		return
	}
	items, err := listDir(dir)
	if err != nil {
		fail(w, 404, "folder not found")
		return
	}
	list := make([]entry, 0, len(items))
	for _, it := range items {
		list = append(list, it.entry)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].IsDir != list[j].IsDir {
			return list[i].IsDir
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
	writeJSON(w, list)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	full, _, err := resolve(r, strings.TrimPrefix(r.URL.Path, "/dl"), accRead)
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	f, m, err := openEncrypted(full)
	if err != nil {
		http.Error(w, "cannot read file", 500)
		return
	}
	defer f.Close()
	webPage := false
	switch strings.ToLower(filepath.Ext(m.Name)) {
	case ".html", ".htm", ".xhtml", ".shtml", ".mht", ".mhtml", ".hta":
		webPage = true // never opened in the browser, download only
	}
	if r.URL.Query().Get("view") == "" || webPage {
		w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlEscape(m.Name))
	} else {
		// never let an uploaded page/script run inside the app's origin
		switch strings.ToLower(filepath.Ext(m.Name)) {
		case ".html", ".htm", ".xhtml", ".shtml", ".svg", ".svgz", ".xml", ".xsl", ".js", ".mjs", ".mht", ".mhtml":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		w.Header().Set("Content-Security-Policy", "script-src 'none'; object-src 'none'; frame-ancestors 'self'")
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, m.Name, st.ModTime(), f)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	if !diskOK() {
		diskFullFail(w)
		return
	}
	dir, _, err := resolve(r, r.URL.Query().Get("path"), accWrite)
	if err != nil {
		resolveFail(w, err)
		return
	}
	if !isDir(dir) {
		fail(w, 404, "folder not found")
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
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(w, 400, "upload interrupted")
			return
		}
		name := filepath.Base(strings.ReplaceAll(part.FileName(), "\\", "/"))
		if part.FormName() != "file" || !validName(name) {
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
		count++
	}
	writeJSON(w, map[string]int{"uploaded": count})
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	q, ok := readReq(w, r)
	if !ok {
		return
	}
	if !validName(q.Name) {
		fail(w, 400, "invalid name")
		return
	}
	dir, _, err := resolve(r, q.Path, accWrite)
	if err != nil && errors.Is(err, errForbidden) {
		resolveFail(w, err)
		return
	}
	if err != nil || !isDir(dir) {
		fail(w, 400, "folder not found")
		return
	}
	if err := makeDir(dir, q.Name); err != nil {
		fail(w, 400, "cannot create folder (exists?)")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	q, ok := readReq(w, r)
	if !ok {
		return
	}
	full, sr, err := resolve(r, q.Path, accModify)
	if errors.Is(err, errForbidden) {
		resolveFail(w, err)
		return
	}
	if err != nil || full == sr {
		fail(w, 400, "invalid path")
		return
	}
	if err := toTrash(full, sr, q.Path, clientIP(r)); err != nil { // recycle bin, not erased
		log.Printf("delete %q: %v", q.Path, err)
		fail(w, 500, "cannot delete")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func handleRename(w http.ResponseWriter, r *http.Request) {
	if !requireWrite(w, r) {
		return
	}
	q, ok := readReq(w, r)
	if !ok {
		return
	}
	full, sr, err := resolve(r, q.Path, accModify)
	if errors.Is(err, errForbidden) {
		resolveFail(w, err)
		return
	}
	if err != nil || full == sr || !validName(q.Name) {
		fail(w, 400, "invalid name")
		return
	}
	if !exists(full) {
		fail(w, 404, "not found")
		return
	}
	if exists(filepath.Join(filepath.Dir(full), nameID(q.Name))) {
		fail(w, 400, "name already exists")
		return
	}
	if err := renameItem(full, q.Name); err != nil {
		fail(w, 500, "cannot rename")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// dataDir returns the folder for config.json and the default "shared" folder:
// next to the exe when writable (portable), otherwise the user's own
// AppData folder, so the program never needs admin rights to start.
func dataDir(exeDir string) string {
	if writable(exeDir) {
		return exeDir
	}
	if d, err := os.UserConfigDir(); err == nil {
		d = filepath.Join(d, "LanFileServer")
		if os.MkdirAll(d, 0o755) == nil && writable(d) {
			// keep the existing key if one was created next to the exe earlier
			if _, err := os.Stat(filepath.Join(d, "config.json")); os.IsNotExist(err) {
				if b, err := os.ReadFile(filepath.Join(exeDir, "config.json")); err == nil {
					os.WriteFile(filepath.Join(d, "config.json"), b, 0o600)
				}
			}
			return d
		}
	}
	return exeDir
}

func writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".lfs-write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}

var webPorts = []int{443, 8080, 80, 9100, 631, 8000, 8888, 8081, 8090}

func containsInt(a []int, v int) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
