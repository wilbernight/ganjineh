package main

// Built-in FTP server, so the shared folder also opens from Win+R:
//   explorer ftp://IP        (user: anything, password: the 6-digit TOTP code)
// The code is checked once; the same code then keeps working from that IP
// for the session length, because Explorer reconnects with saved credentials.
// Files stay encrypted on disk; FTP sees the real names and contents.

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ftpMu    sync.Mutex
	ftpLogin = map[string]ftpCred{} // ip -> accepted code
)

type ftpCred struct {
	pass string
	exp  time.Time
}

const (
	ftpPasvFirst = 50000
	ftpPasvLast  = 50100
)

// FTP also runs on web ports that are already open in the firewall: a client
// that connects and stays silent (FTP clients wait for the server to speak
// first) gets an FTP session; browsers send their request at once and get
// the web app. 80, 443 and 8080 (the main browser ports) never do this.
var (
	ftpEnabled    bool
	ftpSniffPorts = []int{9100, 631, 8000, 8888, 8081, 8090}
	ftpDataPorts  = []int{8000, 8888, 8081, 8090, 9100, 631}

	pendMu  sync.Mutex
	webOpen = map[int]bool{}           // web ports listening on IPv4
	pending = map[int][]*pendingData{} // port -> data connections expected
)

type pendingData struct {
	ip string
	ch chan net.Conn
}

func markWebOpen(p int) { pendMu.Lock(); webOpen[p] = true; pendMu.Unlock() }

func isSniffPort(p int) bool { return ftpEnabled && containsInt(ftpSniffPorts, p) }

// takePending hands a new connection on a shared port to a waiting FTP
// transfer from the same client IP, if there is one.
func takePending(port int, ip string) chan net.Conn {
	pendMu.Lock()
	defer pendMu.Unlock()
	l := pending[port]
	for i, pd := range l {
		if pd.ip == ip {
			pending[port] = append(l[:i:i], l[i+1:]...)
			return pd.ch
		}
	}
	return nil
}

func addPending(port int, ip string) *pendingData {
	pendMu.Lock()
	defer pendMu.Unlock()
	if !webOpen[port] {
		return nil
	}
	for _, pd := range pending[port] {
		if pd.ip == ip {
			return nil
		}
	}
	pd := &pendingData{ip, make(chan net.Conn, 1)}
	pending[port] = append(pending[port], pd)
	return pd
}

func dropPending(port int, pd *pendingData) {
	pendMu.Lock()
	defer pendMu.Unlock()
	l := pending[port]
	for i, x := range l {
		if x == pd {
			pending[port] = append(l[:i:i], l[i+1:]...)
			break
		}
	}
	select { // a connection may have arrived just now
	case c := <-pd.ch:
		c.Close()
	default:
	}
}

func serveFTPConn(c net.Conn) { (&ftpSession{c: c, cwd: "/"}).serve() }

// startFTP listens on the given control ports; returns the ports opened.
func startFTP(ports []int) []int {
	var open []int
	for _, p := range ports {
		ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", p))
		if err != nil {
			continue
		}
		open = append(open, p)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						time.Sleep(50 * time.Millisecond)
						continue
					}
					return
				}
				go serveFTPConn(c)
			}
		}()
	}
	return open
}

func ftpCheckPass(ip, pass string) (bool, string) {
	pass = strings.TrimSpace(pass)
	ftpMu.Lock()
	defer ftpMu.Unlock()
	if cr, ok := ftpLogin[ip]; ok && time.Now().Before(cr.exp) &&
		subtle.ConstantTimeCompare([]byte(cr.pass), []byte(pass)) == 1 {
		return true, ""
	}
	mu.Lock()
	fi := failures[ip]
	if fi != nil && time.Now().Before(fi.until) {
		mu.Unlock()
		return false, "Too many wrong codes, wait a minute."
	}
	mu.Unlock()
	if !verifyTOTP(pass) {
		mu.Lock()
		if failures[ip] == nil {
			failures[ip] = &failInfo{}
		}
		f := failures[ip]
		f.count++
		if f.count >= 5 {
			f.count = 0
			f.until = time.Now().Add(time.Minute)
		}
		mu.Unlock()
		return false, "Wrong code. Password = 6-digit code from the Authenticator app."
	}
	mu.Lock()
	delete(failures, ip)
	mu.Unlock()
	ftpLogin[ip] = ftpCred{pass, time.Now().Add(sessionTTL)}
	return true, ""
}

type ftpSession struct {
	c      net.Conn
	r      *bufio.Reader
	ip     string
	user   string
	authed bool
	cwd    string
	pasv   net.Listener
	pend   *pendingData // passive data expected on a shared web port
	pendP  int
	port   string // active mode target
	rest   int64
	rnfr   string
}

func (s *ftpSession) reply(code int, msg string) {
	lines := strings.Split(msg, "\n")
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		fmt.Fprintf(s.c, "%d%s%s\r\n", code, sep, l)
	}
}

func (s *ftpSession) serve() {
	defer s.c.Close()
	defer s.closePasv()
	s.ip, _, _ = net.SplitHostPort(s.c.RemoteAddr().String())
	s.r = bufio.NewReaderSize(s.c, 4096)
	s.reply(220, "LAN File Server v"+version+" FTP. Password = 6-digit Authenticator code.")
	for {
		s.c.SetReadDeadline(time.Now().Add(15 * time.Minute))
		line, err := s.r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		if cmd == "PASS" {
			logf("%s FTP PASS ***", s.ip)
		} else {
			logf("%s FTP %s", s.ip, line)
		}
		if !s.authed {
			switch cmd {
			case "USER", "PASS", "QUIT", "FEAT", "SYST", "OPTS", "NOOP", "AUTH":
			default:
				s.reply(530, "Please log in (password = Authenticator code).")
				continue
			}
		}
		if s.handle(cmd, arg) {
			return
		}
	}
}

func logf(f string, a ...any) {
	fmt.Printf("%s "+f+"\n", append([]any{time.Now().Format("2006/01/02 15:04:05")}, a...)...)
}

func (s *ftpSession) abs(arg string) string {
	arg = strings.ReplaceAll(arg, "\\", "/")
	if !strings.HasPrefix(arg, "/") {
		arg = path.Join(s.cwd, arg)
	}
	return path.Clean("/" + arg)
}

func (s *ftpSession) phys(arg string) (string, string, bool) {
	lp := s.abs(arg)
	p, err := physPath(lp)
	if err != nil {
		s.reply(553, "Invalid file name.")
		return "", "", false
	}
	return p, lp, true
}

func (s *ftpSession) writable() bool {
	if readOnly {
		s.reply(550, "Server is in read-only mode.")
		return false
	}
	return true
}

// handle runs one command; true means close the connection.
func (s *ftpSession) handle(cmd, arg string) bool {
	switch cmd {
	case "USER":
		s.user, s.authed = arg, false
		if strings.EqualFold(arg, "anonymous") || strings.EqualFold(arg, "ftp") {
			s.reply(331, "Anonymous login is not allowed. Enter the Authenticator code as password.")
		} else {
			s.reply(331, "Password = 6-digit code from the Authenticator app.")
		}
	case "PASS":
		if s.user == "" {
			s.reply(503, "Send USER first.")
			break
		}
		if strings.EqualFold(s.user, "anonymous") || strings.EqualFold(s.user, "ftp") {
			s.reply(530, "Anonymous login is not allowed.") // Explorer tries this first; not counted as a wrong code
			break
		}
		if ok, why := ftpCheckPass(s.ip, arg); ok {
			s.authed = true
			s.reply(230, "Logged in.")
		} else {
			time.Sleep(time.Second)
			s.reply(530, why)
		}
	case "AUTH":
		s.reply(502, "TLS not supported; use plain FTP on the LAN.")
	case "SYST":
		s.reply(215, "UNIX Type: L8")
	case "FEAT":
		s.reply(211, "Features:\n UTF8\n SIZE\n MDTM\n REST STREAM\n PASV\n EPSV\n MLST type*;size*;modify*;\nEnd")
	case "OPTS":
		s.reply(200, "OK")
	case "NOOP", "ALLO", "MODE", "STRU":
		s.reply(200, "OK")
	case "TYPE":
		s.reply(200, "Type set to "+strings.ToUpper(arg))
	case "PWD", "XPWD":
		s.reply(257, `"`+strings.ReplaceAll(s.cwd, `"`, `""`)+`" is the current directory`)
	case "CWD", "XCWD":
		p, lp, ok := s.phys(arg)
		if !ok {
			break
		}
		if !isDir(p) {
			s.reply(550, "No such folder.")
			break
		}
		s.cwd = lp
		s.reply(250, "OK")
	case "CDUP", "XCUP":
		s.cwd = path.Dir(s.cwd)
		s.reply(250, "OK")
	case "PASV":
		s.cmdPasv(false)
	case "EPSV":
		s.cmdPasv(true)
	case "PORT":
		s.cmdPort(arg)
	case "REST":
		n, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
		if err != nil || n < 0 {
			s.reply(501, "Bad offset.")
			break
		}
		s.rest = n
		s.reply(350, "Restarting at "+strconv.FormatInt(n, 10))
	case "LIST", "NLST", "MLSD":
		s.cmdList(cmd, arg)
	case "MLST":
		p, lp, ok := s.phys(arg)
		if !ok {
			break
		}
		e, ok := statEntry(p, path.Base(lp))
		if !ok {
			s.reply(550, "Not found.")
			break
		}
		s.reply(250, "Listing\n "+mlsdLine(e)+"\nEnd")
	case "SIZE", "MDTM":
		p, lp, ok := s.phys(arg)
		if !ok {
			break
		}
		e, ok := statEntry(p, path.Base(lp))
		if !ok || e.IsDir {
			s.reply(550, "Not a file.")
			break
		}
		if cmd == "SIZE" {
			s.reply(213, strconv.FormatInt(e.Size, 10))
		} else {
			s.reply(213, time.Unix(e.ModTime, 0).UTC().Format("20060102150405"))
		}
	case "RETR":
		s.cmdRetr(arg)
	case "STOR":
		s.cmdStor(arg)
	case "DELE":
		if !s.writable() {
			break
		}
		p, lp, ok := s.phys(arg)
		if !ok {
			break
		}
		if p == root || isDir(p) || toTrash(p, root, lp, s.ip) != nil {
			s.reply(550, "Cannot delete.")
			break
		}
		s.reply(250, "Deleted.")
	case "MKD", "XMKD":
		if !s.writable() {
			break
		}
		lp := s.abs(arg)
		parent, err := physPath(path.Dir(lp))
		name := path.Base(lp)
		if err != nil || !validName(name) || !isDir(parent) || makeDir(parent, name) != nil {
			s.reply(550, "Cannot create folder.")
			break
		}
		s.reply(257, `"`+lp+`" created`)
	case "RMD", "XRMD":
		if !s.writable() {
			break
		}
		p, _, ok := s.phys(arg)
		if !ok {
			break
		}
		if p == root || !isDir(p) {
			s.reply(550, "Not a folder.")
			break
		}
		if items, _ := listDir(p); len(items) > 0 {
			s.reply(550, "Folder is not empty.")
			break
		}
		if os.RemoveAll(p) != nil {
			s.reply(550, "Cannot remove folder.")
			break
		}
		s.reply(250, "Removed.")
	case "RNFR":
		if !s.writable() {
			break
		}
		p, _, ok := s.phys(arg)
		if !ok {
			break
		}
		if p == root || !exists(p) {
			s.reply(550, "Not found.")
			break
		}
		s.rnfr = p
		s.reply(350, "Ready for RNTO.")
	case "RNTO":
		if s.rnfr == "" {
			s.reply(503, "Send RNFR first.")
			break
		}
		src := s.rnfr
		s.rnfr = ""
		lp := s.abs(arg)
		dstDir, err := physPath(path.Dir(lp))
		name := path.Base(lp)
		if err != nil || !validName(name) {
			s.reply(553, "Invalid name.")
			break
		}
		if dstDir != filepath.Dir(src) {
			s.reply(553, "Moving to another folder is not supported; rename only.")
			break
		}
		if exists(filepath.Join(dstDir, nameID(name))) {
			s.reply(553, "Name already exists.")
			break
		}
		if renameItem(src, name) != nil {
			s.reply(550, "Cannot rename.")
			break
		}
		s.reply(250, "Renamed.")
	case "ABOR":
		s.closePasv()
		s.reply(226, "Aborted.")
	case "STAT":
		s.reply(211, "LAN File Server FTP, logged in.")
	case "HELP":
		s.reply(214, "Use a normal FTP client or Windows Explorer.")
	case "QUIT":
		s.reply(221, "Bye.")
		return true
	default:
		s.reply(502, "Command not implemented.")
	}
	return false
}

func (s *ftpSession) closePasv() {
	if s.pasv != nil {
		s.pasv.Close()
		s.pasv = nil
	}
	if s.pend != nil {
		dropPending(s.pendP, s.pend)
		s.pend = nil
	}
}

func (s *ftpSession) cmdPasv(ext bool) {
	s.closePasv()
	s.port = ""
	ip := s.c.LocalAddr().(*net.TCPAddr).IP.To4()
	if ip == nil && !ext {
		s.reply(425, "Use EPSV.")
		return
	}
	pasvReply := func(port int) {
		if ext {
			s.reply(229, fmt.Sprintf("Entering Extended Passive Mode (|||%d|)", port))
		} else {
			s.reply(227, fmt.Sprintf("Entering Passive Mode (%d,%d,%d,%d,%d,%d)", ip[0], ip[1], ip[2], ip[3], port>>8, port&255))
		}
	}
	// Prefer a web port that is already open in the firewall (not the one
	// this control connection uses, so a new control connection is never
	// mistaken for data).
	ctrlPort := s.c.LocalAddr().(*net.TCPAddr).Port
	for _, p := range ftpDataPorts {
		if p == ctrlPort {
			continue
		}
		if pd := addPending(p, s.ip); pd != nil {
			s.pend, s.pendP = pd, p
			pasvReply(p)
			return
		}
	}
	var ln net.Listener
	for p := ftpPasvFirst; p <= ftpPasvLast; p++ {
		if l, err := net.Listen("tcp", fmt.Sprintf(":%d", p)); err == nil {
			ln = l
			break
		}
	}
	if ln == nil {
		l, err := net.Listen("tcp", ":0")
		if err != nil {
			s.reply(425, "Cannot open data port.")
			return
		}
		ln = l
	}
	s.pasv = ln
	pasvReply(ln.Addr().(*net.TCPAddr).Port)
}

func (s *ftpSession) cmdPort(arg string) {
	f := strings.Split(strings.TrimSpace(arg), ",")
	if len(f) != 6 {
		s.reply(501, "Bad PORT.")
		return
	}
	n := make([]int, 6)
	for i, x := range f {
		v, err := strconv.Atoi(x)
		if err != nil || v < 0 || v > 255 {
			s.reply(501, "Bad PORT.")
			return
		}
		n[i] = v
	}
	host := fmt.Sprintf("%d.%d.%d.%d", n[0], n[1], n[2], n[3])
	if host != s.ip { // never connect anywhere except back to the client
		s.reply(500, "PORT must point to your own address.")
		return
	}
	s.closePasv()
	s.port = net.JoinHostPort(host, strconv.Itoa(n[4]<<8|n[5]))
	s.reply(200, "PORT OK")
}

func (s *ftpSession) dataConn() (net.Conn, bool) {
	if s.pasv == nil && s.port == "" && s.pend == nil {
		s.reply(425, "Use PASV or PORT first.")
		return nil, false
	}
	s.reply(150, "Opening data connection.")
	var c net.Conn
	var err error
	if s.pend != nil {
		pd, p := s.pend, s.pendP
		s.pend = nil
		select {
		case c = <-pd.ch:
		case <-time.After(30 * time.Second):
			dropPending(p, pd)
			err = fmt.Errorf("timeout")
		}
	} else if s.pasv != nil {
		ln := s.pasv
		s.pasv = nil
		if tl, ok := ln.(*net.TCPListener); ok {
			tl.SetDeadline(time.Now().Add(30 * time.Second))
		}
		for {
			c, err = ln.Accept()
			if err != nil {
				break
			}
			if h, _, _ := net.SplitHostPort(c.RemoteAddr().String()); h == s.ip {
				break
			}
			c.Close() // someone else grabbed the data port
		}
		ln.Close()
	} else {
		c, err = net.DialTimeout("tcp", s.port, 15*time.Second)
		s.port = ""
	}
	if err != nil {
		s.reply(425, "Cannot open data connection.")
		return nil, false
	}
	return c, true
}

func statEntry(p, name string) (entry, bool) {
	st, err := os.Stat(p)
	if err != nil {
		return entry{}, false
	}
	if st.IsDir() {
		if p == root {
			name = "/"
		}
		return entry{name, true, 0, st.ModTime().Unix()}, true
	}
	f, err := os.Open(p)
	if err != nil {
		return entry{}, false
	}
	m, err := readHeader(f)
	f.Close()
	if err != nil {
		return entry{}, false
	}
	return entry{m.Name, false, m.Size, st.ModTime().Unix()}, true
}

func mlsdLine(e entry) string {
	t := "file"
	if e.IsDir {
		t = "dir"
	}
	return fmt.Sprintf("type=%s;size=%d;modify=%s; %s", t, e.Size,
		time.Unix(e.ModTime, 0).UTC().Format("20060102150405"), e.Name)
}

func listLine(e entry) string {
	mode := "-rw-r--r--"
	if e.IsDir {
		mode = "drwxr-xr-x"
	}
	t := time.Unix(e.ModTime, 0)
	ts := t.Format("Jan _2 15:04")
	if time.Since(t) > 180*24*time.Hour || t.After(time.Now().Add(time.Hour)) {
		ts = t.Format("Jan _2  2006")
	}
	return fmt.Sprintf("%s 1 owner group %13d %s %s", mode, e.Size, ts, e.Name)
}

func (s *ftpSession) cmdList(cmd, arg string) {
	// drop "ls" style options such as -la
	for strings.HasPrefix(arg, "-") {
		_, arg, _ = strings.Cut(arg, " ")
	}
	p, lp, ok := s.phys(arg)
	if !ok {
		return
	}
	var list []entry
	if isDir(p) {
		items, err := listDir(p)
		if err != nil {
			s.reply(550, "Cannot read folder.")
			return
		}
		for _, it := range items {
			list = append(list, it.entry)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].IsDir != list[j].IsDir {
				return list[i].IsDir
			}
			return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
		})
	} else if e, ok := statEntry(p, path.Base(lp)); ok && cmd != "MLSD" {
		list = []entry{e}
	} else {
		s.reply(550, "No such folder.")
		return
	}
	dc, ok := s.dataConn()
	if !ok {
		return
	}
	w := bufio.NewWriter(dc)
	for _, e := range list {
		switch cmd {
		case "NLST":
			w.WriteString(e.Name + "\r\n")
		case "MLSD":
			w.WriteString(mlsdLine(e) + "\r\n")
		default:
			w.WriteString(listLine(e) + "\r\n")
		}
	}
	err := w.Flush()
	dc.Close()
	if err != nil {
		s.reply(426, "Transfer aborted.")
		return
	}
	s.reply(226, "Done.")
}

func (s *ftpSession) cmdRetr(arg string) {
	rest := s.rest
	s.rest = 0
	p, _, ok := s.phys(arg)
	if !ok {
		return
	}
	if isDir(p) {
		s.reply(550, "Not a file.")
		return
	}
	f, _, err := openEncrypted(p)
	if err != nil {
		s.reply(550, "File not found.")
		return
	}
	defer f.Close()
	if rest > 0 {
		if _, err := f.Seek(rest, io.SeekStart); err != nil {
			s.reply(551, "Bad restart offset.")
			return
		}
	}
	dc, ok := s.dataConn()
	if !ok {
		return
	}
	_, err = io.Copy(dc, f)
	dc.Close()
	if err != nil {
		s.reply(426, "Transfer aborted.")
		return
	}
	s.reply(226, "Transfer complete.")
}

func (s *ftpSession) cmdStor(arg string) {
	rest := s.rest
	s.rest = 0
	if !s.writable() {
		return
	}
	if rest > 0 {
		s.reply(550, "Resume upload is not supported; upload the whole file.")
		return
	}
	lp := s.abs(arg)
	dir, err := physPath(path.Dir(lp))
	name := path.Base(lp)
	if err != nil || !validName(name) || !isDir(dir) {
		s.reply(553, "Invalid file name or folder.")
		return
	}
	dst := filepath.Join(dir, nameID(name))
	if isDir(dst) {
		s.reply(553, "A folder with this name exists.")
		return
	}
	dc, ok := s.dataConn()
	if !ok {
		return
	}
	err = writeEncrypted(dst, name, dc)
	dc.Close()
	if err != nil {
		s.reply(451, "Upload failed.")
		return
	}
	s.reply(226, "Upload complete.")
}
