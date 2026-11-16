package main

// Encrypted storage. Nothing readable is written to disk:
//   - vault.json holds the random master key, sealed with a key derived from
//     the startup password (Argon2id), and the TOTP secret sealed with the
//     master key. Without the password neither can be recovered.
//   - Every file/folder name on disk is an HMAC of the real name (26 chars).
//   - Folders keep their real name encrypted in a ".n" file inside them.
//   - Files: 4 KiB header (encrypted real name, per-file key, size) followed
//     by the content in 64 KiB AES-256-GCM chunks (chunk index as nonce).

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	hdrSize  = 4096
	chunk    = 64 << 10
	tagSize  = 16
	magic    = "LFSv1\x00"
	dirNameF = ".n"
)

var (
	encKey, nameKey []byte
	idRe            = regexp.MustCompile(`^[a-z2-7]{26}$`)
	idEnc           = base32.StdEncoding.WithPadding(base32.NoPadding)
	errCorrupt      = errors.New("file is damaged or was not made with this password")
)

type vaultFile struct {
	V       int    `json:"v"`
	Salt    string `json:"salt"`
	Time    uint32 `json:"argonTime"`
	Mem     uint32 `json:"argonMemKiB"`
	Threads uint8  `json:"argonThreads"`
	Key     string `json:"masterKey"`  // sealed with the password key
	TOTP    string `json:"totpSecret"` // sealed with the master key
}

/* ---------- primitives ---------- */

func aead(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return a
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func seal(key, pt, ad []byte) []byte {
	a := aead(key)
	n := randBytes(a.NonceSize())
	return a.Seal(n, n, pt, ad)
}

func unseal(key, ct, ad []byte) ([]byte, error) {
	a := aead(key)
	if len(ct) < a.NonceSize()+a.Overhead() {
		return nil, errCorrupt
	}
	pt, err := a.Open(nil, ct[:a.NonceSize()], ct[a.NonceSize():], ad)
	if err != nil {
		return nil, errCorrupt
	}
	return pt, nil
}

func subKey(mk []byte, label string) []byte {
	m := hmac.New(sha256.New, mk)
	m.Write([]byte(label))
	return m.Sum(nil)
}

func chunkNonce(i uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], i)
	return n
}

// nameID is the on-disk name for a real name (same name -> same id).
func nameID(name string) string {
	m := hmac.New(sha256.New, nameKey)
	m.Write([]byte(name))
	return strings.ToLower(idEnc.EncodeToString(m.Sum(nil)[:16]))
}

/* ---------- unlock at startup ---------- */

var stdin = bufio.NewReader(os.Stdin)

// unlockedPW is the password that opened the vault; main uses it once for
// "start with Windows" and then clears it.
var unlockedPW string

func readSecretLine(prompt string) string {
	fmt.Print(prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err == nil {
			return strings.TrimRight(string(b), "\r\n")
		}
	}
	s, err := stdin.ReadString('\n')
	if err != nil && s == "" { // input closed: asking again would loop forever
		fmt.Println("\n !! No input. Run LanFileServer.exe in its own console window.")
		os.Exit(1)
	}
	return strings.TrimRight(s, "\r\n")
}

func passKey(pw string, v *vaultFile, salt []byte) []byte {
	return argon2.IDKey([]byte(pw), salt, v.Time, v.Mem, v.Threads, 32)
}

func askNewPassword() string {
	for {
		p1 := readSecretLine(" New password (min 8 characters, English letters/digits): ")
		if len(p1) < 8 {
			fmt.Println(" !! Too short.")
			continue
		}
		if p1 != readSecretLine(" Repeat password: ") {
			fmt.Println(" !! The two passwords are different.")
			continue
		}
		return p1
	}
}

func saveVault(p string, v *vaultFile) error {
	data, _ := json.MarshalIndent(v, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// unlockVault asks for the password (creating the vault on first run) and
// loads the keys and the TOTP secret. Returns true when a new TOTP secret was made.
// parseTOTPKey accepts a base32 Authenticator key ("NQYV PHV3 ..." or "nqyv...").
func parseTOTPKey(k string) ([]byte, error) {
	k = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(strings.TrimSpace(k)))
	s, err := b32.DecodeString(k)
	if err != nil || len(s) < 10 {
		return nil, errors.New("not a valid Authenticator key (letters A-Z and digits 2-7)")
	}
	return s, nil
}

func unlockVault(base string, resetTOTP, changePW bool, setKey string) (bool, error) {
	os.MkdirAll(base, 0o700)
	vp := filepath.Join(base, "vault.json")
	legacy := filepath.Join(base, "config.json")
	b64 := base64.StdEncoding
	var v vaultFile
	var mk []byte
	newTOTP := false

	if data, err := os.ReadFile(vp); err == nil {
		if json.Unmarshal(data, &v) != nil || v.V != 1 {
			return false, errors.New("vault.json is damaged")
		}
		salt, _ := b64.DecodeString(v.Salt)
		sealed, _ := b64.DecodeString(v.Key)
		fmt.Println("==============================================")
		fmt.Println(" LAN File Server v" + version + " - files are encrypted")
		if pw, ok := savedPassword(base); ok && !changePW {
			if k, err := unseal(passKey(pw, &v, salt), sealed, []byte("master")); err == nil {
				mk, unlockedPW = k, pw
				fmt.Println(" Unlocked with the password saved for this Windows user (start with Windows).")
			} else {
				fmt.Println(" !! The saved password no longer works; type it below.")
			}
		}
		for try := 1; mk == nil; try++ {
			pw := readSecretLine(" Password: ")
			if k, err := unseal(passKey(pw, &v, salt), sealed, []byte("master")); err == nil {
				mk, unlockedPW = k, pw
				break
			}
			fmt.Println(" !! Wrong password.")
			if try >= 5 {
				return false, errors.New("wrong password")
			}
		}
		if changePW {
			fmt.Println(" Choose the NEW password.")
			pw := askNewPassword()
			salt = randBytes(16)
			v.Salt = b64.EncodeToString(salt)
			v.Key = b64.EncodeToString(seal(passKey(pw, &v, salt), mk, []byte("master")))
			if err := saveVault(vp, &v); err != nil {
				return false, err
			}
			unlockedPW = pw
			fmt.Println(" Password changed.")
		}
	} else {
		fmt.Println("==============================================")
		fmt.Println(" LAN File Server v" + version + " - first run")
		fmt.Println(" Choose a password. It is asked every time the program starts.")
		fmt.Println(" All stored files are encrypted with it.")
		fmt.Println(" !! If you forget it, the files can NOT be recovered by anyone.")
		pw := askNewPassword()
		unlockedPW = pw
		v = vaultFile{V: 1, Time: 3, Mem: 64 * 1024, Threads: 4}
		salt := randBytes(16)
		mk = randBytes(32)
		v.Salt = b64.EncodeToString(salt)
		v.Key = b64.EncodeToString(seal(passKey(pw, &v, salt), mk, []byte("master")))
	}
	encKey, nameKey = subKey(mk, "content"), subKey(mk, "names")
	totpKey := subKey(mk, "totp")
	usersKey = subKey(mk, "users")

	firstRun := v.TOTP == ""
	if setKey != "" {
		s, err := parseTOTPKey(setKey)
		if err != nil {
			return false, err
		}
		totpSecret = s
		v.TOTP = b64.EncodeToString(seal(totpKey, totpSecret, []byte("totp")))
		fmt.Println(" Authenticator key replaced with the one given by -set-totp.")
	} else if v.TOTP != "" && !resetTOTP {
		ct, _ := b64.DecodeString(v.TOTP)
		s, err := unseal(totpKey, ct, []byte("totp"))
		if err != nil {
			return false, errors.New("vault.json is damaged (TOTP)")
		}
		totpSecret = s
	} else {
		// keep the authenticator code of an older version if there is one
		if data, err := os.ReadFile(legacy); err == nil && !resetTOTP {
			var c config
			if json.Unmarshal(data, &c) == nil {
				if s, err := b32.DecodeString(strings.ToUpper(c.Secret)); err == nil && len(s) >= 10 {
					totpSecret = s
				}
			}
		}
		for totpSecret == nil && firstRun && !resetTOTP {
			fmt.Println(" If your Authenticator app already has a key for this server, type it now")
			k := strings.TrimSpace(readSecretLine(" so the same codes keep working (Enter = make a new key): "))
			if k == "" {
				break
			}
			if s, err := parseTOTPKey(k); err == nil {
				totpSecret = s
			} else {
				fmt.Println(" !!", err)
			}
		}
		if totpSecret == nil {
			totpSecret = randBytes(20)
			newTOTP = true
		}
		v.TOTP = b64.EncodeToString(seal(totpKey, totpSecret, []byte("totp")))
	}
	if err := saveVault(vp, &v); err != nil {
		return false, err
	}
	os.Remove(legacy) // the plain-text secret is no longer needed
	return newTOTP, nil
}

/* ---------- paths ---------- */

// physPath maps a client path ("/a/b") to the encrypted path on disk.
// Every part is hashed, so "..", drive letters etc. can never escape root.
func physPath(p string) (string, error) { return mapPath(root, p) }

// mapPath is physPath below another root (private folders).
func mapPath(base, p string) (string, error) {
	clean := path.Clean("/" + strings.ReplaceAll(p, "\\", "/"))
	full := base
	if clean == "/" {
		return full, nil
	}
	for _, part := range strings.Split(clean[1:], "/") {
		if !validName(part) {
			return "", errors.New("invalid path")
		}
		full = filepath.Join(full, nameID(part))
	}
	return full, nil
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// uniqueLogical returns name, or "name (1).ext"... if it is taken in dir.
func uniqueLogical(dir, name string) string {
	if !exists(filepath.Join(dir, nameID(name))) {
		return name
	}
	ext := filepath.Ext(name)
	b := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		c := fmt.Sprintf("%s (%d)%s", b, i, ext)
		if !exists(filepath.Join(dir, nameID(c))) {
			return c
		}
	}
}

/* ---------- folders ---------- */

func writeDirName(dir, name string) error {
	tmp := filepath.Join(dir, dirNameF+".tmp")
	if err := os.WriteFile(tmp, seal(encKey, []byte(name), []byte("dir")), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, dirNameF))
}

func readDirName(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, dirNameF))
	if err != nil {
		return "", err
	}
	n, err := unseal(encKey, b, []byte("dir"))
	return string(n), err
}

func makeDir(parent, name string) error {
	p := filepath.Join(parent, nameID(name))
	if err := os.Mkdir(p, 0o700); err != nil {
		return err
	}
	if err := writeDirName(p, name); err != nil {
		os.RemoveAll(p)
		return err
	}
	return nil
}

/* ---------- files ---------- */

type fileMeta struct {
	Name string `json:"n"`
	Key  []byte `json:"k"`
	Size int64  `json:"s"`
}

func writeHeader(f *os.File, m fileMeta) error {
	js, _ := json.Marshal(m)
	ct := seal(encKey, js, []byte(magic))
	if len(magic)+2+len(ct) > hdrSize {
		return errors.New("name too long")
	}
	buf := make([]byte, hdrSize)
	copy(buf, magic)
	binary.BigEndian.PutUint16(buf[len(magic):], uint16(len(ct)))
	copy(buf[len(magic)+2:], ct)
	_, err := f.WriteAt(buf, 0)
	return err
}

func readHeader(f io.ReaderAt) (fileMeta, error) {
	var m fileMeta
	buf := make([]byte, hdrSize)
	if n, _ := f.ReadAt(buf, 0); n != hdrSize || string(buf[:len(magic)]) != magic {
		return m, errCorrupt
	}
	l := int(binary.BigEndian.Uint16(buf[len(magic):]))
	if len(magic)+2+l > hdrSize {
		return m, errCorrupt
	}
	js, err := unseal(encKey, buf[len(magic)+2:len(magic)+2+l], []byte(magic))
	if err != nil || json.Unmarshal(js, &m) != nil || len(m.Key) != 32 || m.Size < 0 {
		return m, errCorrupt
	}
	return m, nil
}

func hasMagic(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, len(magic))
	n, _ := f.ReadAt(b, 0)
	return n == len(magic) && string(b) == magic
}

type encWriter struct {
	f    *os.File
	a    cipher.AEAD
	buf  []byte
	idx  uint64
	off  int64
	size int64
}

func (w *encWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		k := min(chunk-len(w.buf), len(p))
		w.buf = append(w.buf, p[:k]...)
		p = p[k:]
		if len(w.buf) == chunk {
			if err := w.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (w *encWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	ct := w.a.Seal(nil, chunkNonce(w.idx), w.buf, nil)
	if _, err := w.f.WriteAt(ct, w.off); err != nil {
		return err
	}
	w.off += int64(len(ct))
	w.size += int64(len(w.buf))
	w.idx++
	w.buf = w.buf[:0]
	return nil
}

// writeEncrypted stores r as dst (written to dst.part first, then renamed).
func writeEncrypted(dst, name string, r io.Reader) error {
	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	key := randBytes(32)
	w := &encWriter{f: f, a: aead(key), buf: make([]byte, 0, chunk), off: hdrSize}
	_, err = io.Copy(w, r)
	if err == nil {
		err = w.flush()
	}
	if err == nil {
		err = writeHeader(f, fileMeta{Name: name, Key: key, Size: w.size})
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// decReader decrypts a stored file; it supports Seek, so ranges/video work.
type decReader struct {
	f    *os.File
	a    cipher.AEAD
	size int64
	pos  int64
	cidx int64
	ct   []byte
	pt   []byte
}

func openEncrypted(p string) (*decReader, fileMeta, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fileMeta{}, err
	}
	m, err := readHeader(f)
	if err != nil {
		f.Close()
		return nil, m, err
	}
	return &decReader{f: f, a: aead(m.Key), size: m.Size, cidx: -1, ct: make([]byte, chunk+tagSize)}, m, nil
}

func (d *decReader) Read(b []byte) (int, error) {
	if d.pos >= d.size {
		return 0, io.EOF
	}
	ci := d.pos / chunk
	if ci != d.cidx {
		n := min(int64(chunk), d.size-ci*chunk) + tagSize
		ct := d.ct[:n]
		if k, _ := d.f.ReadAt(ct, hdrSize+ci*(chunk+tagSize)); int64(k) != n {
			return 0, errCorrupt
		}
		pt, err := d.a.Open(d.pt[:0], chunkNonce(uint64(ci)), ct, nil)
		if err != nil {
			return 0, errCorrupt
		}
		d.pt, d.cidx = pt, ci
	}
	n := copy(b, d.pt[d.pos-ci*chunk:])
	d.pos += int64(n)
	return n, nil
}

func (d *decReader) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		off += d.pos
	case io.SeekEnd:
		off += d.size
	}
	if off < 0 {
		return 0, errors.New("negative position")
	}
	d.pos = off
	return off, nil
}

func (d *decReader) Close() error { return d.f.Close() }

// renameItem gives an item a new real name (and the matching on-disk id).
func renameItem(phys, newName string) error {
	dst := filepath.Join(filepath.Dir(phys), nameID(newName))
	if isDir(phys) {
		old, _ := readDirName(phys)
		if err := writeDirName(phys, newName); err != nil {
			return err
		}
		if err := os.Rename(phys, dst); err != nil {
			writeDirName(phys, old)
			return err
		}
		return nil
	}
	f, err := os.OpenFile(phys, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	m, err := readHeader(f)
	if err != nil {
		f.Close()
		return err
	}
	old := m.Name
	m.Name = newName
	err = writeHeader(f, m)
	f.Close()
	if err != nil {
		return err
	}
	if err := os.Rename(phys, dst); err != nil {
		if f, e := os.OpenFile(phys, os.O_RDWR, 0); e == nil {
			m.Name = old
			writeHeader(f, m)
			f.Close()
		}
		return err
	}
	return nil
}

/* ---------- listing ---------- */

type vEntry struct {
	entry
	phys string
}

func listDir(dir string) ([]vEntry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]vEntry, 0, len(des))
	for _, d := range des {
		if !idRe.MatchString(d.Name()) {
			continue
		}
		p := filepath.Join(dir, d.Name())
		info, err := d.Info()
		if err != nil {
			continue
		}
		if d.IsDir() {
			n, err := readDirName(p)
			if err != nil {
				continue
			}
			out = append(out, vEntry{entry{n, true, 0, info.ModTime().Unix()}, p})
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		m, err := readHeader(f)
		f.Close()
		if err != nil {
			continue
		}
		out = append(out, vEntry{entry{m.Name, false, m.Size, info.ModTime().Unix()}, p})
	}
	return out, nil
}

/* ---------- encrypt files that are still plain ---------- */

// encryptPlain converts any normal (unencrypted) files and folders under dir
// into the encrypted format. The original is removed only after the
// encrypted copy has been read back and compared.
func encryptPlain(dir string) (done, failed int) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, d := range des {
		nm := d.Name()
		p := filepath.Join(dir, nm)
		switch {
		case nm == dirNameF:
			continue
		case strings.HasSuffix(nm, ".part") || strings.HasSuffix(nm, ".uploading") || nm == dirNameF+".tmp":
			os.Remove(p) // leftovers of an interrupted upload
			continue
		}
		if d.IsDir() {
			if idRe.MatchString(nm) && exists(filepath.Join(p, dirNameF)) {
				a, b := encryptPlain(p)
				done, failed = done+a, failed+b
				continue
			}
			if !validName(nm) {
				continue
			}
			real := uniqueLogical(dir, nm)
			dst := filepath.Join(dir, nameID(real))
			if err := os.Rename(p, dst); err != nil {
				failed++
				continue
			}
			if err := writeDirName(dst, real); err != nil {
				os.Rename(dst, p)
				failed++
				continue
			}
			a, b := encryptPlain(dst)
			done, failed = done+a+1, failed+b
			continue
		}
		if !d.Type().IsRegular() || (idRe.MatchString(nm) && hasMagic(p)) || !validName(nm) {
			continue
		}
		if err := encryptOne(dir, p, nm); err != nil {
			fmt.Println(" !! Could not encrypt", p, "-", err)
			failed++
			continue
		}
		done++
	}
	return
}

func encryptOne(dir, p, nm string) error {
	src, err := os.Open(p)
	if err != nil {
		return err
	}
	h1 := sha256.New()
	real := uniqueLogical(dir, nm)
	dst := filepath.Join(dir, nameID(real))
	err = writeEncrypted(dst, real, io.TeeReader(src, h1))
	src.Close()
	if err != nil {
		return err
	}
	r, _, err := openEncrypted(dst)
	if err != nil {
		os.Remove(dst)
		return err
	}
	h2 := sha256.New()
	_, err = io.Copy(h2, r)
	r.Close()
	if err != nil || !bytes.Equal(h1.Sum(nil), h2.Sum(nil)) {
		os.Remove(dst)
		return errors.New("verification failed")
	}
	st, _ := os.Stat(p)
	if st != nil {
		os.Chtimes(dst, st.ModTime(), st.ModTime())
	}
	return os.Remove(p)
}
