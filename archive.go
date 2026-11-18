package main

// Names inside .zip and .rar files, so search can find files packed in them.
//
// Only the archive's list of names is read (the zip central directory, the
// rar block headers); nothing is unpacked. The lists are cached per archive
// (keyed by on-disk path, size and time) like the plain names in search.go.
// RAR is read with a small header parser (RAR 4 and RAR 5), so there is no
// extra library. Archives with encrypted headers (password on the names) are
// skipped.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const maxArchEntries = 50000 // per archive; the rest is not indexed

type archEntry struct {
	Path  string // path inside the archive, "/" separated, no leading slash
	IsDir bool
	Size  int64
	MTime int64
}

type archInfo struct {
	mtime, fsize int64
	entries      []archEntry
}

var (
	archMu    sync.RWMutex
	archCache = map[string]archInfo{}
)

// archKind returns "zip", "rar" or "" from the real file name.
func archKind(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".zip":
		return "zip"
	case ".rar":
		return "rar"
	}
	return ""
}

// archiveEntries lists an encrypted .zip/.rar file (p on disk, real name name).
func archiveEntries(p, name string, fi os.FileInfo) []archEntry {
	kind := archKind(name)
	if kind == "" {
		return nil
	}
	archMu.RLock()
	c, ok := archCache[p]
	archMu.RUnlock()
	if ok && c.mtime == fi.ModTime().UnixNano() && c.fsize == fi.Size() {
		return c.entries
	}
	var list []archEntry
	if f, _, err := openEncrypted(p); err == nil {
		r := &readerAt{d: f}
		if kind == "zip" {
			list = listZip(r, f.size)
		} else {
			list = listRar(r, f.size)
		}
		f.Close()
	}
	archMu.Lock()
	archCache[p] = archInfo{fi.ModTime().UnixNano(), fi.Size(), list} // also caches failures
	archMu.Unlock()
	return list
}

// readerAt adds io.ReaderAt to the decrypting reader (one reader at a time).
type readerAt struct{ d *decReader }

func (r *readerAt) ReadAt(b []byte, off int64) (int, error) {
	if _, err := r.d.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	n, err := io.ReadFull(r.d, b)
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	return n, err
}

func cleanInner(s string) string {
	s = strings.Trim(strings.ReplaceAll(s, "\\", "/"), "/")
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	return s
}

/* ---------- zip ---------- */

func listZip(r io.ReaderAt, size int64) []archEntry {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil
	}
	out := make([]archEntry, 0, min(len(zr.File), maxArchEntries))
	for _, f := range zr.File {
		if len(out) >= maxArchEntries {
			break
		}
		n := cleanInner(f.Name)
		if n == "" {
			continue
		}
		out = append(out, archEntry{n, f.FileInfo().IsDir(), int64(f.UncompressedSize64), f.Modified.Unix()})
	}
	return addParents(out)
}

// addParents adds folders that only appear as part of a file's path.
func addParents(list []archEntry) []archEntry {
	seen := map[string]bool{}
	for _, e := range list {
		if e.IsDir {
			seen[e.Path] = true
		}
	}
	for _, e := range list {
		for d := path.Dir(e.Path); d != "." && d != "/" && !seen[d] && len(list) < maxArchEntries; d = path.Dir(d) {
			seen[d] = true
			list = append(list, archEntry{d, true, 0, e.MTime})
		}
	}
	return list
}

/* ---------- rar ---------- */

var (
	rar4Sig = []byte("Rar!\x1a\x07\x00")
	rar5Sig = []byte("Rar!\x1a\x07\x01\x00")
)

func listRar(r io.ReaderAt, size int64) []archEntry {
	sig := make([]byte, 8)
	if n, _ := r.ReadAt(sig, 0); n < 7 {
		return nil
	}
	var out []archEntry
	if bytes.Equal(sig, rar5Sig) {
		out = listRar5(r, size)
	} else if bytes.Equal(sig[:7], rar4Sig) {
		out = listRar4(r, size)
	}
	return addParents(out)
}

func listRar4(r io.ReaderAt, size int64) []archEntry {
	var out []archEntry
	pos := int64(7)
	h := make([]byte, 7)
	for pos+7 <= size && len(out) < maxArchEntries {
		if n, _ := r.ReadAt(h, pos); n < 7 {
			break
		}
		typ := h[2]
		flags := binary.LittleEndian.Uint16(h[3:])
		hsize := int64(binary.LittleEndian.Uint16(h[5:]))
		if hsize < 7 {
			break
		}
		next := pos + hsize
		switch typ {
		case 0x73: // main header
			if flags&0x0080 != 0 { // names are encrypted
				return out
			}
		case 0x74: // file
			b := make([]byte, hsize)
			if n, _ := r.ReadAt(b, pos); int64(n) < hsize || hsize < 32 {
				return out
			}
			pack := int64(binary.LittleEndian.Uint32(b[7:]))
			unp := int64(binary.LittleEndian.Uint32(b[11:]))
			ftime := binary.LittleEndian.Uint32(b[20:])
			nlen := int(binary.LittleEndian.Uint16(b[26:]))
			off := 32
			if flags&0x0100 != 0 { // 64-bit sizes
				if len(b) < 40 {
					return out
				}
				pack |= int64(binary.LittleEndian.Uint32(b[32:])) << 32
				unp |= int64(binary.LittleEndian.Uint32(b[36:])) << 32
				off = 40
			}
			if off+nlen > len(b) {
				return out
			}
			name := b[off : off+nlen]
			var n string
			if flags&0x0200 != 0 {
				n = rar4Unicode(name)
			} else {
				n = string(name)
			}
			if flags&0x0001 == 0 { // not the continuation of a file from the previous volume
				out = append(out, archEntry{cleanInner(n), flags&0x00e0 == 0x00e0, unp, dosTime(ftime)})
			}
			next += pack
		case 0x7b: // end of archive
			return out
		default:
			if flags&0x8000 != 0 { // block with data after the header
				b := make([]byte, 4)
				if n, _ := r.ReadAt(b, pos+7); n < 4 {
					return out
				}
				next += int64(binary.LittleEndian.Uint32(b))
			}
		}
		if next <= pos {
			break
		}
		pos = next
	}
	return out
}

// rar4Unicode decodes RAR 4's packed Unicode file names.
func rar4Unicode(b []byte) string {
	z := bytes.IndexByte(b, 0)
	if z < 0 {
		return string(b)
	}
	std, enc := b[:z], b[z+1:]
	if len(enc) == 0 {
		return string(std)
	}
	high := uint16(enc[0])
	var out []uint16
	var flags byte
	bits := 0
	for i := 1; i < len(enc); {
		if bits == 0 {
			flags = enc[i]
			i++
			bits = 8
			if i >= len(enc) {
				break
			}
		}
		switch flags >> 6 {
		case 0:
			out = append(out, uint16(enc[i]))
			i++
		case 1:
			out = append(out, uint16(enc[i])|high<<8)
			i++
		case 2:
			if i+1 >= len(enc) {
				i = len(enc)
				break
			}
			out = append(out, uint16(enc[i])|uint16(enc[i+1])<<8)
			i += 2
		case 3:
			l := int(enc[i])
			i++
			if l&0x80 != 0 {
				if i >= len(enc) {
					break
				}
				corr := enc[i]
				i++
				for l = l&0x7f + 2; l > 0 && len(out) < len(std); l-- {
					out = append(out, uint16(std[len(out)]+corr)|high<<8)
				}
			} else {
				for l += 2; l > 0 && len(out) < len(std); l-- {
					out = append(out, uint16(std[len(out)]))
				}
			}
		}
		flags <<= 2
		bits -= 2
	}
	return string(utf16.Decode(out))
}

func dosTime(t uint32) int64 {
	if t == 0 {
		return 0
	}
	return time.Date(int(t>>25)+1980, time.Month(t>>21&15), int(t>>16&31), int(t>>11&31), int(t>>5&63), int(t&31)*2, 0, time.Local).Unix()
}

// vint reads a RAR 5 variable-length number from b at *i.
func vint(b []byte, i *int) (uint64, error) {
	var v uint64
	for s := 0; s < 64; s += 7 {
		if *i >= len(b) {
			return 0, errors.New("short")
		}
		c := b[*i]
		*i++
		v |= uint64(c&0x7f) << s
		if c&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errors.New("bad vint")
}

func listRar5(r io.ReaderAt, size int64) []archEntry {
	var out []archEntry
	pos := int64(8)
	head := make([]byte, 4+3)
	for pos+7 <= size && len(out) < maxArchEntries {
		n, _ := r.ReadAt(head, pos)
		if n < 5 {
			break
		}
		i := 4 // skip CRC32
		hsize, err := vint(head[:n], &i)
		if err != nil || hsize == 0 || hsize > 2<<20 {
			break
		}
		start := pos + int64(i) // header data begins here
		b := make([]byte, hsize)
		if n, _ := r.ReadAt(b, start); uint64(n) < hsize {
			break
		}
		j := 0
		typ, _ := vint(b, &j)
		hflags, _ := vint(b, &j)
		if hflags&1 != 0 {
			vint(b, &j) // extra area size
		}
		var dsize uint64
		if hflags&2 != 0 {
			dsize, _ = vint(b, &j)
		}
		switch typ {
		case 4: // encryption header: everything after it is encrypted
			return out
		case 5: // end
			return out
		case 2: // file
			fflags, _ := vint(b, &j)
			unp, _ := vint(b, &j)
			vint(b, &j) // attributes
			var mt int64
			if fflags&2 != 0 && j+4 <= len(b) {
				mt = int64(binary.LittleEndian.Uint32(b[j:]))
				j += 4
			}
			if fflags&4 != 0 {
				j += 4 // data CRC
			}
			vint(b, &j) // compression
			vint(b, &j) // host OS
			nl, err := vint(b, &j)
			if err == nil && uint64(j)+nl <= uint64(len(b)) {
				out = append(out, archEntry{cleanInner(string(b[j : j+int(nl)])), fflags&1 != 0, int64(unp), mt})
			}
		}
		next := start + int64(hsize) + int64(dsize)
		if next <= pos {
			break
		}
		pos = next
	}
	return out
}

/* ---------- download one file from inside a zip ---------- */

// handleArchiveFile: GET /api/archive-file?path=<zip>&inner=<entry>
func handleArchiveFile(w http.ResponseWriter, r *http.Request) {
	full, _, err := resolve(r, r.URL.Query().Get("path"), accRead)
	if err != nil {
		resolveFail(w, err)
		return
	}
	inner := cleanInner(r.URL.Query().Get("inner"))
	f, m, err := openEncrypted(full)
	if err != nil {
		fail(w, 404, "not found")
		return
	}
	defer f.Close()
	if archKind(m.Name) != "zip" {
		fail(w, 400, "only zip")
		return
	}
	zr, err := zip.NewReader(&readerAt{d: f}, f.size)
	if err != nil {
		fail(w, 400, "cannot read zip")
		return
	}
	for _, zf := range zr.File {
		if cleanInner(zf.Name) != inner || zf.FileInfo().IsDir() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			fail(w, 400, "cannot read zip")
			return
		}
		defer rc.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlEscape(path.Base(inner)))
		w.Header().Set("Content-Length", itoa(int64(zf.UncompressedSize64)))
		w.Header().Set("Cache-Control", "no-store")
		io.Copy(w, rc)
		return
	}
	fail(w, 404, "not found")
}

func itoa(n int64) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
