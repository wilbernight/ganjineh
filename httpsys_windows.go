//go:build windows

package main

// Port 80 through Windows' own web server (http.sys, HTTP Server API v1).
// On locked-down PCs the firewall drops everything except port 80, which
// belongs to http.sys. Windows lets every user (no admin) serve the URL
// http://+:80/Temporary_Listen_Addresses/ there, so requests on that path are
// received from http.sys and passed to the normal handler.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	httpapi            = syscall.NewLazyDLL(filepath.Join(os.Getenv("SystemRoot"), "System32", "httpapi.dll"))
	procInitialize     = httpapi.NewProc("HttpInitialize")
	procCreateHandle   = httpapi.NewProc("HttpCreateHttpHandle")
	procAddURL         = httpapi.NewProc("HttpAddUrl")
	procReceiveRequest = httpapi.NewProc("HttpReceiveHttpRequest")
	procReceiveBody    = httpapi.NewProc("HttpReceiveRequestEntityBody")
	procSendResponse   = httpapi.NewProc("HttpSendHttpResponse")
	procSendBody       = httpapi.NewProc("HttpSendResponseEntityBody")
)

const (
	errHandleEOF         = 38
	errAlreadyExists     = 183
	errMoreData          = 234
	errOperationAborted  = 995
	errConnectionInvalid = 1236
	errInvalidHandle     = 6

	flagMoreEntityBody = 1 // HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS
	sendDisconnect     = 1 // HTTP_SEND_RESPONSE_FLAG_DISCONNECT
	sendMoreData       = 2 // HTTP_SEND_RESPONSE_FLAG_MORE_DATA
	sendBufferData     = 4 // HTTP_SEND_RESPONSE_FLAG_BUFFER_DATA
)

// Layouts of the HTTP Server API structures (64-bit).
type httpKnownHeader struct {
	RawValueLength uint16
	RawValue       *byte
}

type httpUnknownHeader struct {
	NameLength     uint16
	RawValueLength uint16
	Name           *byte
	RawValue       *byte
}

type httpRequestHeaders struct {
	UnknownHeaderCount uint16
	UnknownHeaders     *httpUnknownHeader
	TrailerCount       uint16
	Trailers           *httpUnknownHeader
	KnownHeaders       [41]httpKnownHeader
}

type httpResponseHeaders struct {
	UnknownHeaderCount uint16
	UnknownHeaders     *httpUnknownHeader
	TrailerCount       uint16
	Trailers           *httpUnknownHeader
	KnownHeaders       [30]httpKnownHeader
}

type httpCookedURL struct {
	FullURLLength, HostLength, AbsPathLength, QueryStringLength uint16
	FullURL, Host, AbsPath, QueryString                         *uint16
}

type httpRequest struct {
	Flags             uint32
	ConnectionID      uint64
	RequestID         uint64
	URLContext        uint64
	VersionMajor      uint16
	VersionMinor      uint16
	Verb              int32
	UnknownVerbLength uint16
	RawURLLength      uint16
	UnknownVerb       *byte
	RawURL            *byte
	CookedURL         httpCookedURL
	RemoteAddress     *[28]byte
	LocalAddress      *[28]byte
	Headers           httpRequestHeaders
	BytesReceived     uint64
	EntityChunkCount  uint16
	EntityChunks      uintptr
	RawConnectionID   uint64
	SslInfo           uintptr
}

type httpDataChunk struct {
	Type         uint32 // 0 = from memory
	_            uint32
	Buffer       *byte
	BufferLength uint32
	_            [12]byte
}

type httpResponse struct {
	Flags            uint32
	VersionMajor     uint16
	VersionMinor     uint16
	StatusCode       uint16
	ReasonLength     uint16
	Reason           *byte
	Headers          httpResponseHeaders
	EntityChunkCount uint16
	EntityChunks     *httpDataChunk
}

var reqHeaderNames = [41]string{"Cache-Control", "Connection", "Date", "Keep-Alive", "Pragma", "Trailer",
	"Transfer-Encoding", "Upgrade", "Via", "Warning", "Allow", "Content-Length", "Content-Type",
	"Content-Encoding", "Content-Language", "Content-Location", "Content-Md5", "Content-Range", "Expires",
	"Last-Modified", "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Authorization",
	"Cookie", "Expect", "From", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range",
	"If-Unmodified-Since", "Max-Forwards", "Proxy-Authorization", "Referer", "Range", "Te", "Translate",
	"User-Agent"}

var respHeaderIndex = map[string]int{"Cache-Control": 0, "Connection": 1, "Date": 2, "Keep-Alive": 3,
	"Pragma": 4, "Trailer": 5, "Transfer-Encoding": 6, "Upgrade": 7, "Via": 8, "Warning": 9, "Allow": 10,
	"Content-Length": 11, "Content-Type": 12, "Content-Encoding": 13, "Content-Language": 14,
	"Content-Location": 15, "Content-Md5": 16, "Content-Range": 17, "Expires": 18, "Last-Modified": 19,
	"Accept-Ranges": 20, "Age": 21, "Etag": 22, "Location": 23, "Proxy-Authenticate": 24,
	"Retry-After": 25, "Server": 26, "Set-Cookie": 27, "Vary": 28, "Www-Authenticate": 29}

var verbs = map[int32]string{3: "OPTIONS", 4: "GET", 5: "HEAD", 6: "POST", 7: "PUT", 8: "DELETE",
	9: "TRACE", 10: "CONNECT", 11: "TRACK", 12: "MOVE", 13: "COPY", 14: "PROPFIND", 15: "PROPPATCH",
	16: "MKCOL", 17: "LOCK", 18: "UNLOCK", 19: "SEARCH"}

type sysServer struct {
	h uintptr // request queue handle
	k http.Handler
}

// startHTTPSys registers http://+:80/Temporary_Listen_Addresses/ with http.sys
// and serves h there. Returns the URL path prefix that works.
func startHTTPSys(h http.Handler) (base string, short bool, err error) {
	if err := procInitialize.Find(); err != nil {
		return "", false, err
	}
	if r, _, _ := procInitialize.Call(1, 1, 0); r != 0 { // HTTPAPI_VERSION 1.0, HTTP_INITIALIZE_SERVER
		return "", false, fmt.Errorf("HttpInitialize: %w", syscall.Errno(r))
	}
	var q uintptr
	if r, _, _ := procCreateHandle.Call(uintptr(unsafe.Pointer(&q)), 0); r != 0 {
		return "", false, fmt.Errorf("HttpCreateHttpHandle: %w", syscall.Errno(r))
	}
	// The short address http://IP/ works only after "netsh http add urlacl
	// url=http://+:80/ ..." was run once as admin (short-address.bat). Without
	// it Windows refuses here and only the long address below is used.
	ru, _ := syscall.UTF16PtrFromString("http://+:80/")
	rootOK := false
	if r, _, _ := procAddURL.Call(q, uintptr(unsafe.Pointer(ru)), 0); r == 0 {
		rootOK = true
	}
	var lastErr error
	// If another program already uses the plain prefix, a sub-path still works.
	for _, b := range []string{"/Temporary_Listen_Addresses", "/Temporary_Listen_Addresses/LanFileServer"} {
		u, _ := syscall.UTF16PtrFromString("http://+:80" + b + "/")
		r, _, _ := procAddURL.Call(q, uintptr(unsafe.Pointer(u)), 0)
		if r == 0 {
			base = b
			break
		}
		lastErr = fmt.Errorf("HttpAddUrl %s/: %w", b, syscall.Errno(r))
		if r != errAlreadyExists {
			break
		}
	}
	if base == "" && !rootOK {
		syscall.CloseHandle(syscall.Handle(q))
		return "", false, lastErr
	}
	k := http.NotFoundHandler()
	if base != "" {
		k = withBase(base, h)
	}
	if rootOK { // both addresses: the old long one keeps working
		long := k
		k = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := r.URL.Path; base != "" && len(p) >= len(base) && strings.EqualFold(p[:len(base)], base) && (len(p) == len(base) || p[len(base)] == '/') {
				long.ServeHTTP(w, r)
				return
			}
			h.ServeHTTP(w, r)
		})
	}
	s := &sysServer{h: q, k: k}
	for i := 0; i < 4; i++ {
		go s.receive()
	}
	return base, rootOK, nil
}

func (s *sysServer) receive() {
	const small = 16 << 10
	buf := make([]byte, small)
	var id uint64
	for {
		var n uint32
		r, _, _ := procReceiveRequest.Call(s.h, uintptr(id), 0, uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), 0)
		req := (*httpRequest)(unsafe.Pointer(&buf[0]))
		switch r {
		case 0:
			hr, rid := s.convert(req), req.RequestID
			go s.serve(rid, hr)
			id = 0
			if len(buf) > small {
				buf = make([]byte, small)
			}
		case errMoreData: // headers larger than the buffer: same request again, bigger buffer
			id = req.RequestID
			buf = make([]byte, n+512)
		case errConnectionInvalid:
			id = 0
		case errInvalidHandle, errOperationAborted:
			return
		default:
			log.Printf("http.sys receive: %v", syscall.Errno(r))
			id = 0
		}
	}
}

func cbytes(p *byte, n uint16) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return bytes.Clone(unsafe.Slice(p, n))
}

func sockaddr(a *[28]byte) string {
	if a == nil {
		return "0.0.0.0:0"
	}
	port := int(binary.BigEndian.Uint16(a[2:4]))
	switch binary.LittleEndian.Uint16(a[0:2]) {
	case 2: // AF_INET
		return net.JoinHostPort(net.IP(bytes.Clone(a[4:8])).String(), strconv.Itoa(port))
	case 23: // AF_INET6
		return net.JoinHostPort(net.IP(bytes.Clone(a[8:24])).String(), strconv.Itoa(port))
	}
	return "0.0.0.0:0"
}

// convert copies everything out of the receive buffer into an *http.Request.
func (s *sysServer) convert(q *httpRequest) *http.Request {
	method := verbs[q.Verb]
	if method == "" {
		method = string(cbytes(q.UnknownVerb, q.UnknownVerbLength))
	}
	raw := string(cbytes(q.RawURL, q.RawURLLength))
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		u = &url.URL{Path: "/"}
	}
	u.Scheme, u.Host = "", ""
	hdr := http.Header{}
	for i, name := range reqHeaderNames {
		k := q.Headers.KnownHeaders[i]
		if k.RawValueLength > 0 {
			hdr.Add(name, string(cbytes(k.RawValue, k.RawValueLength)))
		}
	}
	if q.Headers.UnknownHeaderCount > 0 && q.Headers.UnknownHeaders != nil {
		for _, x := range unsafe.Slice(q.Headers.UnknownHeaders, q.Headers.UnknownHeaderCount) {
			hdr.Add(string(cbytes(x.Name, x.NameLength)), string(cbytes(x.RawValue, x.RawValueLength)))
		}
	}
	r := &http.Request{
		Method: method, URL: u, RequestURI: raw, Header: hdr, Host: hdr.Get("Host"),
		Proto:      fmt.Sprintf("HTTP/%d.%d", q.VersionMajor, q.VersionMinor),
		ProtoMajor: int(q.VersionMajor), ProtoMinor: int(q.VersionMinor),
		RemoteAddr: sockaddr(q.RemoteAddress), Body: http.NoBody,
	}
	if q.Flags&flagMoreEntityBody != 0 {
		r.Body = &sysBody{s: s, id: q.RequestID}
		r.ContentLength = -1
		if cl, err := strconv.ParseInt(hdr.Get("Content-Length"), 10, 64); err == nil {
			r.ContentLength = cl
		}
	}
	return r
}

type sysBody struct {
	s   *sysServer
	id  uint64
	eof bool
}

func (b *sysBody) Read(p []byte) (int, error) {
	if b.eof {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > 1<<20 {
		p = p[:1<<20]
	}
	var n uint32
	r, _, _ := procReceiveBody.Call(b.s.h, uintptr(b.id), 0, uintptr(unsafe.Pointer(&p[0])),
		uintptr(len(p)), uintptr(unsafe.Pointer(&n)), 0)
	switch r {
	case 0:
		return int(n), nil
	case errHandleEOF:
		b.eof = true
		if n > 0 {
			return int(n), nil
		}
		return 0, io.EOF
	}
	return int(n), fmt.Errorf("receive body: %w", syscall.Errno(r))
}

func (b *sysBody) Close() error { return nil }

func (s *sysServer) serve(id uint64, r *http.Request) {
	w := &sysWriter{s: s, id: id, hdr: http.Header{}, head: r.Method == "HEAD", http11: r.ProtoAtLeast(1, 1)}
	defer func() {
		if e := recover(); e != nil {
			log.Printf("panic serving %s: %v", r.URL.Path, e)
			if !w.sent {
				w.hdr = http.Header{}
				w.status, w.buf = 500, nil
			}
		}
		w.finish()
	}()
	s.k.ServeHTTP(w, r)
}

// sysWriter buffers small responses (sent with a Content-Length in one call)
// and streams large ones, chunk-encoded when the length is unknown.
type sysWriter struct {
	s            *sysServer
	id           uint64
	hdr          http.Header
	status       int
	head, http11 bool
	sent         bool // headers sent
	chunked      bool
	closeConn    bool
	buf          []byte
	err          error
}

const sysFlushSize = 256 << 10

func (w *sysWriter) Header() http.Header { return w.hdr }

func (w *sysWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *sysWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.head || w.status == 204 || w.status == 304 {
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	if len(w.buf) >= sysFlushSize {
		w.flush(true)
	}
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func (w *sysWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.flush(true)
}

// flush sends the headers (first time) and the buffered body.
func (w *sysWriter) flush(more bool) {
	if w.err != nil {
		return
	}
	body := w.buf
	w.buf = w.buf[:0]
	flags := uintptr(sendBufferData)
	if more {
		flags |= sendMoreData
	} else if w.closeConn {
		flags |= sendDisconnect
	}
	var chunks [][]byte
	if w.chunked {
		if len(body) > 0 {
			chunks = append(chunks, []byte(strconv.FormatInt(int64(len(body)), 16)+"\r\n"), body, []byte("\r\n"))
		}
		if !more {
			chunks = append(chunks, []byte("0\r\n\r\n"))
		}
	} else if len(body) > 0 {
		chunks = append(chunks, body)
	}
	if !w.sent {
		w.sent = true
		w.err = w.sendHeaders(flags, chunks, more, body)
	} else if len(chunks) > 0 || !more {
		w.err = w.sendBody(flags, chunks)
	}
}

func makeChunks(chunks [][]byte) []httpDataChunk {
	var dc []httpDataChunk
	for _, c := range chunks {
		if len(c) > 0 {
			dc = append(dc, httpDataChunk{Buffer: &c[0], BufferLength: uint32(len(c))})
		}
	}
	return dc
}

func (w *sysWriter) sendHeaders(flags uintptr, chunks [][]byte, more bool, body []byte) error {
	h := w.hdr
	if _, ok := h["Content-Type"]; !ok && len(body) > 0 {
		h.Set("Content-Type", http.DetectContentType(body))
	}
	if !more && !w.head && h.Get("Content-Length") == "" && w.status != 204 && w.status != 304 {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if more && h.Get("Content-Length") == "" && !w.head {
		if w.http11 { // length unknown: chunk-encode it ourselves
			w.chunked = true
			h.Set("Transfer-Encoding", "chunked")
			chunks = append([][]byte{[]byte(strconv.FormatInt(int64(len(body)), 16) + "\r\n")}, chunks...)
			chunks = append(chunks, []byte("\r\n"))
			if len(body) == 0 {
				chunks = nil
			}
		} else {
			w.closeConn = true
		}
	}
	h.Del("Connection")
	var resp httpResponse
	resp.VersionMajor, resp.VersionMinor = 1, 1
	resp.StatusCode = uint16(w.status)
	reason := []byte(http.StatusText(w.status))
	if len(reason) == 0 {
		reason = []byte("Status")
	}
	resp.Reason, resp.ReasonLength = &reason[0], uint16(len(reason))
	var keep [][]byte
	var unknown []httpUnknownHeader
	for k, vs := range h {
		idx, known := respHeaderIndex[k]
		if known && len(vs) == 1 {
			v := []byte(vs[0])
			keep = append(keep, v)
			if len(v) > 0 {
				resp.Headers.KnownHeaders[idx] = httpKnownHeader{RawValueLength: uint16(len(v)), RawValue: &v[0]}
			}
			continue
		}
		name := []byte(k)
		keep = append(keep, name)
		for _, s := range vs {
			v := []byte(s + " ")[:len(s)] // never empty backing array
			keep = append(keep, v)
			unknown = append(unknown, httpUnknownHeader{NameLength: uint16(len(name)), RawValueLength: uint16(len(v)),
				Name: &name[0], RawValue: unsafe.SliceData(v)})
		}
	}
	if len(unknown) > 0 {
		resp.Headers.UnknownHeaderCount = uint16(len(unknown))
		resp.Headers.UnknownHeaders = &unknown[0]
	}
	dc := makeChunks(chunks)
	if len(dc) > 0 {
		resp.EntityChunkCount, resp.EntityChunks = uint16(len(dc)), &dc[0]
	}
	var sent uint32
	r, _, _ := procSendResponse.Call(w.s.h, uintptr(w.id), flags, uintptr(unsafe.Pointer(&resp)), 0,
		uintptr(unsafe.Pointer(&sent)), 0, 0, 0, 0)
	runtime.KeepAlive(keep)
	runtime.KeepAlive(unknown)
	runtime.KeepAlive(dc)
	runtime.KeepAlive(chunks)
	runtime.KeepAlive(reason)
	if r != 0 {
		return fmt.Errorf("send response: %w", syscall.Errno(r))
	}
	return nil
}

func (w *sysWriter) sendBody(flags uintptr, chunks [][]byte) error {
	dc := makeChunks(chunks)
	var p uintptr
	if len(dc) > 0 {
		p = uintptr(unsafe.Pointer(&dc[0]))
	}
	var sent uint32
	r, _, _ := procSendBody.Call(w.s.h, uintptr(w.id), flags, uintptr(len(dc)), p,
		uintptr(unsafe.Pointer(&sent)), 0, 0, 0, 0)
	runtime.KeepAlive(dc)
	runtime.KeepAlive(chunks)
	if r != 0 {
		return fmt.Errorf("send body: %w", syscall.Errno(r))
	}
	return nil
}

func (w *sysWriter) finish() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.flush(false)
	if w.err != nil && !errors.Is(w.err, syscall.Errno(errConnectionInvalid)) {
		log.Printf("http.sys: %v", w.err)
	}
}
