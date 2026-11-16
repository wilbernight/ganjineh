package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// runningInstance checks whether a LAN File Server (any version) already
// answers on the candidate ports of this computer. Returns its port and version.
func runningInstance(port int) (int, string) {
	ports := webPorts
	if port != 0 {
		ports = []int{port}
	}
	c := &http.Client{Timeout: 700 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	urls := []string{"http://127.0.0.1/Temporary_Listen_Addresses/login", "http://127.0.0.1/Temporary_Listen_Addresses/LanFileServer/login"}
	nums := []int{80, 80}
	for _, p := range ports {
		urls = append(urls, fmt.Sprintf("http://127.0.0.1:%d/login", p))
		nums = append(nums, p)
	}
	for i, u := range urls {
		p := nums[i]
		r, err := c.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		r.Body.Close()
		if v := r.Header.Get("X-LFS-Version"); v != "" {
			return p, "v" + v
		}
		body := string(b)
		if strings.Contains(body, "فایل سرور") || strings.Contains(body, "فایل‌سرور") {
			return p, "(older version)"
		}
	}
	return 0, ""
}
