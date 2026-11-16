package main

// Where vault.json (password-protected master key + Authenticator key) and the
// shared folder live. Older versions kept them next to the exe, so a new
// version unzipped into another folder started from scratch (new key, new
// password, no files). Now the folder in use is remembered in
// %AppData%\LanFileServer\location.txt, and on a first start an existing
// vault.json is looked for on this computer and reused in place.

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func appHome() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "LanFileServer")
}

func hasVault(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "vault.json"))
	return err == nil && !st.IsDir()
}

func rememberDataDir(dir string) {
	h := appHome()
	if h == "" {
		return
	}
	os.MkdirAll(h, 0o700)
	os.WriteFile(filepath.Join(h, "location.txt"), []byte(dir), 0o600)
}

// findDataDir returns the data folder to use (it may not exist yet).
func findDataDir(exeDir, flagDir string) string {
	if flagDir != "" {
		d, _ := filepath.Abs(flagDir)
		return d
	}
	if hasVault(exeDir) {
		return exeDir
	}
	h := appHome()
	if h != "" {
		if b, err := os.ReadFile(filepath.Join(h, "location.txt")); err == nil {
			if d := strings.TrimSpace(string(b)); d != "" && hasVault(d) {
				return d
			}
		}
		if hasVault(h) {
			return h
		}
	}
	fmt.Println(" Looking for the data (vault.json) of an earlier version on this computer...")
	c := searchVaults(exeDir, 12*time.Second)
	switch len(c) {
	case 0:
		fmt.Println(" None found: starting fresh.")
		if h != "" && os.MkdirAll(h, 0o700) == nil && writable(h) {
			return h
		}
		return exeDir
	case 1:
		fmt.Println(" Found:", c[0].dir)
		return c[0].dir
	}
	fmt.Println(" Several were found (each has its own password and Authenticator key):")
	for i, v := range c {
		fmt.Printf("   %d) %s   (%d item(s), %s)\n", i+1, v.dir, v.items, v.mod.Format("2006-01-02 15:04"))
	}
	in := stdin
	for {
		fmt.Print(" Which one? [Enter = 1]: ")
		s, _ := in.ReadString('\n')
		s = strings.TrimSpace(s)
		if s == "" {
			return c[0].dir
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(c) {
			return c[n-1].dir
		}
	}
}

type vaultCand struct {
	dir   string
	items int
	mod   time.Time
}

func searchVaults(exeDir string, budget time.Duration) []vaultCand {
	deadline := time.Now().Add(budget)
	seen := map[string]bool{}
	var out []vaultCand
	skip := map[string]bool{"appdata": true, "windows": true, "program files": true, "program files (x86)": true,
		"programdata": true, "$recycle.bin": true, "system volume information": true, "node_modules": true,
		".git": true, "library": true, "shared": true, "private": true}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if time.Now().After(deadline) || seen[strings.ToLower(dir)] {
			return
		}
		seen[strings.ToLower(dir)] = true
		if hasVault(dir) {
			st, _ := os.Stat(filepath.Join(dir, "vault.json"))
			n := 0
			if es, err := os.ReadDir(filepath.Join(dir, "shared")); err == nil {
				n = len(es)
			}
			out = append(out, vaultCand{dir: dir, items: n, mod: st.ModTime()})
			return
		}
		if depth <= 0 {
			return
		}
		es, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range es {
			if !e.IsDir() || e.Type()&os.ModeSymlink != 0 || strings.HasPrefix(e.Name(), ".") || skip[strings.ToLower(e.Name())] {
				continue
			}
			walk(filepath.Join(dir, e.Name()), depth-1)
		}
	}
	// next to the exe first (an older copy in the parent folder, siblings)
	walk(filepath.Dir(exeDir), 2)
	if home, err := os.UserHomeDir(); err == nil {
		for _, s := range []string{"Desktop", "Downloads", "Documents", "OneDrive"} {
			walk(filepath.Join(home, s), 5)
		}
		walk(home, 3)
	}
	if runtime.GOOS == "windows" {
		for c := 'C'; c <= 'Z'; c++ {
			walk(string(c)+`:\`, 3)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].items != out[j].items {
			return out[i].items > out[j].items
		}
		return out[i].mod.After(out[j].mod)
	})
	return out
}
