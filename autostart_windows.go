//go:build windows

package main

// Start with Windows, without admin rights:
//   - the startup password is kept in <data>/autostart.bin, encrypted with
//     Windows DPAPI for the current Windows user only (another user, another
//     PC, or a copy of the file cannot open it);
//   - a value under HKCU\...\Run starts the program when this user signs in.
// Both live in the user's own space, so no UAC prompt is needed.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const runName = "Ganjineh"

var dpapiEntropy = []byte("ganjineh-autostart-v1")

func autoPassPath(base string) string { return filepath.Join(base, "autostart.bin") }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func blobBytes(d *windows.DataBlob) []byte {
	out := make([]byte, d.Size)
	copy(out, unsafe.Slice(d.Data, d.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(d.Data)))
	return out
}

func dpapiSeal(p []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(p), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return blobBytes(&out), nil
}

func dpapiOpen(c []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(c), nil, blob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return blobBytes(&out), nil
}

// savedPassword returns the remembered startup password, if any.
func savedPassword(base string) (string, bool) {
	c, err := os.ReadFile(autoPassPath(base))
	if err != nil {
		return "", false
	}
	p, err := dpapiOpen(c)
	if err != nil {
		return "", false
	}
	return string(p), true
}

func rememberPassword(base, pw string) error {
	c, err := dpapiSeal([]byte(pw))
	if err != nil {
		return err
	}
	tmp := autoPassPath(base) + ".tmp"
	if err := os.WriteFile(tmp, c, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, autoPassPath(base))
}

func autostartEnabled(base string) bool {
	_, err := os.Stat(autoPassPath(base))
	return err == nil
}

func enableAutostart(base, pw string) error {
	if err := rememberPassword(base, pw); err != nil {
		return errors.New("cannot save the password for this Windows user: " + err.Error())
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	d := filepath.Clean(base)
	if strings.HasSuffix(d, `\`) { // "C:\" would escape the closing quote
		d += "."
	}
	return k.SetStringValue(runName, `"`+exe+`" -data "`+d+`" -minimized`)
}

func disableAutostart(base string) error {
	os.Remove(autoPassPath(base))
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	if err := k.DeleteValue(runName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// minimizeConsole puts the console window in the taskbar (used at sign-in).
func minimizeConsole() {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	u32 := windows.NewLazySystemDLL("user32.dll")
	h, _, _ := k32.NewProc("GetConsoleWindow").Call()
	if h != 0 {
		u32.NewProc("ShowWindow").Call(h, 7) // SW_SHOWMINNOACTIVE
	}
}
