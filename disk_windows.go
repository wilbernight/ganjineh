//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var procDiskFree = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func diskFree(dir string) (uint64, error) {
	free, _, err := diskSpace(dir)
	return free, err
}

// diskSpace: bytes free (for this user) and total on the disk holding dir.
func diskSpace(dir string) (free, total uint64, err error) {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	if r, _, e := procDiskFree.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), 0); r == 0 {
		return 0, 0, e
	}
	return free, total, nil
}
