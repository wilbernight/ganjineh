//go:build !windows

package main

import "syscall"

func diskFree(dir string) (uint64, error) {
	free, _, err := diskSpace(dir)
	return free, err
}

func diskSpace(dir string) (free, total uint64, err error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(dir, &s); err != nil {
		return 0, 0, err
	}
	return s.Bavail * uint64(s.Bsize), s.Blocks * uint64(s.Bsize), nil
}
