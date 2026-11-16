//go:build !windows

package main

import "errors"

func savedPassword(string) (string, bool)  { return "", false }
func autostartEnabled(string) bool         { return false }
func enableAutostart(string, string) error { return errors.New("start with Windows works only on Windows") }
func disableAutostart(string) error        { return nil }
func minimizeConsole()                     {}
