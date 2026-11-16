//go:build !windows

package main

import (
	"errors"
	"net/http"
)

// startHTTPSys is only available on Windows.
func startHTTPSys(http.Handler) (string, bool, error) {
	return "", false, errors.New("Windows only")
}
