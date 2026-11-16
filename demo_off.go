//go:build !demo

package main

import "net/http"

const demoBuild = false

func startDemo(http.Handler) {}
