//go:build demo

package main

// Test build only (go build -tags demo): extra local ports that act as if
// every request came from another computer's IP, so the client view can be
// tried on the server PC itself. Never part of the release exe.

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
)

var demoBase = flag.String("demo-base", "", "TEST ONLY: port - also serve under /Temporary_Listen_Addresses on this local port, like Windows port 80")

var demoClients = flag.String("demo-clients", "", "TEST ONLY: port=ip,port=ip - serve on these local ports as if requests came from that IP")

const demoBuild = true

func startDemo(h http.Handler) {
	if *demoBase != "" {
		go http.ListenAndServe("127.0.0.1:"+*demoBase, withBase("/Temporary_Listen_Addresses", h))
		fmt.Printf("   TEST port-80 style address:  http://localhost:%s/Temporary_Listen_Addresses/\n", *demoBase)
	}
	for _, pair := range strings.Split(*demoClients, ",") {
		port, ip, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		fake := ip + ":40000"
		go http.ListenAndServe("127.0.0.1:"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.RemoteAddr = fake
			h.ServeHTTP(w, r)
		}))
		fmt.Printf("   TEST client view as %s:  http://localhost:%s\n", ip, port)
	}
}
