//go:build windows

package main

import "fmt"

// ensureFirewall does not touch Windows settings and starts no other
// programs (no netsh, no UAC). It only explains what to do if other PCs
// cannot connect: allow-firewall.bat (run once by an admin) opens the ports.
func ensureFirewall(ports []int) {
	if len(ports) == 0 { // only http.sys port 80, which Windows already allows
		return
	}
	fmt.Println(" Other PCs cannot connect? Windows Firewall is blocking port(s)", ports)
	fmt.Println("    -> have an admin run allow-firewall.bat once (in the same folder as this exe).")
	fmt.Println("    If you clicked Cancel on the Windows Firewall popup, that created a BLOCK")
	fmt.Println("    rule; allow-firewall.bat removes it.")
}
