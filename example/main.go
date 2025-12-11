//go:build cgo

package main

import (
	"context"
	"fmt"
	"log"

	fipscheck "github.com/bahe-msft/fips-check"
)

func main() {
	// Check host FIPS capabilities
	hostInfo := fipscheck.CheckHostFIPS()
	fmt.Printf("Host FIPS Info:\n")
	fmt.Printf("  OpenSSL Version: %s\n", hostInfo.OpenSSLVersion)
	fmt.Printf("  FIPS Capable: %t\n", hostInfo.FIPSCapable)
	fmt.Println()

	// Check binaries in current directory
	ctx := context.Background()
	reports, err := fipscheck.CheckBinaries(ctx, ".")
	if err != nil {
		log.Fatalf("Error checking binaries: %v", err)
	}

	fmt.Printf("Found %d binaries:\n\n", len(reports))

	// Process each binary report - all info is already provided by CheckBinaries
	for i, report := range reports {
		fmt.Printf("[%d] %s\n", i+1, report.RelativePath)

		if report.Error != nil {
			fmt.Printf("  Error: %v\n", report.Error)
			continue
		}

		details := report.GoBinaryDetails
		fmt.Printf("  Go Version: %s\n", details.GoVersion)
		fmt.Printf("  Module: %s\n", details.Module)
		fmt.Printf("  CGO Enabled: %t\n", details.CGOEnabled)
		fmt.Printf("  Uses Systemcrypto: %t\n", details.UseSystemcrypto)
		fmt.Printf("  Uses OpensslNoCGO: %t\n", details.UseOpensslNoCGO)
		fmt.Printf("  Fails FIPS Check: %t\n", details.FailsOnFIPSCheck)

		// Determine final FIPS compliance using SDK helper
		isCompliant := fipscheck.IsBinaryFIPSCompliant(details, hostInfo.FIPSCapable)
		if isCompliant {
			fmt.Printf("  ✅ FIPS Status: COMPLIANT\n")
		} else {
			fmt.Printf("  ❌ FIPS Status: NOT COMPLIANT\n")
			// Show why it's not compliant
			if !details.UseSystemcrypto && !details.UseOpensslNoCGO {
				fmt.Printf("    Reason: Missing GOEXPERIMENT=systemcrypto or GOEXPERIMENT=ms_nocgo_opensslcrypto\n")
			}
			if !details.CGOEnabled {
				fmt.Printf("    Reason: CGO not enabled\n")
			}
			if details.FailsOnFIPSCheck {
				fmt.Printf("    Reason: Runtime FIPS check failed\n")
			}
			if !hostInfo.FIPSCapable {
				fmt.Printf("    Reason: Host not FIPS capable\n")
			}
		}

		if details.RuntimePanicLog != "" {
			fmt.Printf("  Runtime Log: %s\n", details.RuntimePanicLog)
		}

		fmt.Println()
	}

	fmt.Printf("Summary: %d binaries scanned\n", len(reports))
}
