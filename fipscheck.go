//go:build cgo

// Package fipscheck provides FIPS compliance checking functionality for Go binaries.
// This package exposes the functionality from internal packages to allow external
// repositories to use the FIPS checking capabilities.
package fipscheck

import (
	"context"

	"github.com/bahe-msft/fips-check/internal/binarychecker"
	_ "github.com/bahe-msft/fips-check/internal/opensslsetup" // Initialize OpenSSL
	"github.com/golang-fips/openssl/v2"
)

// BinaryReport contains the FIPS compliance information for a binary file.
// This mirrors the internal BinaryReport structure to provide external access.
type BinaryReport struct {
	// RelativePath is the path of the binary relative to the scan root
	RelativePath string
	// Type indicates the type of binary (e.g., "gobinary")
	Type            string
	GoBinaryDetails GoBinaryReportDetails
	// Error contains any error that occurred while scanning this binary
	Error error
}

// GoBinaryReportDetails contains detailed information about a Go binary's FIPS capabilities.
type GoBinaryReportDetails struct {
	GoVersion        string
	Module           string
	UseSystemcrypto  bool
	UseOpensslNoCGO  bool
	CGOEnabled       bool
	FailsOnFIPSCheck bool   // Indicates if the binary fails when run with GOFIPS=1
	RuntimePanicLog  string // Captures the panic log from runtime FIPS check
}

// CheckBinaries recursively scans the filesystem starting from the given path
// and checks all binaries for FIPS compliance in parallel.
// It returns a slice of BinaryReport containing the results for each binary found.
func CheckBinaries(ctx context.Context, path string) ([]BinaryReport, error) {
	internalReports, err := binarychecker.Check(ctx, path)
	if err != nil {
		return nil, err
	}

	// Convert internal reports to public SDK reports
	reports := make([]BinaryReport, len(internalReports))
	for i, report := range internalReports {
		reports[i] = BinaryReport{
			RelativePath: report.RelativePath,
			Type:         report.Type,
			GoBinaryDetails: GoBinaryReportDetails{
				GoVersion:        report.GoBinaryDetails.GoVersion,
				Module:           report.GoBinaryDetails.Module,
				UseSystemcrypto:  report.GoBinaryDetails.UseSystemcrypto,
				UseOpensslNoCGO:  report.GoBinaryDetails.UseOpensslNoCGO,
				CGOEnabled:       report.GoBinaryDetails.CGOEnabled,
				FailsOnFIPSCheck: report.GoBinaryDetails.FailsOnFIPSCheck,
				RuntimePanicLog:  report.GoBinaryDetails.RuntimePanicLog,
			},
			Error: report.Error,
		}
	}

	return reports, nil
}

// HostFIPSInfo contains information about the host's FIPS capabilities.
type HostFIPSInfo struct {
	OpenSSLVersion string
	FIPSCapable    bool
}

// CheckHostFIPS returns information about the host's FIPS capabilities.
// This function checks the OpenSSL version and FIPS capability of the current host.
func CheckHostFIPS() HostFIPSInfo {
	return HostFIPSInfo{
		OpenSSLVersion: openssl.VersionText(),
		FIPSCapable:    openssl.FIPSCapable(),
	}
}

// IsBinaryFIPSCompliant determines if a binary is FIPS compliant based on the report details.
// A binary is considered FIPS compliant if:
// - It uses systemcrypto (GOEXPERIMENT=systemcrypto)
// - It doesn't fail the runtime FIPS check
// - The host system is FIPS capable
func IsBinaryFIPSCompliant(details GoBinaryReportDetails, hostFIPSCapable bool) bool {
	if !details.UseSystemcrypto && !details.UseOpensslNoCGO {
		return false
	}
	if details.FailsOnFIPSCheck {
		return false
	}
	return hostFIPSCapable
}
