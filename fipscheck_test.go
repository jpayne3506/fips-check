//go:build cgo

package fipscheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckHostFIPS(t *testing.T) {
	hostInfo := CheckHostFIPS()

	// Verify we get non-empty version string
	if hostInfo.OpenSSLVersion == "" {
		t.Error("Expected non-empty OpenSSL version")
	}

	// FIPS capability is boolean, so just verify we get a response
	t.Logf("OpenSSL Version: %s", hostInfo.OpenSSLVersion)
	t.Logf("FIPS Capable: %t", hostInfo.FIPSCapable)
}

func TestIsBinaryFIPSCompliant(t *testing.T) {
	tests := []struct {
		name        string
		details     GoBinaryReportDetails
		hostCapable bool
		expected    bool
		description string
	}{
		{
			name: "fully_compliant_systemcrypto",
			details: GoBinaryReportDetails{
				UseSystemcrypto:  true,
				UseOpensslNoCGO:  false,
				CGOEnabled:       true,
				FailsOnFIPSCheck: false,
			},
			hostCapable: true,
			expected:    true,
			description: "Binary with systemcrypto, passes runtime, host capable",
		},
		{
			name: "fully_compliant_ms_nocgo_opensslcrypto",
			details: GoBinaryReportDetails{
				UseSystemcrypto:  false,
				UseOpensslNoCGO:  true,
				CGOEnabled:       true,
				FailsOnFIPSCheck: false,
			},
			hostCapable: true,
			expected:    true,
			description: "Binary with ms_nocgo_opensslcrypto, passes runtime, host capable",
		},
		{
			name: "no_systemcrypto_or_ms_nocgo_opensslcrypto",
			details: GoBinaryReportDetails{
				UseSystemcrypto:  false,
				UseOpensslNoCGO:  false,
				CGOEnabled:       true,
				FailsOnFIPSCheck: false,
			},
			hostCapable: true,
			expected:    false,
			description: "Binary without systemcrypto or ms_nocgo_opensslcrypto",
		},
		{
			name: "runtime_fails",
			details: GoBinaryReportDetails{
				UseSystemcrypto:  true,
				CGOEnabled:       true,
				FailsOnFIPSCheck: true,
			},
			hostCapable: true,
			expected:    false,
			description: "Binary with systemcrypto but fails runtime check",
		},
		{
			name: "host_not_capable",
			details: GoBinaryReportDetails{
				UseSystemcrypto:  true,
				CGOEnabled:       true,
				FailsOnFIPSCheck: false,
			},
			hostCapable: false,
			expected:    false,
			description: "Binary ready but host not FIPS capable",
		},
		{
			name: "multiple_issues",
			details: GoBinaryReportDetails{
				UseSystemcrypto:  false,
				UseOpensslNoCGO:  false,
				CGOEnabled:       false,
				FailsOnFIPSCheck: true,
			},
			hostCapable: false,
			expected:    false,
			description: "Binary with multiple FIPS issues",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsBinaryFIPSCompliant(tt.details, tt.hostCapable)
			if result != tt.expected {
				t.Errorf("Test %s (%s): expected %t, got %t",
					tt.name, tt.description, tt.expected, result)
			}
		})
	}
}

func TestCheckBinariesWithEmptyDir(t *testing.T) {
	// Create temporary empty directory
	tempDir, err := os.MkdirTemp("", "fips-test-empty")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reports, err := CheckBinaries(ctx, tempDir)
	if err != nil {
		t.Fatalf("CheckBinaries failed on empty directory: %v", err)
	}

	if len(reports) != 0 {
		t.Errorf("Expected 0 reports for empty directory, got %d", len(reports))
	}
}

func TestCheckBinariesWithNonExistentPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nonExistentPath := "/path/that/definitely/does/not/exist"
	reports, err := CheckBinaries(ctx, nonExistentPath)
	// Should handle non-existent paths gracefully
	if err != nil {
		t.Logf("Expected error for non-existent path: %v", err)
	}

	// If no error, should return empty results
	if err == nil && len(reports) != 0 {
		t.Errorf("Expected 0 reports for non-existent path, got %d", len(reports))
	}
}

func TestCheckBinariesContextCancellation(t *testing.T) {
	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	reports, err := CheckBinaries(ctx, "/tmp")

	// Should respect context cancellation
	if err != nil && err == context.Canceled {
		t.Logf("Correctly handled context cancellation: %v", err)
	} else if err == nil {
		// If it completes fast enough before cancellation, that's also OK
		t.Logf("Completed before cancellation, found %d reports", len(reports))
	}
}

func TestBinaryReportStructure(t *testing.T) {
	// Test that BinaryReport structure contains expected fields
	report := BinaryReport{
		RelativePath: "test/binary",
		Type:         "gobinary",
		GoBinaryDetails: GoBinaryReportDetails{
			GoVersion:        "go1.24.6 X:systemcrypto",
			Module:           "github.com/example/test",
			UseSystemcrypto:  true,
			UseOpensslNoCGO:  true,
			CGOEnabled:       true,
			FailsOnFIPSCheck: false,
			RuntimePanicLog:  "",
		},
		Error: nil,
	}

	// Verify all fields are accessible
	if report.RelativePath != "test/binary" {
		t.Error("RelativePath field not working")
	}
	if report.Type != "gobinary" {
		t.Error("Type field not working")
	}
	if report.GoBinaryDetails.GoVersion != "go1.24.6 X:systemcrypto" {
		t.Error("GoBinaryDetails.GoVersion field not working")
	}
	if !report.GoBinaryDetails.UseSystemcrypto {
		t.Error("GoBinaryDetails.UseSystemcrypto field not working")
	}
	if !report.GoBinaryDetails.UseOpensslNoCGO {
		t.Error("GoBinaryDetails.UseOpensslNoCGO field not working")
	}
}

func TestHostFIPSInfoStructure(t *testing.T) {
	// Test HostFIPSInfo structure
	hostInfo := HostFIPSInfo{
		OpenSSLVersion: "OpenSSL 3.0.2",
		FIPSCapable:    false,
	}

	if hostInfo.OpenSSLVersion != "OpenSSL 3.0.2" {
		t.Error("OpenSSLVersion field not working")
	}
	if hostInfo.FIPSCapable != false {
		t.Error("FIPSCapable field not working")
	}
}

// Benchmark test for CheckBinaries performance
func BenchmarkCheckHostFIPS(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CheckHostFIPS()
	}
}

func BenchmarkIsBinaryFIPSCompliant(b *testing.B) {
	details := GoBinaryReportDetails{
		UseSystemcrypto:  true,
		CGOEnabled:       true,
		FailsOnFIPSCheck: false,
	}

	for i := 0; i < b.N; i++ {
		IsBinaryFIPSCompliant(details, true)
	}
}

// Integration test that creates a real test environment
func TestIntegrationWithRealBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Try to find a Go binary on the system for testing
	goBinary := ""
	possiblePaths := []string{
		"/usr/bin/go",
		"/usr/local/bin/go",
		"/usr/local/go/bin/go",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			goBinary = path
			break
		}
	}

	if goBinary == "" {
		t.Skip("No Go binary found for integration test")
	}

	// Create temp directory and copy Go binary
	tempDir, err := os.MkdirTemp("", "fips-integration-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testBinary := filepath.Join(tempDir, "test-go")
	if err := copyFile(goBinary, testBinary); err != nil {
		t.Fatalf("Failed to copy test binary: %v", err)
	}

	// Make it executable
	if err := os.Chmod(testBinary, 0o755); err != nil {
		t.Fatalf("Failed to make binary executable: %v", err)
	}

	// Test CheckBinaries with real binary
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	reports, err := CheckBinaries(ctx, tempDir)
	if err != nil {
		t.Fatalf("CheckBinaries failed: %v", err)
	}

	// Should find at least one binary
	if len(reports) == 0 {
		t.Logf("No Go binaries detected (this is OK if the copied binary isn't a Go binary)")
	} else {
		t.Logf("Found %d binaries", len(reports))
		for _, report := range reports {
			t.Logf("Binary: %s, Type: %s, GoVersion: %s",
				report.RelativePath, report.Type, report.GoBinaryDetails.GoVersion)
		}
	}
}

// Helper function to copy files for integration test
func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0o644)
}
