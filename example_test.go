//go:build cgo

package fipscheck

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestExampleUsage demonstrates how external users would use the SDK
func TestExampleUsage(t *testing.T) {
	// Example 1: Check host FIPS capabilities
	t.Run("example_host_check", func(t *testing.T) {
		hostInfo := CheckHostFIPS()

		t.Logf("Example Host Check:")
		t.Logf("  OpenSSL Version: %s", hostInfo.OpenSSLVersion)
		t.Logf("  FIPS Capable: %t", hostInfo.FIPSCapable)

		// Verify we get valid data
		if hostInfo.OpenSSLVersion == "" {
			t.Error("Should return non-empty OpenSSL version")
		}
	})

	// Example 2: Check binaries in a directory
	t.Run("example_binary_check", func(t *testing.T) {
		// Create a temporary test directory
		tempDir, err := os.MkdirTemp("", "example-test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		reports, err := CheckBinaries(ctx, tempDir)
		if err != nil {
			t.Fatalf("CheckBinaries should not fail on empty directory: %v", err)
		}

		t.Logf("Example Binary Check:")
		t.Logf("  Scanned directory: %s", tempDir)
		t.Logf("  Found %d binaries", len(reports))
	})

	// Example 3: FIPS compliance logic
	t.Run("example_compliance_check", func(t *testing.T) {
		hostInfo := CheckHostFIPS()

		// Example binary details (simulated)
		examples := []struct {
			name    string
			details GoBinaryReportDetails
		}{
			{
				name: "FIPS_ready_binary_systemcrypto",
				details: GoBinaryReportDetails{
					GoVersion:        "go1.24.6 X:systemcrypto",
					Module:           "example.com/app",
					UseSystemcrypto:  true,
					UseOpensslNoCGO:  false,
					CGOEnabled:       true,
					FailsOnFIPSCheck: false,
				},
			},
			{
				name: "FIPS_ready_binary_ms_nocgo_opensslcrypto",
				details: GoBinaryReportDetails{
					GoVersion:        "go1.24.6 X:systemcrypto",
					Module:           "example.com/app",
					UseSystemcrypto:  false,
					UseOpensslNoCGO:  true,
					CGOEnabled:       true,
					FailsOnFIPSCheck: false,
				},
			},
			{
				name: "non_FIPS_binary",
				details: GoBinaryReportDetails{
					GoVersion:        "go1.21.0",
					Module:           "example.com/old-app",
					UseSystemcrypto:  false,
					UseOpensslNoCGO:  false,
					CGOEnabled:       true,
					FailsOnFIPSCheck: false,
				},
			},
		}

		for _, example := range examples {
			isCompliant := IsBinaryFIPSCompliant(example.details, hostInfo.FIPSCapable)

			t.Logf("Example Compliance Check - %s:", example.name)
			t.Logf("  Go Version: %s", example.details.GoVersion)
			t.Logf("  Uses Systemcrypto: %t", example.details.UseSystemcrypto)
			t.Logf("  Uses OpensslNoCGO: %t", example.details.UseOpensslNoCGO)
			t.Logf("  CGO Enabled: %t", example.details.CGOEnabled)
			t.Logf("  Runtime Check Passes: %t", !example.details.FailsOnFIPSCheck)
			t.Logf("  Host FIPS Capable: %t", hostInfo.FIPSCapable)
			t.Logf("  → Final Compliance: %t", isCompliant)
		}
	})
}

// TestExampleErrorHandling shows how to handle errors properly
func TestExampleErrorHandling(t *testing.T) {
	t.Run("example_timeout_handling", func(t *testing.T) {
		// Very short timeout to demonstrate cancellation
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// This might complete or might be cancelled
		reports, err := CheckBinaries(ctx, "/tmp")

		if err != nil {
			t.Logf("Example: Handled timeout/cancellation: %v", err)
		} else {
			t.Logf("Example: Completed before timeout, found %d reports", len(reports))
		}
	})

	t.Run("example_invalid_path", func(t *testing.T) {
		ctx := context.Background()

		// Test with non-existent directory
		reports, err := CheckBinaries(ctx, "/definitely/does/not/exist")

		if err != nil {
			t.Logf("Example: Properly handled invalid path: %v", err)
		} else {
			t.Logf("Example: No error for invalid path, got %d reports", len(reports))
		}
	})
}

// TestSDKWorkflow demonstrates a complete SDK workflow
func TestSDKWorkflow(t *testing.T) {
	t.Run("complete_workflow", func(t *testing.T) {
		t.Log("=== Complete SDK Workflow Example ===")

		// Step 1: Check host environment
		t.Log("Step 1: Checking host FIPS environment...")
		hostInfo := CheckHostFIPS()
		t.Logf("Host OpenSSL: %s", hostInfo.OpenSSLVersion)
		t.Logf("Host FIPS Capable: %t", hostInfo.FIPSCapable)

		// Step 2: Scan for binaries
		t.Log("Step 2: Scanning for Go binaries...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Use /usr/bin which likely exists but may not have Go binaries
		reports, err := CheckBinaries(ctx, "/usr/bin")
		if err != nil {
			t.Logf("Scan error (expected): %v", err)
			return
		}

		t.Logf("Found %d Go binaries", len(reports))

		// Step 3: Analyze each binary
		if len(reports) > 0 {
			t.Log("Step 3: Analyzing FIPS compliance...")

			compliantCount := 0
			for i, report := range reports {
				if i >= 3 { // Limit output for test
					break
				}

				isCompliant := IsBinaryFIPSCompliant(report.GoBinaryDetails, hostInfo.FIPSCapable)
				if isCompliant {
					compliantCount++
				}

				t.Logf("Binary %d: %s", i+1, report.RelativePath)
				t.Logf("  Module: %s", report.GoBinaryDetails.Module)
				t.Logf("  Go Version: %s", report.GoBinaryDetails.GoVersion)
				t.Logf("  FIPS Compliant: %t", isCompliant)

				if report.Error != nil {
					t.Logf("  Error: %v", report.Error)
				}
			}

			t.Logf("Summary: %d/%d binaries are FIPS compliant", compliantCount, len(reports))
		} else {
			t.Log("Step 3: No Go binaries found to analyze")
		}

		t.Log("=== Workflow Complete ===")
	})
}

// TestExampleDockerImage demonstrates checking FIPS compliance in a Docker container
func TestExampleDockerImage(t *testing.T) {
	t.Run("real_docker_fips_image", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Docker integration test in short mode")
		}

		imageName := "mcr.microsoft.com/oss/v2/istio/proxyv2-fips:v1.26.4-1"
		t.Logf("Real Docker Image Test: %s", imageName)

		extractedPath, cleanup, err := extractDockerImage(t, imageName)
		if err != nil {
			t.Skipf("Could not extract Docker image %s: %v", imageName, err)
		}
		defer cleanup()

		// Check binaries in the extracted container
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		reports, err := CheckBinaries(ctx, extractedPath)
		if err != nil {
			t.Logf("CheckBinaries error (may be expected): %v", err)
		}

		// Check host FIPS capability first
		hostInfo := CheckHostFIPS()

		t.Logf("=== Host FIPS Environment Check ===")
		t.Logf("OpenSSL Version: %s", hostInfo.OpenSSLVersion)
		t.Logf("FIPS Capable: %t", hostInfo.FIPSCapable)
		if hostInfo.FIPSCapable {
			t.Logf("✅ Status: Host is FIPS capable")
		} else {
			t.Logf("❌ Status: Host is NOT FIPS capable")
		}
		t.Logf("")

		t.Logf("=== Binary FIPS Check Report ===")
		t.Logf("Found %d binaries in container", len(reports))

		// Analyze any Go binaries found
		for _, report := range reports {
			if report.Error != nil {
				t.Logf("Binary %s had error: %v", report.RelativePath, report.Error)
				continue
			}

			isCompliant := IsBinaryFIPSCompliant(report.GoBinaryDetails, hostInfo.FIPSCapable)
			t.Logf("Binary: %s", report.RelativePath)
			t.Logf("  Go Version: %s", report.GoBinaryDetails.GoVersion)
			t.Logf("  Uses Systemcrypto: %t", report.GoBinaryDetails.UseSystemcrypto)
			t.Logf("  CGO Enabled: %t", report.GoBinaryDetails.CGOEnabled)
			t.Logf("  FIPS Compliant: %t", isCompliant)
		}
	})

	t.Run("real_docker_negative_image", func(t *testing.T) {
		if testing.Short() {
			t.Skip("Skipping Docker integration test in short mode")
		}

		// Use a Kubernetes CSI image that should have Go binaries without systemcrypto
		imageName := "mcr.microsoft.com/oss/kubernetes-csi/blob-csi:v1.26.6"
		t.Logf("Real Docker Negative Test (non-FIPS image): %s", imageName)

		extractedPath, cleanup, err := extractDockerImage(t, imageName)
		if err != nil {
			t.Skipf("Could not extract non-FIPS image %s: %v", imageName, err)
		}
		defer cleanup()

		// Check host FIPS capability first
		hostInfo := CheckHostFIPS()

		t.Logf("=== Host FIPS Environment Check ===")
		t.Logf("OpenSSL Version: %s", hostInfo.OpenSSLVersion)
		t.Logf("FIPS Capable: %t", hostInfo.FIPSCapable)
		if hostInfo.FIPSCapable {
			t.Logf("✅ Status: Host is FIPS capable")
		} else {
			t.Logf("❌ Status: Host is NOT FIPS capable")
		}
		t.Logf("")

		// Check binaries in the extracted container
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		reports, err := CheckBinaries(ctx, extractedPath)
		if err != nil {
			t.Logf("CheckBinaries error (may be expected): %v", err)
		}

		t.Logf("=== Binary FIPS Check Report ===")
		t.Logf("Found %d binaries in non-FIPS container", len(reports))

		// Verify that binaries are identified as non-compliant
		foundGoBinaries := 0
		compliantBinaries := 0

		for _, report := range reports {
			if report.Error != nil {
				t.Logf("Binary %s had error: %v", report.RelativePath, report.Error)
				continue
			}

			foundGoBinaries++
			isCompliant := IsBinaryFIPSCompliant(report.GoBinaryDetails, hostInfo.FIPSCapable)

			t.Logf("")
			t.Logf("─────────────────────────────────────────────────────")
			t.Logf("[%d] Binary: %s", foundGoBinaries, report.RelativePath)
			t.Logf("    Go Version: %s", report.GoBinaryDetails.GoVersion)
			t.Logf("    Module: %s", report.GoBinaryDetails.Module)
			t.Logf("    Uses Systemcrypto: %t", report.GoBinaryDetails.UseSystemcrypto)
			t.Logf("    Uses OpensslNoCGO: %t", report.GoBinaryDetails.UseOpensslNoCGO)
			t.Logf("    CGO Enabled: %t", report.GoBinaryDetails.CGOEnabled)
			t.Logf("    Fails FIPS Check: %t", report.GoBinaryDetails.FailsOnFIPSCheck)

			if isCompliant {
				compliantBinaries++
				t.Logf("    ✅ FIPS Status: COMPLIANT")
			} else {
				t.Logf("    ❌ FIPS Status: NOT COMPLIANT")
				// Explain why it's not compliant
				t.Logf("    → Reasons for non-compliance:")
				if !report.GoBinaryDetails.UseSystemcrypto && !report.GoBinaryDetails.UseOpensslNoCGO {
					t.Logf("      - Missing GOEXPERIMENT=systemcrypto or GOEXPERIMENT=ms_nocgo_opensslcrypto")
				}
				if report.GoBinaryDetails.FailsOnFIPSCheck {
					t.Logf("      - Runtime FIPS check failed")
				}
				if !hostInfo.FIPSCapable {
					t.Logf("      - Host not FIPS capable")
				}
			}
		}

		t.Logf("─────────────────────────────────────────────────────")

		if foundGoBinaries > 0 {
			t.Logf("")
			t.Logf("Summary:")
			t.Logf("  Total: %d | Compliant: %d | Non-compliant: %d",
				foundGoBinaries, compliantBinaries, foundGoBinaries-compliantBinaries)

			// For a non-FIPS image, we expect most/all binaries to be non-compliant
			if compliantBinaries == foundGoBinaries {
				t.Errorf("❌ Expected non-FIPS image to have non-compliant binaries, but all %d were compliant", compliantBinaries)
			} else {
				t.Logf("✅ SDK correctly identified %d/%d binaries as non-FIPS compliant",
					foundGoBinaries-compliantBinaries, foundGoBinaries)
			}
		} else {
			t.Log("No Go binaries found in container for FIPS analysis")
		}
	})
}

// extractDockerImage pulls a Docker image and extracts its filesystem to a temporary directory
func extractDockerImage(t *testing.T, imageName string) (extractedPath string, cleanup func(), err error) {
	// Create temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "docker-extract-")
	if err != nil {
		return "", nil, err
	}

	cleanup = func() {
		os.RemoveAll(tempDir)
	}

	// Check if docker command is available
	if _, err := os.Stat("/usr/bin/docker"); os.IsNotExist(err) {
		if _, err := os.Stat("/usr/local/bin/docker"); os.IsNotExist(err) {
			return "", cleanup, fmt.Errorf("docker command not found")
		}
	}

	// Pull the Docker image
	t.Logf("Pulling Docker image: %s", imageName)
	pullCmd := fmt.Sprintf("docker pull %s", imageName)
	if err := runCommand(pullCmd); err != nil {
		return "", cleanup, fmt.Errorf("failed to pull image: %v", err)
	}

	// Create a container from the image (without running it)
	containerName := fmt.Sprintf("fips-test-%d", time.Now().Unix())
	createCmd := fmt.Sprintf("docker create --name %s %s", containerName, imageName)
	if err := runCommand(createCmd); err != nil {
		return "", cleanup, fmt.Errorf("failed to create container: %v", err)
	}

	// Export the container filesystem
	exportCmd := fmt.Sprintf("docker export %s | tar -xf - -C %s", containerName, tempDir)
	if err := runCommand(exportCmd); err != nil {
		// Clean up container even if export fails
		runCommand(fmt.Sprintf("docker rm %s", containerName))
		return "", cleanup, fmt.Errorf("failed to export container: %v", err)
	}

	// Clean up the container
	if err := runCommand(fmt.Sprintf("docker rm %s", containerName)); err != nil {
		t.Logf("Warning: failed to remove container %s: %v", containerName, err)
	}

	return tempDir, cleanup, nil
}

// runCommand executes a shell command and returns an error if it fails
func runCommand(cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	var execCmd *exec.Cmd
	if len(parts) == 1 {
		execCmd = exec.Command(parts[0])
	} else {
		execCmd = exec.Command(parts[0], parts[1:]...)
	}

	// For complex commands with pipes, use shell
	if strings.Contains(cmd, "|") {
		execCmd = exec.Command("sh", "-c", cmd)
	}

	output, err := execCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s, output: %s", err, string(output))
	}
	return nil
}
