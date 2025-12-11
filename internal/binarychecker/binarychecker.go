package binarychecker

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type GoBinaryReportDetails struct {
	GoVersion        string
	Module           string
	UseSystemcrypto  bool
	UseOpensslNoCGO  bool
	CGOEnabled       bool
	FailsOnFIPSCheck bool   // Indicates if the binary fails when run with GOFIPS=1
	RuntimePanicLog  string // Captures the panic log from runtime FIPS check
}

// BinaryReport contains the FIPS compliance information for a binary file.
type BinaryReport struct {
	// RelativePath is the path of the binary relative to the scan root
	RelativePath string
	// Type indicates the type of binary (e.g., "gobinary")
	Type            string
	GoBinaryDetails GoBinaryReportDetails
	// Error contains any error that occurred while scanning this binary
	Error error
}

// Check recursively scans the filesystem starting from the given path
// and checks all binaries for FIPS compliance in parallel.
// It returns a slice of BinaryReport containing the results for each binary found.
func Check(ctx context.Context, path string) ([]BinaryReport, error) {
	// Get absolute path for the root to calculate relative paths
	absRoot, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Collect all binary paths first
	var binaryPaths []string
	err = filepath.WalkDir(absRoot, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip directories/files we can't read
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Skip excluded paths (e.g., /proc, /sys)
		if shouldExcludePath(filePath) {
			return nil
		}

		// Check if the file is a binary
		if isBinary(filePath) {
			binaryPaths = append(binaryPaths, filePath)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking directory tree: %w", err)
	}

	// Process binaries in parallel
	reports := make([]BinaryReport, len(binaryPaths))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Use a semaphore to limit concurrency
	semaphore := make(chan struct{}, 10) // Limit to 10 concurrent checks

	for i, filePath := range binaryPaths {
		// Check context cancellation before starting each goroutine
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		go func(idx int, fp string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Check context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Calculate relative path
			relPath, err := filepath.Rel(absRoot, fp)
			if err != nil {
				relPath = fp // fallback to absolute path
			}

			report := BinaryReport{
				RelativePath: relPath,
				Type:         "gobinary",
			}

			// Perform FIPS check
			details, checkErr := checkGoBinaryFIPS(ctx, fp)
			report.GoBinaryDetails = details
			report.Error = checkErr

			mu.Lock()
			reports[idx] = report
			mu.Unlock()
		}(i, filePath)
	}

	wg.Wait()

	// Check if context was cancelled during execution
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return reports, nil
}

// isBinary checks if a file is an executable Go binary.
// It checks for executable permissions, verifies it's an ELF binary,
// and uses debug/buildinfo to confirm it's a Go binary.
func isBinary(filePath string) bool {
	// Check file permissions
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	// Check if file has executable permission
	if info.Mode()&0o111 == 0 {
		return false
	}

	// Try to open as ELF file to verify it's a binary
	f, err := elf.Open(filePath)
	if err != nil {
		return false
	}
	f.Close()

	_, err = buildinfo.ReadFile(filePath)
	if err != nil {
		// Not a Go binary
		// TODO: handle special cases where the binary is built by bazel
		return false
	}

	return true
}

// shouldExcludePath checks if a path should be excluded from scanning.
// This excludes virtual filesystems like /proc and /sys that contain symlinks
// to running processes.
func shouldExcludePath(filePath string) bool {
	// List of path prefixes to exclude
	excludedPrefixes := []string{
		"/proc/",
		"/sys/",
		"/dev/",
	}

	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(filePath, prefix) {
			return true
		}
	}

	return false
}

// checkGoBinaryFIPS performs FIPS compliance check on a Go binary.
// It extracts build information and determines FIPS capability.
// Returns: details GoBinaryReportDetails, error
func checkGoBinaryFIPS(ctx context.Context, filePath string) (GoBinaryReportDetails, error) {
	details := GoBinaryReportDetails{}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return details, ctx.Err()
	default:
	}

	// Read build info from the binary
	info, err := buildinfo.ReadFile(filePath)
	if err != nil {
		return details, fmt.Errorf("failed to read build info: %w", err)
	}

	// Extract Go version
	details.GoVersion = info.GoVersion

	// Extract module path
	if info.Main.Path != "" {
		details.Module = info.Main.Path
	}

	// Check build settings for CGO and GOEXPERIMENT=systemcrypto
	for _, setting := range info.Settings {
		switch setting.Key {
		case "CGO_ENABLED":
			details.CGOEnabled = setting.Value == "1"
		case "GOEXPERIMENT":
			// Check if systemcrypto experiment is enabled
			if strings.Contains(setting.Value, "systemcrypto") {
				details.UseSystemcrypto = true
			}
			if strings.Contains(setting.Value, "ms_nocgo_opensslcrypto") {
				details.UseOpensslNoCGO = true
			}
		}
	}

	passed, panicLog, err := checkRuntimeFIPS(ctx, filePath)
	if err != nil {
		// If we can't perform runtime check, return the static analysis result
		return details, fmt.Errorf("runtime FIPS check failed: %w", err)
	}
	// Store the panic log in details
	details.RuntimePanicLog = panicLog
	// Set FailsOnFIPSCheck to true if the binary did not pass (failed)
	details.FailsOnFIPSCheck = !passed

	return details, nil
}

// checkRuntimeFIPS attempts to run the binary with GOFIPS=1 environment variable
// to verify runtime FIPS compliance.
//
// Requirements:
//   - The binary is invoked with environment variable GOFIPS=1 to enforce FIPS mode
//   - If the binary panics with an error message like:
//     "panic: opensslcrypto: FIPS mode requested (system FIPS mode) but not available in OpenSSL 3.0.16"
//     then it is NOT FIPS compliant (returns false)
//   - If the binary does not panic with FIPS-related errors, it MIGHT BE FIPS compliant
//     (returns true), as actual compliance depends on the host system configuration
//   - The binary is given a short timeout (2 seconds) to start and potentially panic
//
// Returns:
// - bool: true if binary might be FIPS compliant, false if FIPS panic detected
// - string: the panic log or stderr output captured during execution
// - error: if the check cannot be performed
func checkRuntimeFIPS(ctx context.Context, filePath string) (bool, string, error) {
	// Create a context with timeout for the binary execution
	execCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Prepare the command with GOFIPS=1 environment variable
	cmd := exec.CommandContext(execCtx, filePath)
	cmd.Env = append(os.Environ(), "GOFIPS=1")

	// Capture stderr to check for FIPS-related panic messages
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Run the command
	err := cmd.Run()

	// Check the stderr output for FIPS-related panic messages
	stderrOutput := stderr.String()

	// Look for FIPS mode panic indicators
	fipsPanicIndicators := []string{
		"panic: opensslcrypto: FIPS mode requested",
		"FIPS mode requested",
		"but not available in OpenSSL",
	}

	for _, indicator := range fipsPanicIndicators {
		if strings.Contains(stderrOutput, indicator) {
			// Binary panicked due to FIPS unavailability - NOT FIPS compliant
			// Return the panic log
			return false, stderrOutput, nil
		}
	}

	// If the command timed out or exited for other reasons without FIPS panic,
	// we consider it potentially FIPS compliant
	if err != nil {
		// Check if it's a timeout or context cancellation
		if execCtx.Err() == context.DeadlineExceeded {
			// Timeout means the binary ran without panicking immediately
			// This is a good sign for FIPS compliance
			return true, stderrOutput, nil
		}

		// For other errors, if there's no FIPS panic in stderr, still consider it compliant
		if !strings.Contains(stderrOutput, "FIPS") {
			return true, stderrOutput, nil
		}
	}

	// No FIPS-related panic detected - might be FIPS compliant
	return true, stderrOutput, nil
}
