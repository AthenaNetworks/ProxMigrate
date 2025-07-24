package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Build-time variables (set by build script)
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// ServerConfig represents a single server configuration
type ServerConfig struct {
	Host          string `json:"host"`
	User          string `json:"user"`
	TokenID       string `json:"token_id"`
	TokenSecret   string `json:"token_secret"`
	Insecure      bool   `json:"insecure"`
	BackupStorage string `json:"backup_storage"`
}

// TargetConfig represents a target server configuration with additional fields
type TargetConfig struct {
	ServerConfig
	Node    string `json:"node"`
	Storage string `json:"storage"`
}

// Config represents the JSON configuration structure
type Config struct {
	Sources map[string]ServerConfig `json:"sources"`
	Targets map[string]TargetConfig `json:"targets"`

	SSH struct {
		User    string `json:"user"`
		KeyPath string `json:"key_path"`
	} `json:"ssh"`
}

// SSH helper functions

// resolveSSHKeyPath resolves SSH key path relative to executable directory if it's a relative path
func resolveSSHKeyPath(keyPath string) (string, error) {
	// If it's already an absolute path, return as-is
	if filepath.IsAbs(keyPath) {
		return keyPath, nil
	}

	// If it starts with ~/, expand to home directory
	if strings.HasPrefix(keyPath, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not get home directory: %w", err)
		}
		return filepath.Join(homeDir, keyPath[2:]), nil
	}

	// For relative paths, resolve relative to executable directory
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not determine executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)
	return filepath.Join(execDir, keyPath), nil
}

// createSSHClient creates an SSH client connection
func createSSHClient(host, user, keyPath string) (*ssh.Client, error) {
	// Resolve the SSH key path
	resolvedKeyPath, err := resolveSSHKeyPath(keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve SSH key path: %w", err)
	}

	// Read the private key
	key, err := os.ReadFile(resolvedKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key from %s: %w", resolvedKeyPath, err)
	}

	// Create the Signer for this private key
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %w", err)
	}

	// SSH client configuration
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Note: In production, use proper host key verification
		Timeout:         30 * time.Second,
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", host+":22", config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial SSH: %w", err)
	}

	return client, nil
}

// executeSSHCommand executes a command over SSH and returns the output
func executeSSHCommand(client *ssh.Client, command string) (string, error) {
	// Create a session
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Run the command
	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}

	return string(output), nil
}

// executeSSHCommandWithStreaming executes a command over SSH and streams output in real-time
func executeSSHCommandWithStreaming(client *ssh.Client, command string) (string, error) {
	// Create a session
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	// Create pipes for stdout and stderr
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := session.Start(command); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	// Buffer to collect all output
	var outputBuffer strings.Builder

	// Channel to signal completion
	done := make(chan bool, 2)

	// Stream stdout
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		var lastWasProgress bool
		for scanner.Scan() {
			line := scanner.Text()

			// Check if this line contains progress information
			isProgress := strings.Contains(line, "%") || strings.Contains(line, "MiB/s") || strings.Contains(line, "GiB") || strings.Contains(line, "transferred")

			if isProgress {
				// Clear line and print progress update
				fmt.Printf("\r\033[K[SSH] %s", line)
				lastWasProgress = true
			} else {
				// If previous line was progress, add newline first
				if lastWasProgress {
					fmt.Println()
				}
				fmt.Printf("[SSH] %s\n", line)
				lastWasProgress = false
			}

			outputBuffer.WriteString(line + "\n")
		}

		// If last line was progress, add final newline
		if lastWasProgress {
			fmt.Println()
		}

		done <- true
	}()

	// Stream stderr
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			//line := scanner.Text()
			//fmt.Printf("[SSH ERROR] %s\n", line)
			//outputBuffer.WriteString(line + "\n")
		}
		done <- true
	}()

	// Wait for both streams to complete
	<-done
	<-done

	// Wait for the command to complete
	err = session.Wait()
	output := outputBuffer.String()

	if err != nil {
		return output, fmt.Errorf("command failed: %w", err)
	}

	return output, nil
}

// formatBytes converts bytes to human readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// cleanupBackupFile removes a backup file from the specified server
func cleanupBackupFile(client *ssh.Client, filePath, serverName string) error {
	rmCmd := fmt.Sprintf("rm -f '%s'", filePath)
	output, err := executeSSHCommand(client, rmCmd)
	if err != nil {
		return fmt.Errorf("failed to cleanup backup file on %s: %w, output: %s", serverName, err, output)
	}
	fmt.Printf("Cleaned up backup file on %s: %s\n", serverName, filePath)
	return nil
}

// copyFileDirectly copies a file directly from source to target server using SCP (server-to-server)
func copyFileDirectly(sourceClient *ssh.Client, sourcePath string, targetHost, targetPath, sshUser, sshKeyPath string) error {
	// Get file info from source
	statCmd := fmt.Sprintf("stat -c '%%s' '%s'", sourcePath)
	sizeOutput, err := executeSSHCommand(sourceClient, statCmd)
	if err != nil {
		return fmt.Errorf("failed to get source file size: %w", err)
	}
	fileSizeStr := strings.TrimSpace(sizeOutput)

	// Parse file size to int64 for human-readable formatting
	fileSizeBytes, err := strconv.ParseInt(fileSizeStr, 10, 64)
	if err != nil {
		// Fallback to raw string if parsing fails
		fmt.Printf("Transferring file (%s bytes) directly from source to target...\n", fileSizeStr)
	} else {
		// Debug: show both raw and formatted
		fmt.Printf("Transferring file (%s bytes = %s) directly from source to target...\n", fileSizeStr, formatBytes(fileSizeBytes))
	}

	// Build SCP command to run on source server that copies directly to target
	scpCmd := fmt.Sprintf("scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i '%s' '%s' '%s@%s:%s'",
		sshKeyPath,
		sourcePath,
		sshUser,
		targetHost,
		targetPath)

	// Execute the SCP command on the source server with streaming output
	output, err := executeSSHCommandWithStreaming(sourceClient, scpCmd)
	if err != nil {
		return fmt.Errorf("direct file transfer failed: %w, output: %s", err, output)
	}

	if output != "" {
		//debugging: fmt.Printf("Transfer output: %s\n", output)
	}
	return nil
}

var (
	// Command line flags
	configFile  = flag.String("config", "", "Path to JSON configuration file")
	sourceName  = flag.String("source", "", "Source environment name from config")
	targetName  = flag.String("target", "", "Target environment name from config")
	vmID        = flag.Int("vmid", 0, "VM ID to migrate")
	testFlag    = flag.Bool("test", false, "Test connectivity to source and target")
	listFlag    = flag.Bool("list", false, "List all configured hosts with their roles")
	versionFlag = flag.Bool("version", false, "Show version information")
)

// getVMConfig connects to Proxmox and fetches the configuration for a specific VM.
func getVMConfig(ctx context.Context, host, tokenID, tokenSecret string, vmID int, insecure bool) (map[string]interface{}, string, error) {
	// Validate token credentials
	if tokenID == "" || tokenSecret == "" {
		return nil, "", fmt.Errorf("API token ID and secret are required")
	}

	// Make sure host doesn't end with a slash
	host = strings.TrimSuffix(host, "/")

	// Create custom HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure, // Skip certificate verification if requested
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	// First get the list of nodes
	nodesURL := fmt.Sprintf("%s/api2/json/nodes", host)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "GET", nodesURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add the authentication header
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	// Make the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get nodes list: %w", err)
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read nodes response: %w", err)
	}

	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var nodesResponse struct {
		Data []struct {
			Node   string `json:"node"`
			Name   string `json:"name"`
			Status string `json:"status"`
			ID     string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &nodesResponse); err != nil {
		return nil, "", fmt.Errorf("failed to parse nodes response: %w", err)
	}

	// Get the list of nodes
	nodes, err := getNodes(ctx, host, tokenID, tokenSecret, insecure)
	if err != nil {
		return nil, "", fmt.Errorf("error listing nodes: %w", err)
	}

	// We need to find which node the VM is on
	var vmConfig map[string]interface{}
	var vmFound bool
	var foundNodeName string

	// Try each node until we find the VM
	for _, nodeName := range nodes {

		// Try to get the VM's config directly using the API
		// First try QEMU VM path
		configURL := fmt.Sprintf("%s/api2/json/nodes/%s/qemu/%d/config", host, nodeName, vmID)
		fmt.Printf("Checking for VM on node '%s'... ", nodeName)

		// Create the request
		req, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create request for node '%s': %v\n", nodeName, err)
			continue
		}

		// Add the authentication header
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

		// Make the request
		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not access node '%s': %v\n", nodeName, err)
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			fmt.Println("404 fuck off, next!")
			continue
		}

		if resp.StatusCode == http.StatusInternalServerError {
			fmt.Println("500 fuck off, next!")
			continue
		}

		// Check if we found the VM
		if resp.StatusCode == http.StatusOK {
			// Read and parse the response
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not read response from node '%s': %v\n", nodeName, err)
				continue
			}

			// Parse the JSON response
			var configResponse struct {
				Data map[string]interface{} `json:"data"`
			}
			if err := json.Unmarshal(body, &configResponse); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not parse response from node '%s': %v\n", nodeName, err)
				continue
			}

			// Found the VM!
			vmConfig = configResponse.Data
			vmFound = true
			foundNodeName = nodeName
			fmt.Println("Found the fucker!")
			break
		}
		resp.Body.Close()

		// If that didn't work, try LXC container path
		configURL = fmt.Sprintf("%s/api2/json/nodes/%s/lxc/%d/config", host, nodeName, vmID)

		// Create the request
		req, err = http.NewRequestWithContext(ctx, "GET", configURL, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not create request for node '%s': %v\n", nodeName, err)
			continue
		}

		// Add the authentication header
		req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

		// Make the request
		resp, err = httpClient.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not access node '%s': %v\n", nodeName, err)
			continue
		}

		// Check if we found the container
		if resp.StatusCode == http.StatusOK {
			// Read and parse the response
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not read response from node '%s': %v\n", nodeName, err)
				continue
			}

			// Parse the JSON response
			var configResponse struct {
				Data map[string]interface{} `json:"data"`
			}
			if err := json.Unmarshal(body, &configResponse); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not parse response from node '%s': %v\n", nodeName, err)
				continue
			}

			// Found the container!
			vmConfig = configResponse.Data
			vmFound = true
			foundNodeName = nodeName
			fmt.Println("Found the fucker!")
			break
		}
		resp.Body.Close()
	}

	if !vmFound || vmConfig == nil {
		return nil, "", fmt.Errorf("could not find VM or container with ID %d on any node in %s", vmID, host)
	}

	return vmConfig, foundNodeName, nil
}

// exportVM creates an export of a VM on the source Proxmox server using vzdump
func exportVM(ctx context.Context, host, tokenID, tokenSecret string, insecure bool, nodeName string, vmID int, _ /* vmType */, storage string) (string, error) {
	// Make sure host doesn't end with a slash
	host = strings.TrimSuffix(host, "/")

	// The vzdump API path is the correct one to use for exporting VMs
	vzdumpURL := fmt.Sprintf("%s/api2/json/nodes/%s/vzdump", host, nodeName)

	// Prepare the vzdump parameters
	vzdumpParams := map[string]string{
		"storage":  storage, // Use the specified storage
		"vmid":     strconv.Itoa(vmID),
		"compress": "zstd", // Use zstd compression for better performance
		"mode":     "snapshot",
		"remove":   "0", // Don't remove existing backups
	}

	// Create form data for the request
	formData := url.Values{}
	for key, value := range vzdumpParams {
		formData.Add(key, value)
	}

	// Create custom HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}

	// Create the POST request
	req, err := http.NewRequestWithContext(ctx, "POST", vzdumpURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create export request: %w", err)
	}

	// Add the authentication header
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	// Set content type for form data
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Make the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error: Failed to initiate VM export: %w", err)
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error: Failed to read export response: %w", err)
	}

	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Error: Unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var taskResponse struct {
		Data string `json:"data"` // This will contain the task ID (UPID)
	}
	if err := json.Unmarshal(body, &taskResponse); err != nil {
		return "", fmt.Errorf("Error: Failed to parse export response: %w", err)
	}

	if taskResponse.Data == "" {
		return "", fmt.Errorf("Error: Export task initiated but no task ID returned")
	}

	// Return the task ID (UPID)
	return taskResponse.Data, nil
}

// waitForTask waits for a Proxmox task to complete and shows progress
func waitForTask(ctx context.Context, host, tokenID, tokenSecret string, insecure bool, taskID string, timeout time.Duration) error {

	// Make sure host doesn't end with a slash
	host = strings.TrimSuffix(host, "/")

	// Extract node name from the task ID (UPIDs have the format UPID:node:...)
	parts := strings.Split(taskID, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid task ID format: %s", taskID)
	}
	nodeName := parts[1]

	// Create a context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Create custom HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	// Track last reported progress to avoid duplicate updates
	lastProgress := -1
	lastStatusUpdate := time.Now()

	// Poll the task status until it completes or times out
	for {
		select {
		case <-ctxWithTimeout.Done():
			return fmt.Errorf("task wait timed out after %v", timeout)
		default:
			// Check task status
			statusURL := fmt.Sprintf("%s/api2/json/nodes/%s/tasks/%s/status", host, nodeName, taskID)

			// Create the request
			req, err := http.NewRequestWithContext(ctx, "GET", statusURL, nil)
			if err != nil {
				return fmt.Errorf("failed to create status request: %w", err)
			}

			// Add the authentication header
			req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

			// Make the request
			resp, err := httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("failed to get task status: %w", err)
			}

			// Read and parse the response
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to read status response: %w", err)
			}

			// Check if the response is successful
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
			}

			// Parse the JSON response
			var taskStatus struct {
				Data struct {
					Status     string  `json:"status"`
					ExitStatus string  `json:"exitstatus"`
					PID        int     `json:"pid"`
					StartTime  float64 `json:"starttime"`
					Uptime     float64 `json:"uptime"`
					Type       string  `json:"type"`
					ID         string  `json:"id"`
					User       string  `json:"user"`
					Progress   float64 `json:"progress,omitempty"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &taskStatus); err != nil {
				return fmt.Errorf("failed to parse status response: %w", err)
			}

			// Check if task is done
			if taskStatus.Data.Status == "stopped" {
				if taskStatus.Data.ExitStatus == "OK" {
					fmt.Println("\nTask completed successfully")
					return nil
				} else {
					return fmt.Errorf("task failed with exit status: %s", taskStatus.Data.ExitStatus)
				}
			}

			// Show progress if available and changed
			currentProgress := int(taskStatus.Data.Progress * 100)
			if currentProgress != lastProgress || time.Since(lastStatusUpdate) > 10*time.Second {
				lastProgress = currentProgress
				lastStatusUpdate = time.Now()

				// Get log entries for more detailed information
				logURL := fmt.Sprintf("%s/api2/json/nodes/%s/tasks/%s/log?limit=1000", host, nodeName, taskID)

				// Create the request
				logReq, err := http.NewRequestWithContext(ctx, "GET", logURL, nil)
				if err != nil {
					// Just continue without log entry if we can't create the request
					latestLogEntry := ""
					printProgress(currentProgress, latestLogEntry)
					continue
				}

				// Add the authentication header
				logReq.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

				// Make the request
				logResp, err := httpClient.Do(logReq)

				// Try to get the latest log entry
				latestLogEntry := ""
				if err == nil && logResp.StatusCode == http.StatusOK {
					logBody, err := io.ReadAll(logResp.Body)
					logResp.Body.Close()

					if err == nil {
						var taskLog struct {
							Data []struct {
								N     int    `json:"n"`
								T     string `json:"t"`
								Level string `json:"level"`
							} `json:"data"`
						}

						if err := json.Unmarshal(logBody, &taskLog); err == nil && len(taskLog.Data) > 0 {
							// Sort log entries by their sequence number to get the most recent ones first
							sort.Slice(taskLog.Data, func(i, j int) bool {
								return taskLog.Data[i].N > taskLog.Data[j].N
							})

							// Get the most recent progress entry
							for _, entry := range taskLog.Data {
								if strings.Contains(entry.T, "%") && strings.Contains(entry.T, "MiB") {
									latestLogEntry = entry.T
									break
								}
							}

							// If no progress entry found, use the most recent entry
							if latestLogEntry == "" && len(taskLog.Data) > 0 {
								latestLogEntry = taskLog.Data[0].T
							}
						}
					}
				} else if logResp != nil {
					logResp.Body.Close()
				}

				// Print progress
				printProgress(currentProgress, latestLogEntry)
			}

			// Wait before checking again - shorter interval for better progress updates
			time.Sleep(1 * time.Second)
		}
	}
}

// printProgress prints a progress bar with the current progress percentage and log entry
func printProgress(progress int, logEntry string) {
	// Clear the entire line using ANSI escape sequence
	fmt.Print("\r\033[K")

	if progress > 0 {
		// Print progress bar and percentage
		fmt.Printf("Progress: [%s%s] %d%% ",
			strings.Repeat("=", progress/2),
			strings.Repeat(" ", 50-progress/2),
			progress)

		// Print log entry on a new line if it contains detailed progress info
		if strings.Contains(logEntry, "%") || strings.Contains(logEntry, "MiB") {
			fmt.Printf("\n%s", logEntry)
		} else {
			fmt.Print(logEntry)
		}
	} else {
		// If no progress percentage available, just show status
		fmt.Printf("Task running... %s", logEntry)
	}
}

// getFilePathOnDisk gets the actual file path on the Proxmox server's filesystem
func getFilePathOnDisk(_ /* ctx */ context.Context, host, _ /* tokenID */, _ /* tokenSecret */ string, _ /* insecure */ bool, _ /* nodeName */, volid string, sshUser, sshKeyPath string) (string, error) {
	// The volid is something like 'local:backup/vzdump-qemu-100-date.vma.zst'
	// We need to find the actual most recent backup file for this VM

	// Extract the storage name and relative path from volid
	parts := strings.SplitN(volid, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid volume ID format: %s", volid)
	}
	storageName := parts[0]
	relPath := parts[1]

	// Extract the VM ID from the filename pattern
	// The pattern is typically backup/vzdump-qemu-VMID-date.vma.zst
	filename := filepath.Base(relPath)
	parts = strings.Split(filename, "-")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid backup filename format: %s", filename)
	}

	// Extract vmType and vmID
	vmType := parts[1] // e.g., "qemu"
	vmID := parts[2]   // e.g., "100"

	// Determine the source hostname/IP
	sourceHostname := strings.TrimPrefix(host, "https://")
	sourceHostname = strings.TrimPrefix(sourceHostname, "http://")
	sourceHostname = strings.Split(sourceHostname, ":")[0] // Remove port if present

	// Create SSH client
	client, err := createSSHClient(sourceHostname, sshUser, sshKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to create SSH client: %w", err)
	}
	defer client.Close()

	// Use SSH to find the most recent backup file for this VM
	backupPattern := fmt.Sprintf("vzdump-%s-%s-*.vma.*", vmType, vmID)
	// Construct the storage path - for most storages it's mounted under /mnt/pve/STORAGE_NAME
	var storagePath string
	if storageName == "local" {
		storagePath = "/var/lib/vz/dump"
	} else {
		storagePath = fmt.Sprintf("/mnt/pve/%s/dump", storageName)
	}
	cmd := fmt.Sprintf("ls -t %s/%s | head -1", storagePath, backupPattern)

	fmt.Print("Finding most recent backup...")

	// Execute the command over SSH
	output, err := executeSSHCommand(client, cmd)
	if err != nil {
		return "", fmt.Errorf("failed to find backup file: %w, output: %s", err, output)
	}

	// Get the filename from the output
	actualFilename := strings.TrimSpace(output)
	if actualFilename == "" {
		return "", fmt.Errorf("no backup files found matching pattern %s", backupPattern)
	}

	// Construct the full path
	absPath := filepath.Join(storagePath, actualFilename)

	fmt.Println("OK")

	return absPath, nil
}

// transferFileToTarget transfers the VM backup file from source to target server using SSH
// Returns targetFilePath, sourceFilePath, error
func transferFileToTarget(_ /* ctx */ context.Context, sourceHost, _ /* sourceTokenID */, _ /* sourceTokenSecret */ string, _ /* sourceInsecure */ bool, _ /* sourceNode */ string, sourceVMID int, targetHost, _ /* targetNode */, sshUser, sshKeyPath string) (string, string, error) {

	// Make sure host doesn't end with a slash
	sourceHost = strings.TrimSuffix(sourceHost, "/")

	// Determine the source and target hostnames/IPs
	sourceHostname := strings.TrimPrefix(sourceHost, "https://")
	sourceHostname = strings.TrimPrefix(sourceHostname, "http://")
	sourceHostname = strings.Split(sourceHostname, ":")[0] // Remove port if present

	targetHostname := strings.TrimPrefix(targetHost, "https://")
	targetHostname = strings.TrimPrefix(targetHostname, "http://")
	targetHostname = strings.Split(targetHostname, ":")[0] // Remove port if present

	// Create SSH client for source server only (target connection handled by SCP)
	fmt.Print("Connecting to source server... ")
	sourceClient, err := createSSHClient(sourceHostname, sshUser, sshKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to connect to source server: %w", err)
	}
	defer sourceClient.Close()

	fmt.Println("OK")

	// First, find the most recent backup file on the source server
	fmt.Print("Finding the most recent backup file on the source server...")

	// Default to QEMU VM type
	vmType := "qemu"

	// Use SSH to find the most recent backup file for this VM
	backupPattern := fmt.Sprintf("vzdump-%s-%d-*.vma.*", vmType, sourceVMID)
	findCmd := fmt.Sprintf("ls -t /var/lib/vz/dump/%s | head -1", backupPattern)

	// Execute the command to find the backup file
	output, err := executeSSHCommand(sourceClient, findCmd)
	if err != nil {
		return "", "", fmt.Errorf("failed to find backup file: %w, output: %s", err, output)
	}

	// Get the filename from the output
	backupFilename := strings.TrimSpace(output)
	if backupFilename == "" {
		return "", "", fmt.Errorf("no backup files found matching pattern %s", backupPattern)
	}

	// Check if the output already contains the full path
	var sourceFilePath string
	if strings.HasPrefix(backupFilename, "/") {
		// It's already a full path
		sourceFilePath = backupFilename
		// Extract just the filename part for the target path
		backupFilename = filepath.Base(backupFilename)
	} else {
		// It's just a filename, so add the path
		sourceFilePath = filepath.Join("/var/lib/vz/dump", backupFilename)
	}

	fmt.Println("OK")

	// Construct the target path (in /var/lib/vz/dump/ which is standard for Proxmox)
	targetFilePath := fmt.Sprintf("/var/lib/vz/dump/%s", backupFilename)

	fmt.Println("Starting file transfer...")

	// Transfer the file directly from source to target server (no local routing)
	err = copyFileDirectly(sourceClient, sourceFilePath, targetHostname, targetFilePath, sshUser, sshKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("file transfer failed: %w", err)
	}

	return targetFilePath, sourceFilePath, nil
}

// getNodes gets a list of node names from the Proxmox API using direct HTTP requests
func getNodes(ctx context.Context, host, tokenID, tokenSecret string, insecure bool) ([]string, error) {
	// Make sure host doesn't end with a slash
	host = strings.TrimSuffix(host, "/")

	// Create custom HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	// Build the URL for the nodes endpoint
	nodesURL := fmt.Sprintf("%s/api2/json/nodes", host)

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "GET", nodesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create nodes request: %w", err)
	}

	// Add the authentication header
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	// Make the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get nodes: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read nodes response: %w", err)
	}

	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var nodesResponse struct {
		Data []struct {
			Node string `json:"node"`
			ID   string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &nodesResponse); err != nil {
		return nil, fmt.Errorf("failed to parse nodes response: %w", err)
	}

	// Extract the node names
	nodeNames := make([]string, 0, len(nodesResponse.Data))
	for _, node := range nodesResponse.Data {
		// Use ID if available, otherwise use Node
		nodeName := node.ID
		if nodeName == "" {
			// Fallback to node.Node if ID is empty
			nodeName = node.Node
		}

		// Remove 'node/' prefix if present
		nodeName = strings.TrimPrefix(nodeName, "node/")

		nodeNames = append(nodeNames, nodeName)
	}

	return nodeNames, nil
}

// loadConfig loads configuration from a JSON file
func loadConfig(configPath string) (*Config, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = json.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &config, nil
}

// restoreBackup restores a VM from a backup file on the target server using SSH and `qmrestore` command
func restoreBackup(_ /* ctx */ context.Context, host, _ /* nodeName */ string, vmID int, storage, archivePath, sshUser, sshKeyPath string) (string, error) {
	// Make sure host doesn't end with a slash
	host = strings.TrimSuffix(host, "/")

	// Determine the target hostname/IP
	targetHostname := strings.TrimPrefix(host, "https://")
	targetHostname = strings.TrimPrefix(targetHostname, "http://")
	targetHostname = strings.Split(targetHostname, ":")[0] // Remove port if present

	// Create SSH client for target server
	client, err := createSSHClient(targetHostname, sshUser, sshKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to connect to target server: %w", err)
	}
	defer client.Close()

	// First, find the next available VMID on the target server
	fmt.Print("Finding next available VMID on target server...")

	// Command to get the next available VMID
	// We'll use 'pvesh get /cluster/nextid' which returns the next available ID
	findVMIDCmd := "pvesh get /cluster/nextid"

	// Execute the command to find the next VMID
	output, err := executeSSHCommand(client, findVMIDCmd)
	if err != nil {
		// If we can't get the next ID, use the source VMID as fallback
		fmt.Printf("Warning: Failed to get next available VMID: %v, using source VMID %d\n", err, vmID)
	} else {
		// Try to parse the output as an integer
		nextVMID := strings.TrimSpace(output)
		parsedVMID, parseErr := strconv.Atoi(nextVMID)
		if parseErr == nil && parsedVMID > 0 {
			// Successfully got the next VMID
			vmID = parsedVMID
			fmt.Printf("OK - VMID %d\n", vmID)
		} else {
			fmt.Printf("Warning: Could not parse next VMID '%s', using source VMID %d\n", nextVMID, vmID)
		}
	}

	// Prepare the qmrestore command to run on the target server
	qmrestoreCmd := fmt.Sprintf("qmrestore %s %d --storage %s",
		archivePath,
		vmID,
		storage)

	fmt.Println("Initiating VM restore...")

	// Execute the qmrestore command over SSH with streaming output
	output, err = executeSSHCommandWithStreaming(client, qmrestoreCmd)
	if err != nil {
		return "", fmt.Errorf("VM restore failed: %w, output: %s", err, output)
	}

	return fmt.Sprintf("VM %d restored successfully", vmID), nil
}

// checkStorageExists checks if a storage with the given name exists on the server
func checkStorageExists(ctx context.Context, host, tokenID, tokenSecret string, insecure bool, storageName string) (bool, error) {
	// Make sure host doesn't end with a slash
	host = strings.TrimSuffix(host, "/")

	// Build the URL for the storage endpoint
	storageURL := fmt.Sprintf("%s/api2/json/storage", host)

	// Create custom HTTP client with TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "GET", storageURL, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create storage request: %w", err)
	}

	// Add the authentication header
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", tokenID, tokenSecret))

	// Make the request
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to get storage list: %w", err)
	}
	defer resp.Body.Close()

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read storage response: %w", err)
	}

	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse the JSON response
	var storageResponse struct {
		Data []struct {
			Storage string `json:"storage"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &storageResponse); err != nil {
		return false, fmt.Errorf("failed to parse storage response: %w", err)
	}

	// Check if the storage exists
	for _, storage := range storageResponse.Data {
		if storage.Storage == storageName {
			return true, nil
		}
	}

	return false, nil
}

// testAPIConnectivity tests API connectivity to a Proxmox server
func testAPIConnectivity(config ServerConfig, serverName string) error {
	fmt.Printf("Testing API connectivity to %s (%s)...\n", serverName, config.Host)

	// Create HTTP client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// Test API connection by getting version info
	req, err := http.NewRequest("GET", config.Host+"api2/json/version", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", config.TokenID, config.TokenSecret))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response to get version info
	var result struct {
		Data struct {
			Version string `json:"version"`
			Release string `json:"release"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	fmt.Printf("  ✓ API connection successful - Proxmox VE %s-%s\n", result.Data.Version, result.Data.Release)
	return nil
}

// testSSHConnectivity tests SSH connectivity to a server
func testSSHConnectivity(host, sshUser, keyPath, serverName string) error {
	fmt.Printf("Testing SSH connectivity to %s (%s)...\n", serverName, host)

	// Extract hostname from URL if needed
	hostname := strings.TrimPrefix(host, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.TrimSuffix(hostname, "/")
	hostname = strings.Split(hostname, ":")[0] // Remove port if present

	// Create SSH client
	client, err := createSSHClient(hostname, sshUser, keyPath)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer client.Close()

	// Test SSH by running a simple command
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	// Run a simple command to test connectivity
	output, err := session.CombinedOutput("hostname && pveversion --verbose | head -1")
	if err != nil {
		return fmt.Errorf("failed to execute test command: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	hostname_result := "unknown"
	version_result := "unknown"

	if len(lines) >= 1 {
		hostname_result = strings.TrimSpace(lines[0])
	}
	if len(lines) >= 2 {
		version_result = strings.TrimSpace(lines[1])
	}

	fmt.Printf("  ✓ SSH connection successful - %s (%s)\n", hostname_result, version_result)
	return nil
}

// listConfiguredHosts lists all configured hosts with their roles
func listConfiguredHosts(config *Config) {
	fmt.Println("Configured Proxmox Hosts:")
	fmt.Println()

	// Create a map to track all unique hosts and their roles
	hostRoles := make(map[string][]string)
	hostConfigs := make(map[string]ServerConfig)

	// Add sources
	for name, sourceConfig := range config.Sources {
		hostRoles[name] = append(hostRoles[name], "source")
		hostConfigs[name] = sourceConfig
	}

	// Add targets
	for name, targetConfig := range config.Targets {
		if _, exists := hostRoles[name]; exists {
			// Host already exists as source, add target role
			hostRoles[name] = append(hostRoles[name], "target")
		} else {
			// New host, add as target only
			hostRoles[name] = []string{"target"}
			hostConfigs[name] = targetConfig.ServerConfig
		}
	}

	if len(hostRoles) == 0 {
		fmt.Println("No hosts configured.")
		return
	}

	// Sort host names for consistent output
	hostNames := make([]string, 0, len(hostRoles))
	for name := range hostRoles {
		hostNames = append(hostNames, name)
	}
	sort.Strings(hostNames)

	// Display hosts with role indicators
	for _, name := range hostNames {
		roles := hostRoles[name]
		config := hostConfigs[name]

		// Create role indicator
		var roleIndicator string
		if len(roles) == 2 {
			// Both source and target
			roleIndicator = "[source,target]"
		} else if roles[0] == "source" {
			roleIndicator = "[source]      "
		} else {
			roleIndicator = "[target]      "
		}

		// Extract hostname from URL for display
		hostURL := strings.TrimPrefix(config.Host, "https://")
		hostURL = strings.TrimPrefix(hostURL, "http://")
		hostURL = strings.TrimSuffix(hostURL, "/")

		fmt.Printf("  %-20s %s %s\n", name, roleIndicator, hostURL)
	}

	fmt.Println()
	fmt.Printf("Total hosts: %d\n", len(hostNames))

	// Show summary by role
	sourceCount := 0
	targetCount := 0
	bothCount := 0

	for _, roles := range hostRoles {
		if len(roles) == 2 {
			bothCount++
		} else if roles[0] == "source" {
			sourceCount++
		} else {
			targetCount++
		}
	}

	fmt.Printf("Roles: %d source-only, %d target-only, %d both\n", sourceCount, targetCount, bothCount)
}

// runConnectivityTests runs connectivity tests for source and target
func runConnectivityTests(config *Config, sourceName, targetName string) {
	fmt.Println("Running connectivity tests...\n")

	// Get source and target configurations
	sourceConfig, exists := config.Sources[sourceName]
	if !exists {
		fmt.Fprintf(os.Stderr, "Source '%s' not found in configuration\n", sourceName)
		os.Exit(1)
	}

	targetConfig, exists := config.Targets[targetName]
	if !exists {
		fmt.Fprintf(os.Stderr, "Target '%s' not found in configuration\n", targetName)
		os.Exit(1)
	}

	var testsPassed, testsTotal int

	// Test source connectivity
	fmt.Println("=== Testing Source Server ===")
	testsTotal += 2

	// Test source API
	if err := testAPIConnectivity(sourceConfig, sourceName); err != nil {
		fmt.Printf("  ✗ API test failed: %v\n", err)
	} else {
		testsPassed++
	}

	// Test source SSH
	if err := testSSHConnectivity(sourceConfig.Host, config.SSH.User, config.SSH.KeyPath, sourceName); err != nil {
		fmt.Printf("  ✗ SSH test failed: %v\n", err)
	} else {
		testsPassed++
	}

	fmt.Println()

	// Test target connectivity
	fmt.Println("=== Testing Target Server ===")
	testsTotal += 2

	// Test target API
	if err := testAPIConnectivity(targetConfig.ServerConfig, targetName); err != nil {
		fmt.Printf("  ✗ API test failed: %v\n", err)
	} else {
		testsPassed++
	}

	// Test target SSH
	if err := testSSHConnectivity(targetConfig.Host, config.SSH.User, config.SSH.KeyPath, targetName); err != nil {
		fmt.Printf("  ✗ SSH test failed: %v\n", err)
	} else {
		testsPassed++
	}

	fmt.Println()

	// Summary
	fmt.Printf("=== Test Summary ===\n")
	fmt.Printf("Tests passed: %d/%d\n", testsPassed, testsTotal)

	if testsPassed == testsTotal {
		fmt.Println("✓ All connectivity tests passed! Ready for migration.")
		os.Exit(0)
	} else {
		fmt.Println("✗ Some tests failed. Please fix connectivity issues before migration.")
		os.Exit(1)
	}
}

func main() {
	flag.Parse() // Parse the command-line flags

	// Handle version flag
	if *versionFlag {
		fmt.Printf("Proxmigrate %s\n", Version)
		fmt.Printf("Built: %s\n", BuildTime)
		os.Exit(0)
	}

	// Handle list flag - only requires config file
	if *listFlag {
		// Load configuration from file
		configPath := *configFile
		if configPath == "" {
			// Get the directory of the executable
			execPath, err := os.Executable()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not determine executable path: %v\n", err)
			}
			execDir := filepath.Dir(execPath)

			// Try default locations (executable dir first, then current dir, then system locations)
			defaultPaths := []string{
				filepath.Join(execDir, "config.json"), // config.json in executable directory
				"./config.json",                       // config.json in current directory
				"./proxmigrate.json",                  // legacy name in current directory
				"~/.proxmigrate/config.json",          // user config directory
				"/etc/proxmigrate/config.json",        // system config directory
			}
			for _, path := range defaultPaths {
				if _, err := os.Stat(path); err == nil {
					configPath = path
					break
				}
			}
		}

		if configPath == "" {
			fmt.Fprintln(os.Stderr, "Error: No configuration file found.")
			fmt.Fprintln(os.Stderr, "Please create a config.json file or specify --config flag.")
			os.Exit(1)
		}

		config, err := loadConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}

		// List configured hosts and exit
		listConfiguredHosts(config)
		os.Exit(0)
	}

	fmt.Println("Proxmox VM Migrator Starting...")

	// Create a background context for all operations
	ctx := context.Background()

	// Load configuration from file
	configPath := *configFile
	if configPath == "" {
		// Get the directory of the executable
		execPath, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not determine executable path: %v\n", err)
		}
		execDir := filepath.Dir(execPath)

		// Try default locations (executable dir first, then current dir, then system locations)
		defaultPaths := []string{
			filepath.Join(execDir, "config.json"), // config.json in executable directory
			"./config.json",                       // config.json in current directory
			"./proxmigrate.json",                  // legacy name in current directory
			"~/.proxmigrate/config.json",          // user config directory
			"/etc/proxmigrate/config.json",        // system config directory
		}
		for _, path := range defaultPaths {
			// Expand ~ to home directory if present
			if strings.HasPrefix(path, "~/") {
				homeDir, err := os.UserHomeDir()
				if err == nil {
					path = filepath.Join(homeDir, path[2:])
				}
			}
			if _, err := os.Stat(path); err == nil {
				configPath = path
				break
			}
		}
	}

	if configPath == "" {
		fmt.Fprintln(os.Stderr, "Error: No configuration file found. Please specify --config or create config.json")
		fmt.Fprintln(os.Stderr, "Searched locations:")
		fmt.Fprintln(os.Stderr, "  - config.json (in executable directory)")
		fmt.Fprintln(os.Stderr, "  - ./config.json (in current directory)")
		fmt.Fprintln(os.Stderr, "  - ./proxmigrate.json (legacy name)")
		fmt.Fprintln(os.Stderr, "  - ~/.proxmigrate/config.json")
		fmt.Fprintln(os.Stderr, "  - /etc/proxmigrate/config.json")
		os.Exit(1)
	}

	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
		os.Exit(1)
	}

	// Handle test flag - only requires source and target, not vmid
	if *testFlag {
		if *sourceName == "" || *targetName == "" {
			fmt.Fprintln(os.Stderr, "Error: --test requires --source and --target flags.")
			fmt.Fprintln(os.Stderr, "Usage: proxmigrate --test --source=prod --target=backup")
			os.Exit(1)
		}
		// Run connectivity tests and exit
		runConnectivityTests(config, *sourceName, *targetName)
		return // This won't be reached due to os.Exit in runConnectivityTests
	}

	// Validate required flags for migration
	if *sourceName == "" || *targetName == "" || *vmID == 0 {
		fmt.Fprintln(os.Stderr, "Error: Missing required flags. --source, --target, and --vmid are mandatory.")
		fmt.Fprintln(os.Stderr, "Usage: proxmigrate --source=prod --target=backup --vmid=109")
		fmt.Fprintln(os.Stderr, "       proxmigrate --test --source=prod --target=backup")
		os.Exit(1)
	}

	// Get source configuration
	sourceConfig, exists := config.Sources[*sourceName]
	if !exists {
		fmt.Fprintf(os.Stderr, "Error: Source '%s' not found in configuration\n", *sourceName)
		fmt.Fprintln(os.Stderr, "Available sources:")
		for name := range config.Sources {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		os.Exit(1)
	}

	// Get target configuration
	targetConfig, exists := config.Targets[*targetName]
	if !exists {
		fmt.Fprintf(os.Stderr, "Error: Target '%s' not found in configuration\n", *targetName)
		fmt.Fprintln(os.Stderr, "Available targets:")
		for name := range config.Targets {
			fmt.Fprintf(os.Stderr, "  - %s\n", name)
		}
		os.Exit(1)
	}

	// Check if backup storage exists on source server
	fmt.Printf("Checking if '%s' storage exists on source server... ", sourceConfig.BackupStorage)
	sourceStorageExists, err := checkStorageExists(ctx, sourceConfig.Host, sourceConfig.TokenID, sourceConfig.TokenSecret, sourceConfig.Insecure, sourceConfig.BackupStorage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking source storage: %v\n", err)
		os.Exit(1)
	}
	if !sourceStorageExists {
		fmt.Fprintf(os.Stderr, "Error: Storage '%s' does not exist on source server. Please create it first.\n", sourceConfig.BackupStorage)
		os.Exit(1)
	}
	fmt.Println("OK")

	// Check if backup storage exists on target server
	fmt.Printf("Checking if '%s' storage exists on target server... ", targetConfig.BackupStorage)
	targetStorageExists, err := checkStorageExists(ctx, targetConfig.Host, targetConfig.TokenID, targetConfig.TokenSecret, targetConfig.Insecure, targetConfig.BackupStorage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking target storage: %v\n", err)
		os.Exit(1)
	}
	if !targetStorageExists {
		fmt.Fprintf(os.Stderr, "Error: Storage '%s' does not exist on target server. Please create it first.\n", targetConfig.BackupStorage)
		os.Exit(1)
	}
	fmt.Println("OK")

	fmt.Println("Source Host:", sourceConfig.Host)
	fmt.Println("Source VM ID:", *vmID)
	fmt.Println("Target Host:", targetConfig.Host)
	fmt.Println("Target Node:", targetConfig.Node)
	fmt.Println("Target Storage:", targetConfig.Storage)

	// Step 1: Connect to source Proxmox and get VM config
	fmt.Print("\nStep 1: Fetching VM configuration from source...\n")
	vmConfig, sourceNodeName, err := getVMConfig(ctx, sourceConfig.Host, sourceConfig.TokenID, sourceConfig.TokenSecret, *vmID, sourceConfig.Insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching source VM config: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Export the VM on the source server
	fmt.Println("\nStep 2: Exporting VM from source server...")

	// Determine the VM type (qemu or lxc) based on the config
	vmType := "qemu" // Default to QEMU VM
	if _, hasLxcFeature := vmConfig["features"]; hasLxcFeature {
		vmType = "lxc"
	}

	if sourceNodeName == "" {
		fmt.Fprintf(os.Stderr, "Error: Could not determine which node VM %d is on\n", *vmID)
		os.Exit(1)
	}

	// Initiate the export
	taskID, err := exportVM(ctx, sourceConfig.Host, sourceConfig.TokenID, sourceConfig.TokenSecret, sourceConfig.Insecure, sourceNodeName, *vmID, vmType, sourceConfig.BackupStorage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting VM export: %v\n", err)
		os.Exit(1)
	}

	// Wait for the export task to complete
	err = waitForTask(ctx, sourceConfig.Host, sourceConfig.TokenID, sourceConfig.TokenSecret, sourceConfig.Insecure, taskID, 120*time.Minute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during VM export: %v\n", err)
		os.Exit(1)
	}

	// Step 3: Transfer the exported file to the target server
	fmt.Println("\nStep 3: Transferring VM backup to target server...")

	// Transfer the exported file to the target server
	targetFilePath, sourceFilePath, err := transferFileToTarget(ctx, sourceConfig.Host, sourceConfig.TokenID, sourceConfig.TokenSecret, sourceConfig.Insecure, sourceNodeName, *vmID, targetConfig.Host, targetConfig.Node, config.SSH.User, config.SSH.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error transferring file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("VM backup successfully transferred to target")

	// Step 4: Import the VM on the target server
	fmt.Println("\nStep 4: Importing VM on target server...")

	// Import the VM on the target node using direct HTTP request
	var importTaskID string
	importTaskID, err = restoreBackup(ctx, targetConfig.Host, targetConfig.Node, *vmID, targetConfig.Storage, targetFilePath, config.SSH.User, config.SSH.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initiating VM import: %v (%s)\n", err, importTaskID)
		os.Exit(1)
	}

	fmt.Println("VM successfully migrated")

	// Step 5: Clean up backup files
	fmt.Println("\nStep 5: Cleaning up backup files...")

	// Clean up source backup file
	// Extract hostname from URL (remove https:// and port)
	sourceHostname := strings.TrimPrefix(sourceConfig.Host, "https://")
	sourceHostname = strings.TrimPrefix(sourceHostname, "http://")
	sourceHostname = strings.TrimSuffix(sourceHostname, "/")
	sourceHostname = strings.Split(sourceHostname, ":")[0] // Remove port if present

	sourceClient, err := createSSHClient(sourceHostname, config.SSH.User, config.SSH.KeyPath)
	if err != nil {
		fmt.Printf("Warning: Could not connect to source for cleanup: %v\n", err)
	} else {
		defer sourceClient.Close()

		// Clean up the source backup file (we already know the path from transfer)
		if err := cleanupBackupFile(sourceClient, sourceFilePath, "source server"); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}

		// Also clean up the corresponding log file
		// Convert backup file path to log file path (replace extension with .log)
		logFilePath := strings.TrimSuffix(sourceFilePath, filepath.Ext(sourceFilePath))
		logFilePath = strings.TrimSuffix(logFilePath, ".vma") // Remove .vma if present
		logFilePath += ".log"

		if err := cleanupBackupFile(sourceClient, logFilePath, "source server"); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	// Clean up target backup file
	// Extract hostname from URL (remove https:// and port)
	targetHostname := strings.TrimPrefix(targetConfig.Host, "https://")
	targetHostname = strings.TrimPrefix(targetHostname, "http://")
	targetHostname = strings.TrimSuffix(targetHostname, "/")
	targetHostname = strings.Split(targetHostname, ":")[0] // Remove port if present

	targetClient, err := createSSHClient(targetHostname, config.SSH.User, config.SSH.KeyPath)
	if err != nil {
		fmt.Printf("Warning: Could not connect to target for cleanup: %v\n", err)
	} else {
		defer targetClient.Close()

		if err := cleanupBackupFile(targetClient, targetFilePath, "target server"); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}
	}

	os.Exit(0)
}
