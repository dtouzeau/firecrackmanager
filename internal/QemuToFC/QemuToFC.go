package QemuToFC

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"firecrackmanager/internal/futils"
)

// ProgressCallback is called during conversion to report progress
type ProgressCallback func(percent int, message string)

// ConvertOptions configures the QEMU/VMDK to ext4 conversion
type ConvertOptions struct {
	OutputImage string // required: path to write the ext4 (e.g., "./rootfs.ext4")
	SizeGiB     int64  // 0 = auto (from source partition, + headroom)
	Label       string // ext4 label (default "rootfs")
	TempDir     string // working dir for temp files; if empty uses a temp dir
}

// ConvertResult contains information about the converted image
type ConvertResult struct {
	InputPath    string
	InputFormat  string
	OutputImage  string
	SizeGiB      int64
	SourceSizeGB float64
}

// ConvertQemuImage converts a QEMU/VMDK/raw disk image to a Firecracker ext4 rootfs
func ConvertQemuImage(inputPath string, opt ConvertOptions, progress ProgressCallback) (*ConvertResult, error) {
	return convertWithProgress(inputPath, opt, progress)
}

func convertWithProgress(inputPath string, opt ConvertOptions, progress ProgressCallback) (*ConvertResult, error) {
	if err := requireRoot(); err != nil {
		return nil, err
	}

	reportProgress := func(pct int, msg string) {
		if progress != nil {
			progress(pct, msg)
		}
	}

	reportProgress(5, "Checking required commands")

	// Find required commands
	qemuImgCmd := futils.FindProgram("qemu-img")
	fdiskCmd := futils.FindProgram("fdisk")
	losetupCmd := futils.FindProgram("losetup")
	mountCmd := futils.FindProgram("mount")
	umountCmd := futils.FindProgram("umount")
	mkfsCmd := futils.FindProgram("mkfs.ext4")
	tarCmd := futils.FindProgram("tar")
	syncCmd := futils.FindProgram("sync")
	duCmd := futils.FindProgram("du")

	for _, cmd := range []string{qemuImgCmd, fdiskCmd, losetupCmd, mountCmd, umountCmd, mkfsCmd, tarCmd} {
		if err := ensureCmd(cmd); err != nil {
			return nil, err
		}
	}

	if strings.TrimSpace(opt.OutputImage) == "" {
		return nil, errors.New("OutputImage is required")
	}
	if opt.Label == "" {
		opt.Label = "rootfs"
	}

	// Check input file exists
	if _, err := os.Stat(inputPath); err != nil {
		return nil, fmt.Errorf("input file not found: %w", err)
	}

	reportProgress(10, "Detecting image format")

	// Detect image format using qemu-img info
	imgFormat, err := detectImageFormat(qemuImgCmd, inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to detect image format: %w", err)
	}

	reportProgress(15, fmt.Sprintf("Detected format: %s", imgFormat))

	// Prepare temp dir
	td := opt.TempDir
	if td == "" {
		td, err = os.MkdirTemp("", "qemu2fc-*")
		if err != nil {
			return nil, fmt.Errorf("tempdir: %w", err)
		}
		defer func(path string) {
			_ = os.RemoveAll(path)
		}(td)
	}

	rawPath := filepath.Join(td, "disk.raw")

	// Convert to raw if not already raw
	if imgFormat != "raw" {
		reportProgress(20, fmt.Sprintf("Converting %s to raw format...", imgFormat))
		if err := convertToRaw(qemuImgCmd, inputPath, rawPath, imgFormat); err != nil {
			return nil, fmt.Errorf("convert to raw failed: %w", err)
		}
	} else {
		// Just copy/link the raw file
		reportProgress(20, "Input is already raw format")
		rawPath = inputPath
	}

	reportProgress(40, "Detecting partitions")

	// Detect partitions
	partitions, err := detectPartitions(fdiskCmd, rawPath)
	if err != nil {
		return nil, fmt.Errorf("partition detection failed: %w", err)
	}

	if len(partitions) == 0 {
		return nil, errors.New("no partitions found in disk image")
	}

	// Find the root partition (usually the largest Linux partition)
	rootPart := findRootPartition(partitions)
	if rootPart == nil {
		return nil, errors.New("could not identify root partition")
	}

	reportProgress(45, fmt.Sprintf("Found root partition at offset %d bytes", rootPart.StartBytes))

	// Mount the source partition with offset
	srcMnt, srcLoop, err := mountLoopWithOffset(rawPath, rootPart.StartBytes, losetupCmd, mountCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to mount source partition: %w", err)
	}
	defer func() {
		_ = runCmd(syncCmd)
		_ = umountPath(srcMnt, umountCmd)
		_ = detachLoop(srcLoop, losetupCmd)
	}()

	reportProgress(50, "Calculating filesystem size")

	// Calculate used space
	usedBytes, err := calculateUsedSpace(duCmd, srcMnt)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate used space: %w", err)
	}

	// Determine output size
	sizeGiB := opt.SizeGiB
	if sizeGiB == 0 {
		const GiB = int64(1024 * 1024 * 1024)
		// Add 35% headroom, minimum 2 GiB
		sizeGiB = (usedBytes + usedBytes/3) / GiB
		if sizeGiB < 2 {
			sizeGiB = 2
		}
	}

	reportProgress(55, fmt.Sprintf("Creating %d GiB ext4 filesystem", sizeGiB))

	// Create output ext4 image
	if err := createExt4(opt.OutputImage, sizeGiB, opt.Label, mkfsCmd); err != nil {
		return nil, fmt.Errorf("failed to create ext4: %w", err)
	}

	reportProgress(60, "Mounting destination filesystem")

	// Mount the output image
	dstMnt, dstLoop, err := mountLoop(opt.OutputImage, losetupCmd, mountCmd)
	if err != nil {
		// Clean up output file on failure
		_ = os.Remove(opt.OutputImage)
		return nil, fmt.Errorf("failed to mount destination: %w", err)
	}
	defer func() {
		_ = runCmd(syncCmd)
		_ = umountPath(dstMnt, umountCmd)
		_ = detachLoop(dstLoop, losetupCmd)
	}()

	reportProgress(65, "Copying filesystem contents (this may take a while)...")

	// Copy contents using tar
	if err := copyWithTar(tarCmd, srcMnt, dstMnt); err != nil {
		return nil, fmt.Errorf("failed to copy filesystem: %w", err)
	}

	reportProgress(90, "Syncing filesystem")

	_ = runCmd(syncCmd)

	reportProgress(100, "Conversion complete")

	return &ConvertResult{
		InputPath:    inputPath,
		InputFormat:  imgFormat,
		OutputImage:  opt.OutputImage,
		SizeGiB:      sizeGiB,
		SourceSizeGB: float64(usedBytes) / (1024 * 1024 * 1024),
	}, nil
}

// Partition represents a detected partition in the disk image
type Partition struct {
	Number      int
	StartSector int64
	EndSector   int64
	SectorSize  int64
	StartBytes  int64
	SizeBytes   int64
	Type        string
	Bootable    bool
}

func detectImageFormat(qemuImgCmd, path string) (string, error) {
	out, err := exec.Command(qemuImgCmd, "info", "--output=json", path).CombinedOutput()
	if err != nil {
		// Fallback: try without JSON
		out, err = exec.Command(qemuImgCmd, "info", path).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("qemu-img info failed: %v: %s", err, string(out))
		}
		// Parse text output for "file format: xxx"
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "file format:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "file format:")), nil
			}
		}
		return "", errors.New("could not detect image format")
	}

	// Parse JSON output - look for "format": "xxx"
	outStr := string(out)
	re := regexp.MustCompile(`"format"\s*:\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(outStr)
	if len(matches) >= 2 {
		return matches[1], nil
	}

	return "", errors.New("could not parse qemu-img output")
}

func convertToRaw(qemuImgCmd, inputPath, outputPath, srcFormat string) error {
	args := []string{"convert"}
	if srcFormat != "" {
		args = append(args, "-f", srcFormat)
	}
	args = append(args, "-O", "raw", inputPath, outputPath)
	return runCmd(qemuImgCmd, args...)
}

func detectPartitions(fdiskCmd, rawPath string) ([]Partition, error) {
	out, err := exec.Command(fdiskCmd, "-l", "-o", "Device,Start,End,Sectors,Size,Type", rawPath).CombinedOutput()
	if err != nil {
		// fdisk might fail for some images, try sfdisk
		return detectPartitionsSfdisk(rawPath)
	}

	return parsePartitions(string(out), rawPath)
}

func detectPartitionsSfdisk(rawPath string) ([]Partition, error) {
	sfdiskCmd := futils.FindProgram("sfdisk")
	if sfdiskCmd == "" {
		return nil, errors.New("neither fdisk nor sfdisk available")
	}

	out, err := exec.Command(sfdiskCmd, "-d", rawPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sfdisk failed: %v: %s", err, string(out))
	}

	return parseSfdiskOutput(string(out))
}

func parsePartitions(output, rawPath string) ([]Partition, error) {
	var partitions []Partition
	lines := strings.Split(output, "\n")
	sectorSize := int64(512) // Default sector size

	// Try to find sector size in output
	for _, line := range lines {
		if strings.Contains(line, "Sector size") {
			// "Sector size (logical/physical): 512 bytes / 512 bytes"
			re := regexp.MustCompile(`Sector size.*?:\s*(\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
				if sz, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
					sectorSize = sz
				}
			}
		}
	}

	// Parse partition lines
	inPartitionSection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Start of partition table
		if strings.Contains(line, "Device") && strings.Contains(line, "Start") {
			inPartitionSection = true
			continue
		}

		if !inPartitionSection {
			continue
		}

		// Parse partition line: /path/to/disk.raw1  2048  1050623  1048576  512M  Linux filesystem
		if strings.HasPrefix(line, rawPath) {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				part := Partition{SectorSize: sectorSize}

				// Extract partition number from device name
				devName := fields[0]
				if idx := strings.LastIndex(devName, "raw"); idx >= 0 {
					numStr := devName[idx+3:]
					if n, err := strconv.Atoi(numStr); err == nil {
						part.Number = n
					}
				}

				// Parse start sector
				if start, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					part.StartSector = start
					part.StartBytes = start * sectorSize
				}

				// Parse end sector
				if end, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
					part.EndSector = end
					part.SizeBytes = (end - part.StartSector + 1) * sectorSize
				}

				// Type is usually the last field(s)
				if len(fields) >= 6 {
					part.Type = strings.Join(fields[5:], " ")
				}

				partitions = append(partitions, part)
			}
		}
	}

	return partitions, nil
}

func parseSfdiskOutput(output string) ([]Partition, error) {
	var partitions []Partition
	lines := strings.Split(output, "\n")
	sectorSize := int64(512)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// sfdisk -d format: /dev/sda1 : start=     2048, size=   206848, type=C12A7328-...
		if strings.Contains(line, "start=") && strings.Contains(line, "size=") {
			part := Partition{SectorSize: sectorSize}

			// Parse start
			if re := regexp.MustCompile(`start=\s*(\d+)`); true {
				if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
					if start, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
						part.StartSector = start
						part.StartBytes = start * sectorSize
					}
				}
			}

			// Parse size
			if re := regexp.MustCompile(`size=\s*(\d+)`); true {
				if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
					if sz, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
						part.SizeBytes = sz * sectorSize
					}
				}
			}

			// Parse type
			if re := regexp.MustCompile(`type=\s*([^,\s]+)`); true {
				if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
					part.Type = matches[1]
				}
			}

			if part.StartBytes > 0 {
				partitions = append(partitions, part)
			}
		}
	}

	return partitions, nil
}

func findRootPartition(partitions []Partition) *Partition {
	if len(partitions) == 0 {
		return nil
	}

	// Find the largest Linux partition (skip EFI, swap, etc.)
	var best *Partition
	for i := range partitions {
		p := &partitions[i]

		// Skip small partitions (likely boot/EFI)
		if p.SizeBytes < 500*1024*1024 { // < 500MB
			continue
		}

		// Skip known non-root partition types
		typeLower := strings.ToLower(p.Type)
		if strings.Contains(typeLower, "efi") ||
			strings.Contains(typeLower, "swap") ||
			strings.Contains(typeLower, "bios") ||
			p.Type == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" { // EFI System Partition GUID
			continue
		}

		if best == nil || p.SizeBytes > best.SizeBytes {
			best = p
		}
	}

	// If no suitable partition found, return the largest one
	if best == nil && len(partitions) > 0 {
		best = &partitions[0]
		for i := range partitions {
			if partitions[i].SizeBytes > best.SizeBytes {
				best = &partitions[i]
			}
		}
	}

	return best
}

func mountLoopWithOffset(img string, offset int64, losetupCmd, mountCmd string) (mountpoint, loopdev string, err error) {
	if losetupCmd == "" {
		losetupCmd = futils.FindProgram("losetup")
	}

	// Create loop device with offset
	out, err := exec.Command(losetupCmd, "--find", "--show", "-o", strconv.FormatInt(offset, 10), img).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("losetup with offset: %v: %s", err, string(out))
	}
	loop := strings.TrimSpace(string(out))

	mnt, err := os.MkdirTemp("", "qemu2fc-src-")
	if err != nil {
		_ = detachLoop(loop, losetupCmd)
		return "", "", err
	}

	if mountCmd == "" {
		mountCmd = futils.FindProgram("mount")
	}

	// Try read-only mount first (safer)
	if err := runCmd(mountCmd, "-o", "ro", loop, mnt); err != nil {
		_ = detachLoop(loop, losetupCmd)
		_ = os.RemoveAll(mnt)
		return "", "", fmt.Errorf("mount failed: %w", err)
	}

	return mnt, loop, nil
}

func mountLoop(img string, losetupCmd, mountCmd string) (mountpoint, loopdev string, err error) {
	if losetupCmd == "" {
		losetupCmd = futils.FindProgram("losetup")
	}

	out, err := exec.Command(losetupCmd, "--find", "--show", img).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("losetup: %v: %s", err, string(out))
	}
	loop := strings.TrimSpace(string(out))

	mnt, err := os.MkdirTemp("", "qemu2fc-dst-")
	if err != nil {
		_ = detachLoop(loop, losetupCmd)
		return "", "", err
	}

	if mountCmd == "" {
		mountCmd = futils.FindProgram("mount")
	}

	if err := runCmd(mountCmd, "-o", "rw", loop, mnt); err != nil {
		_ = detachLoop(loop, losetupCmd)
		_ = os.RemoveAll(mnt)
		return "", "", fmt.Errorf("mount failed: %w", err)
	}

	return mnt, loop, nil
}

func umountPath(mnt string, umountCmd string) error {
	if _, err := os.Stat(mnt); err == nil {
		if umountCmd == "" {
			umountCmd = futils.FindProgram("umount")
		}
		if err := runCmd(umountCmd, mnt); err != nil {
			// Try lazy unmount
			_ = runCmd(umountCmd, "-l", mnt)
		}
		return os.RemoveAll(mnt)
	}
	return nil
}

func detachLoop(loop string, losetupCmd string) error {
	if loop == "" {
		return nil
	}
	if losetupCmd == "" {
		losetupCmd = futils.FindProgram("losetup")
	}
	return runCmd(losetupCmd, "-d", loop)
}

func calculateUsedSpace(duCmd, path string) (int64, error) {
	if duCmd == "" {
		duCmd = futils.FindProgram("du")
	}

	out, err := exec.Command(duCmd, "-sb", path).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("du failed: %v: %s", err, string(out))
	}

	// Output: "12345678\t/path"
	fields := strings.Fields(string(out))
	if len(fields) < 1 {
		return 0, errors.New("could not parse du output")
	}

	return strconv.ParseInt(fields[0], 10, 64)
}

func createExt4(path string, sizeGiB int64, label string, mkfsCmd string) error {
	const GiB = int64(1024 * 1024 * 1024)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(sizeGiB * GiB); err != nil {
		return err
	}
	if mkfsCmd == "" {
		mkfsCmd = futils.FindProgram("mkfs.ext4")
	}
	return runCmd(mkfsCmd, "-F", "-L", label, path)
}

func copyWithTar(tarCmd, src, dst string) error {
	if tarCmd == "" {
		tarCmd = futils.FindProgram("tar")
	}

	// Use tar to preserve permissions, ownership, symlinks, etc.
	// tar -C /source -cf - . | tar -C /dest -xf -
	srcCmd := exec.Command(tarCmd, "-C", src, "-cf", "-", ".")
	dstCmd := exec.Command(tarCmd, "-C", dst, "-xf", "-")

	pipe, err := srcCmd.StdoutPipe()
	if err != nil {
		return err
	}
	dstCmd.Stdin = pipe

	var srcErr, dstErr bytes.Buffer
	srcCmd.Stderr = &srcErr
	dstCmd.Stderr = &dstErr

	if err := srcCmd.Start(); err != nil {
		return fmt.Errorf("tar source start failed: %w", err)
	}
	if err := dstCmd.Start(); err != nil {
		_ = srcCmd.Process.Kill()
		return fmt.Errorf("tar dest start failed: %w", err)
	}

	srcWaitErr := srcCmd.Wait()
	dstWaitErr := dstCmd.Wait()

	if srcWaitErr != nil {
		return fmt.Errorf("tar source failed: %v: %s", srcWaitErr, srcErr.String())
	}
	if dstWaitErr != nil {
		return fmt.Errorf("tar dest failed: %v: %s", dstWaitErr, dstErr.String())
	}

	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, buf.String())
	}
	return nil
}

func ensureCmd(name string) error {
	if name == "" || !futils.FileExists(name) {
		return fmt.Errorf("required command %q not found", name)
	}
	return nil
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root (loop mount, filesystem operations require root)")
	}
	return nil
}

// ConvertQemuImageToRootFS is a convenience function to convert an image directly to the rootfs directory
func ConvertQemuImageToRootFS(inputPath, outputName, rootfsDir string, progress ProgressCallback) (*ConvertResult, error) {
	futils.CreateDir(rootfsDir)
	outputPath := filepath.Join(rootfsDir, outputName+".ext4")

	return ConvertQemuImage(inputPath, ConvertOptions{
		OutputImage: outputPath,
		Label:       "rootfs",
	}, progress)
}

// QemuUtilsStatus represents the availability status of qemu-utils
type QemuUtilsStatus struct {
	Available  bool   `json:"available"`
	Version    string `json:"version,omitempty"`
	CanInstall bool   `json:"can_install"`
	InstallCmd string `json:"install_cmd,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CheckQemuUtils checks if qemu-img is available on the system
func CheckQemuUtils() *QemuUtilsStatus {
	status := &QemuUtilsStatus{
		CanInstall: false,
	}

	// Try to find qemu-img
	qemuImgCmd := futils.FindProgram("qemu-img")
	if qemuImgCmd != "" {
		// Get version
		out, err := exec.Command(qemuImgCmd, "--version").CombinedOutput()
		if err == nil {
			status.Available = true
			// Parse version from first line
			lines := strings.Split(string(out), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
			return status
		}
	}

	// Not available, check if we can install
	status.Available = false

	// Check for apt-get (Debian/Ubuntu)
	aptGet := futils.FindProgram("apt-get")
	if aptGet != "" {
		status.CanInstall = true
		status.InstallCmd = "apt-get install -y qemu-utils"
		return status
	}

	// Check for yum (RHEL/CentOS)
	yum := futils.FindProgram("yum")
	if yum != "" {
		status.CanInstall = true
		status.InstallCmd = "yum install -y qemu-img"
		return status
	}

	// Check for dnf (Fedora)
	dnf := futils.FindProgram("dnf")
	if dnf != "" {
		status.CanInstall = true
		status.InstallCmd = "dnf install -y qemu-img"
		return status
	}

	status.Error = "qemu-utils not found and no supported package manager detected"
	return status
}

// InstallQemuUtils attempts to install qemu-utils using the system package manager
func InstallQemuUtils() error {
	if os.Geteuid() != 0 {
		return errors.New("root privileges required to install packages")
	}

	// Check for apt-get (Debian/Ubuntu)
	aptGet := futils.FindProgram("apt-get")
	if aptGet != "" {
		// Update package list first
		updateCmd := exec.Command(aptGet, "update")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get update failed: %v: %s", err, string(out))
		}

		// Install qemu-utils
		installCmd := exec.Command(aptGet, "install", "-y", "qemu-utils")
		if out, err := installCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("apt-get install qemu-utils failed: %v: %s", err, string(out))
		}
		return nil
	}

	// Check for yum (RHEL/CentOS)
	yum := futils.FindProgram("yum")
	if yum != "" {
		installCmd := exec.Command(yum, "install", "-y", "qemu-img")
		if out, err := installCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("yum install qemu-img failed: %v: %s", err, string(out))
		}
		return nil
	}

	// Check for dnf (Fedora)
	dnf := futils.FindProgram("dnf")
	if dnf != "" {
		installCmd := exec.Command(dnf, "install", "-y", "qemu-img")
		if out, err := installCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("dnf install qemu-img failed: %v: %s", err, string(out))
		}
		return nil
	}

	return errors.New("no supported package manager found (apt-get, yum, or dnf)")
}

// IsAvailable returns true if qemu-img is available for use
func IsAvailable() bool {
	qemuImgCmd := futils.FindProgram("qemu-img")
	if qemuImgCmd == "" {
		return false
	}
	// Verify it actually works
	cmd := exec.Command(qemuImgCmd, "--version")
	return cmd.Run() == nil
}
