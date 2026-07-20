//go:build linux

package install

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/parhamfa/chr-install/internal/mikrotik"
	"github.com/parhamfa/chr-install/internal/model"
	"golang.org/x/sys/unix"
)

func RunWriter(manifestPath string, reboot bool) error {
	ensurePseudoFilesystems()
	manifest, err := ReadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("read writer manifest: %w", err)
	}
	imageHash, imageSize, err := mikrotik.HashFile(manifest.ImagePath)
	if err != nil {
		return fmt.Errorf("hash prepared image: %w", err)
	}
	if imageHash != manifest.ImageSHA256 || imageSize != manifest.ImageSize {
		return fmt.Errorf("prepared image no longer matches the authorized manifest")
	}
	logWriter("Waiting for the authorized target disk to settle\n")
	targetPath, err := waitForFingerprint(manifest.Disk, 20*time.Second)
	if err != nil {
		return err
	}
	if err := ensureUnmounted(targetPath); err != nil {
		return err
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeDevice == 0 {
		return fmt.Errorf("target %s is not a block device", targetPath)
	}
	source, err := os.Open(manifest.ImagePath)
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	logWriter("Writing CHR %s to %s (%d bytes)\n", manifest.Release.Version, targetPath, manifest.ImageSize)
	writtenHash, err := CopyImage(source, target, manifest.ImageSize, consoleProgress("write"))
	if err == nil {
		err = target.Sync()
	}
	closeErr := target.Close()
	if err != nil {
		return fmt.Errorf("write target disk: %w", err)
	}
	if closeErr != nil {
		return closeErr
	}
	if writtenHash != manifest.ImageSHA256 {
		return fmt.Errorf("source changed while writing")
	}
	unix.Sync()
	readback, err := os.Open(targetPath)
	if err != nil {
		return err
	}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, readback.Fd(), uintptr(unix.BLKFLSBUF), 0); errno != 0 {
		_ = readback.Close()
		return fmt.Errorf("flush target buffers before read-back: %w", errno)
	}
	logWriter("Verifying written bytes\n")
	readbackHash, verifyErr := HashPrefix(readback, manifest.ImageSize, consoleProgress("verify"))
	_ = readback.Close()
	if verifyErr != nil {
		return fmt.Errorf("read-back verification: %w", verifyErr)
	}
	if readbackHash != manifest.ImageSHA256 {
		return fmt.Errorf("read-back checksum mismatch; refusing to reboot")
	}
	logWriter("CHR image write and read-back verification succeeded\n")
	if reboot {
		logWriter("Rebooting into CHR now\n")
		unix.Sync()
		if err := unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART); err != nil {
			return fmt.Errorf("reboot: %w", err)
		}
	}
	return nil
}

func waitForFingerprint(expected model.DiskFingerprint, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		path, err := findFingerprint(expected)
		if err == nil {
			return path, nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return "", lastErr
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func findFingerprint(expected model.DiskFingerprint) (string, error) {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		return "", err
	}
	var matches []string
	var observed []string
	for _, entry := range entries {
		name := entry.Name()
		if _, err := os.Stat(filepath.Join("/sys/class/block", name, "partition")); err == nil {
			continue
		}
		candidate := sysfsFingerprint(name)
		observed = append(observed, fmt.Sprintf("%s size=%d serial=%q wwn=%q major:minor=%q driver=%q", candidate.Path, candidate.SizeBytes, candidate.Serial, candidate.WWN, candidate.MajorMinor, candidate.Driver))
		if FingerprintsMatch(expected, candidate) {
			matches = append(matches, "/dev/"+name)
		}
	}
	if len(matches) != 1 {
		return "", fmt.Errorf("disk fingerprint matched %d devices; expected exactly one (authorized size=%d identity=%q; observed: %s)", len(matches), expected.SizeBytes, expected.StableIdentity(), strings.Join(observed, "; "))
	}
	return matches[0], nil
}

func sysfsFingerprint(name string) model.DiskFingerprint {
	base := filepath.Join("/sys/class/block", name)
	sectors, _ := strconv.ParseUint(readTrim(filepath.Join(base, "size")), 10, 64)
	return model.DiskFingerprint{
		Path:       "/dev/" + name,
		KernelName: name,
		MajorMinor: readTrim(filepath.Join(base, "dev")),
		SizeBytes:  sectors * 512,
		Model:      readTrim(filepath.Join(base, "device", "model")),
		Serial:     firstNonempty(readTrim(filepath.Join(base, "device", "serial")), readTrim(filepath.Join(base, "serial")), readSCSIVPDSerial(base)),
		WWN:        firstNonempty(readTrim(filepath.Join(base, "wwid")), readTrim(filepath.Join(base, "device", "wwid"))),
		Driver:     driverFromSysfsDevice(filepath.Join(base, "device")),
	}
}

func ensureUnmounted(targetPath string) error {
	name := filepath.Base(targetPath)
	deviceIDs := map[string]bool{readTrim(filepath.Join("/sys/class/block", name, "dev")): true}
	targetResolved, _ := filepath.EvalSymlinks(filepath.Join("/sys/class/block", name))
	entries, _ := os.ReadDir("/sys/class/block")
	for _, entry := range entries {
		candidate := filepath.Join("/sys/class/block", entry.Name())
		if _, err := os.Stat(filepath.Join(candidate, "partition")); err != nil {
			continue
		}
		resolved, _ := filepath.EvalSymlinks(candidate)
		if targetResolved != "" && strings.HasPrefix(resolved, targetResolved+string(os.PathSeparator)) {
			if id := readTrim(filepath.Join(candidate, "dev")); id != "" {
				deviceIDs[id] = true
			}
		}
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 2 && deviceIDs[fields[2]] {
			return fmt.Errorf("target disk has a mounted filesystem at %s", fields[4])
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	swaps, err := os.Open("/proc/swaps")
	if err != nil {
		return err
	}
	defer swaps.Close()
	scanner = bufio.NewScanner(swaps)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] == "Filename" {
			continue
		}
		var status unix.Stat_t
		if err := unix.Stat(fields[0], &status); err != nil {
			continue
		}
		identity := fmt.Sprintf("%d:%d", unix.Major(uint64(status.Rdev)), unix.Minor(uint64(status.Rdev)))
		if deviceIDs[identity] {
			return fmt.Errorf("target disk has active swap at %s", fields[0])
		}
	}
	return scanner.Err()
}

func ensurePseudoFilesystems() {
	for _, mount := range []struct {
		source string
		target string
		kind   string
	}{
		{"proc", "/proc", "proc"}, {"sysfs", "/sys", "sysfs"}, {"devtmpfs", "/dev", "devtmpfs"},
	} {
		_ = os.MkdirAll(mount.target, 0o755)
		_ = unix.Mount(mount.source, mount.target, mount.kind, 0, "")
	}
}

func consoleProgress(label string) ProgressFunc {
	var lastPercent int64 = -10
	return func(current, total int64) {
		percent := current * 100 / total
		if percent >= lastPercent+10 || percent == 100 {
			logWriter("%s: %d%%\n", label, percent)
			lastPercent = percent
		}
	}
}

func logWriter(format string, values ...any) {
	message := fmt.Sprintf(format, values...)
	_, _ = io.WriteString(os.Stdout, message)
	if console, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
		_, _ = io.WriteString(console, message)
		_ = console.Close()
	}
}

func readTrim(path string) string {
	data, _ := os.ReadFile(path)
	return strings.TrimSpace(string(data))
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func HaltWriter(err error) {
	logWriter("FATAL: %v\nThe writer is halted. Use provider console or rescue access; do not force a normal boot.\n", err)
	for {
		time.Sleep(time.Hour)
	}
}
