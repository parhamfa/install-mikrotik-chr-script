//go:build integration && linux

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/install"
	"github.com/parhamfa/chr-install/internal/model"
)

func TestStagedWriterQEMU(t *testing.T) {
	if os.Getenv("CHR_WRITER_INTEGRATION") != "1" {
		t.Skip("set CHR_WRITER_INTEGRATION=1 with kernel version and binary paths")
	}
	kernel := requireFile(t, "CHR_TEST_KERNEL")
	binaryPath := requireFile(t, "CHR_TEST_BINARY")
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if artifactRoot := os.Getenv("CHR_WRITER_ARTIFACT_DIR"); artifactRoot != "" {
		if err := os.MkdirAll(artifactRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		var err error
		directory, err = os.MkdirTemp(artifactRoot, "writer-run-")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("preserving writer artifacts in %s", directory)
	}
	imagePath := filepath.Join(directory, "payload.img")
	targetPath := filepath.Join(directory, "target.img")
	stagedInitrd := filepath.Join(directory, "staged-initrd.img")
	serialPath := filepath.Join(directory, "serial.log")
	payload := bytes.Repeat([]byte("chr-install-writer-integration\n"), 256*1024)
	if err := os.WriteFile(imagePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, make([]byte, 64*1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(payload))
	targetDisk, diskArguments, err := writerDisk(os.Getenv("CHR_WRITER_DISK"), targetPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := install.NewManifest(
		targetDisk,
		imagePath,
		hash,
		int64(len(payload)),
		model.Release{Version: "integration"},
		model.NetworkPlan{
			InterfaceName: "eth0",
			MAC:           "02:00:00:00:00:01",
			MTU:           1500,
			IPv4:          model.IPv4Plan{Mode: "dhcp"},
		},
	)
	version := os.Getenv("CHR_TEST_KERNEL_VERSION")
	if version == "" {
		version = strings.TrimPrefix(filepath.Base(kernel), "vmlinuz-")
		if version == filepath.Base(kernel) {
			t.Fatal("CHR_TEST_KERNEL_VERSION is required when the kernel filename is not versioned")
		}
	}
	if err := install.BuildInitramfs(context.Background(), command.OSRunner{}, version, stagedInitrd, binaryPath, imagePath, manifest); err != nil {
		t.Fatal(err)
	}
	serial, err := os.Create(serialPath)
	if err != nil {
		t.Fatal(err)
	}
	defer serial.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	arguments := []string{
		"-machine", "q35,accel=tcg", "-m", "768", "-nographic", "-no-reboot",
		"-kernel", kernel, "-initrd", stagedInitrd,
		"-append", "console=ttyS0 root=" + targetDisk.Path + " rootfstype=ext4 ro panic=-1 chr.install=1",
	}
	arguments = append(arguments, diskArguments...)
	process := exec.CommandContext(ctx, "qemu-system-x86_64", arguments...)
	process.Stdout, process.Stderr = serial, serial
	if err := process.Run(); err != nil {
		data, _ := os.ReadFile(serialPath)
		t.Fatalf("staged writer VM failed: %v\n%s", err, tail(string(data), 16000))
	}
	data, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:len(payload)], payload) {
		serialData, _ := os.ReadFile(serialPath)
		t.Fatalf("pre-root writer did not reproduce the authorized payload\n%s", tail(string(serialData), 16000))
	}
	serialData, _ := os.ReadFile(serialPath)
	if !strings.Contains(string(serialData), "write and read-back verification succeeded") {
		t.Fatalf("writer success marker was not found\n%s", tail(string(serialData), 16000))
	}
}

func TestDirectWriterLoopDevice(t *testing.T) {
	if os.Getenv("CHR_WRITER_INTEGRATION") != "1" {
		t.Skip("set CHR_WRITER_INTEGRATION=1 and run as root")
	}
	if kind := os.Getenv("CHR_WRITER_DISK"); kind != "" && kind != "virtio" {
		t.Skip("the direct writer path is exercised once in the virtio matrix job")
	}
	if os.Geteuid() != 0 {
		t.Fatal("direct writer integration requires root")
	}
	if _, err := exec.LookPath("losetup"); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	payload := bytes.Repeat([]byte("chr-install-direct-writer\n"), 128*1024)
	imagePath := filepath.Join(directory, "payload.img")
	targetPath := filepath.Join(directory, "target.img")
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(imagePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Truncate(64 * 1024 * 1024); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("losetup", "--find", "--show", targetPath).CombinedOutput()
	if err != nil {
		t.Fatalf("attach loop target: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath := strings.TrimSpace(string(output))
	t.Cleanup(func() { _ = exec.Command("losetup", "--detach", loopPath).Run() })
	name := filepath.Base(loopPath)
	sectors, err := strconv.ParseUint(readIntegrationFile(t, filepath.Join("/sys/class/block", name, "size")), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(payload))
	manifest := install.NewManifest(
		model.DiskFingerprint{
			Path:       loopPath,
			KernelName: name,
			MajorMinor: readIntegrationFile(t, filepath.Join("/sys/class/block", name, "dev")),
			SizeBytes:  sectors * 512,
		},
		imagePath,
		hash,
		int64(len(payload)),
		model.Release{Version: "integration"},
		model.NetworkPlan{
			InterfaceName: "eth0",
			MAC:           "02:00:00:00:00:01",
			MTU:           1500,
			IPv4:          model.IPv4Plan{Mode: "dhcp"},
		},
	)
	if err := install.WriteManifest(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	if err := install.RunWriter(manifestPath, false); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written[:len(payload)], payload) {
		t.Fatal("direct writer did not reproduce the authorized payload")
	}
}

func readIntegrationFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func writerDisk(kind, targetPath string) (model.DiskFingerprint, []string, error) {
	const size = 64 * 1024 * 1024
	const serial = "chr-test-target"
	drive := "if=none,file=" + targetPath + ",format=raw,id=target"
	switch kind {
	case "", "virtio":
		return model.DiskFingerprint{Path: "/dev/vda", KernelName: "vda", SizeBytes: size, Serial: serial, Driver: "virtio_blk"}, []string{
			"-drive", drive,
			"-device", "virtio-blk-pci,drive=target,serial=" + serial,
		}, nil
	case "scsi":
		return model.DiskFingerprint{Path: "/dev/sda", KernelName: "sda", SizeBytes: size, Serial: serial, Driver: "sd"}, []string{
			"-device", "virtio-scsi-pci,id=scsi0",
			"-drive", drive,
			"-device", "scsi-hd,drive=target,bus=scsi0.0,serial=" + serial,
		}, nil
	case "nvme":
		return model.DiskFingerprint{Path: "/dev/nvme0n1", KernelName: "nvme0n1", SizeBytes: size, Serial: serial, Driver: "nvme"}, []string{
			"-drive", drive,
			"-device", "nvme,drive=target,serial=" + serial,
		}, nil
	default:
		return model.DiskFingerprint{}, nil, fmt.Errorf("unsupported writer disk model %q", kind)
	}
}

func requireFile(t *testing.T, environment string) string {
	t.Helper()
	path := os.Getenv(environment)
	if path == "" {
		t.Fatalf("%s is required", environment)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return path
}
