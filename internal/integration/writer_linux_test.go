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

func TestStagedWriterGRUBQEMU(t *testing.T) {
	if os.Getenv("CHR_WRITER_INTEGRATION") != "1" {
		t.Skip("set CHR_WRITER_INTEGRATION=1 with kernel version and binary paths")
	}
	if kind := os.Getenv("CHR_WRITER_DISK"); kind != "" && kind != "virtio" {
		t.Skip("the GRUB transition is exercised once in the virtio matrix job")
	}
	if os.Geteuid() != 0 {
		t.Fatal("GRUB writer integration requires root")
	}
	for _, commandName := range []string{"blkid", "grub-editenv", "grub-install", "grub-reboot", "losetup", "mkfs.ext4", "mount", "qemu-system-x86_64", "sfdisk", "umount"} {
		if _, err := exec.LookPath(commandName); err != nil {
			t.Fatalf("%s is required: %v", commandName, err)
		}
	}
	kernel := requireFile(t, "CHR_TEST_KERNEL")
	binaryPath := requireFile(t, "CHR_TEST_BINARY")
	directory := t.TempDir()
	imagePath := filepath.Join(directory, "payload.img")
	targetPath := filepath.Join(directory, "target.img")
	stagedInitrd := filepath.Join(directory, "staged-initrd.img")
	bootPath := filepath.Join(directory, "grub-boot.img")
	serialPath := filepath.Join(directory, "grub-writer-serial.log")
	payload := bytes.Repeat([]byte("chr-install-grub-writer-integration\n"), 256*1024)
	if err := os.WriteFile(imagePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, make([]byte, 64*1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	boot, err := os.OpenFile(bootPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := boot.Truncate(512 * 1024 * 1024); err != nil {
		_ = boot.Close()
		t.Fatal(err)
	}
	if err := boot.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		output, _ := exec.Command("losetup", "--associated", bootPath).Output()
		for _, line := range strings.Split(string(output), "\n") {
			loopPath, _, found := strings.Cut(line, ":")
			if found && strings.HasPrefix(loopPath, "/dev/loop") {
				_ = exec.Command("losetup", "--detach", loopPath).Run()
			}
		}
	})
	targetDisk, diskArguments, err := writerDisk(os.Getenv("CHR_WRITER_DISK"), targetPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := install.NewManifest(
		targetDisk,
		imagePath,
		fmt.Sprintf("%x", sha256.Sum256(payload)),
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
	partitionDiskImage(t, bootPath)
	loopPath, partitionPath := attachPartitionedLoop(t, bootPath)
	mountpoint := filepath.Join(directory, "boot-mount")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	runIntegrationCommand(t, nil, "mkfs.ext4", "-F", "-L", "chr-grub-test", partitionPath)
	runIntegrationCommand(t, nil, "mount", partitionPath, mountpoint)
	mounted := true
	t.Cleanup(func() {
		if mounted {
			_ = exec.Command("umount", mountpoint).Run()
		}
	})
	bootDirectory := filepath.Join(mountpoint, "boot")
	if err := os.MkdirAll(bootDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	runIntegrationCommand(t, nil, "grub-install", "--target=i386-pc", "--boot-directory="+bootDirectory, "--no-floppy", "--recheck", loopPath)
	if err := copyIntegrationFile(kernel, filepath.Join(bootDirectory, "vmlinuz"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyIntegrationFile(stagedInitrd, filepath.Join(bootDirectory, "initrd.img"), 0o600); err != nil {
		t.Fatal(err)
	}
	uuid := strings.TrimSpace(runIntegrationCommand(t, nil, "blkid", "-s", "UUID", "-o", "value", partitionPath))
	configuration := fmt.Sprintf(`serial --unit=0 --speed=115200
terminal_input serial
terminal_output serial
set default=0
if [ -s $prefix/grubenv ]; then
  load_env next_entry
fi
if [ "${next_entry}" = "chr-install-writer" ]; then
  set default="chr-install-writer"
  set next_entry=
  save_env next_entry
fi
set timeout=0
menuentry 'Fallback Linux' --id 'fallback-linux' {
  echo 'CHR-GRUB-FALLBACK'
  reboot
}
menuentry 'CHR Install Writer' --id 'chr-install-writer' {
  search --no-floppy --fs-uuid --set=root %s
  linux /boot/vmlinuz console=ttyS0 root=/dev/vda rootfstype=ext4 ro panic=-1 chr.install=1
  initrd /boot/initrd.img
}
`, uuid)
	grubDirectory := filepath.Join(bootDirectory, "grub")
	if err := os.WriteFile(filepath.Join(grubDirectory, "grub.cfg"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	environmentPath := filepath.Join(grubDirectory, "grubenv")
	runIntegrationCommand(t, nil, "grub-editenv", environmentPath, "create")
	runIntegrationCommand(t, nil, "grub-reboot", "--boot-directory="+bootDirectory, "chr-install-writer")
	armedEnvironment := runIntegrationCommand(t, nil, "grub-editenv", environmentPath, "list")
	if !strings.Contains(armedEnvironment, "next_entry=chr-install-writer") {
		t.Fatalf("grub-reboot did not arm the test writer entry: %q", armedEnvironment)
	}
	runIntegrationCommand(t, nil, "sync")
	runIntegrationCommand(t, nil, "umount", mountpoint)
	mounted = false
	runIntegrationCommand(t, nil, "losetup", "--detach", loopPath)

	serial, err := os.Create(serialPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	arguments := []string{
		"-machine", "q35,accel=tcg", "-m", "768", "-nographic", "-no-reboot",
		"-drive", "if=none,file=" + bootPath + ",format=raw,id=boot",
		"-device", "virtio-blk-pci,drive=boot,serial=chr-grub-boot,bootindex=1",
	}
	arguments = append(arguments, diskArguments...)
	process := exec.CommandContext(ctx, "qemu-system-x86_64", arguments...)
	process.Stdout, process.Stderr = serial, serial
	processErr := process.Run()
	closeErr := serial.Close()
	if processErr != nil || closeErr != nil {
		data, _ := os.ReadFile(serialPath)
		t.Fatalf("GRUB-staged writer VM failed: %v, close=%v\n%s", processErr, closeErr, tail(string(data), 16000))
	}
	written, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written[:len(payload)], payload) {
		data, _ := os.ReadFile(serialPath)
		t.Fatalf("GRUB-staged writer did not reproduce the authorized payload\n%s", tail(string(data), 16000))
	}
	serialData, _ := os.ReadFile(serialPath)
	if !strings.Contains(string(serialData), "write and read-back verification succeeded") {
		t.Fatalf("GRUB writer success marker was not found\n%s", tail(string(serialData), 16000))
	}

	loopPath, partitionPath = attachPartitionedLoop(t, bootPath)
	runIntegrationCommand(t, nil, "mount", partitionPath, mountpoint)
	mounted = true
	environment := runIntegrationCommand(t, nil, "grub-editenv", filepath.Join(mountpoint, "boot", "grub", "grubenv"), "list")
	if strings.Contains(environment, "next_entry=chr-install-writer") {
		t.Fatalf("GRUB did not clear the one-shot writer entry: %q", environment)
	}
	runIntegrationCommand(t, nil, "umount", mountpoint)
	mounted = false
	runIntegrationCommand(t, nil, "losetup", "--detach", loopPath)

	fallbackLog := filepath.Join(directory, "grub-fallback-serial.log")
	fallback, err := os.Create(fallbackLog)
	if err != nil {
		t.Fatal(err)
	}
	fallbackContext, fallbackCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer fallbackCancel()
	fallbackProcess := exec.CommandContext(fallbackContext, "qemu-system-x86_64",
		"-machine", "q35,accel=tcg", "-m", "256", "-nographic", "-no-reboot",
		"-drive", "if=none,file="+bootPath+",format=raw,id=boot",
		"-device", "virtio-blk-pci,drive=boot,serial=chr-grub-boot,bootindex=1",
	)
	fallbackProcess.Stdout, fallbackProcess.Stderr = fallback, fallback
	fallbackErr := fallbackProcess.Run()
	_ = fallback.Close()
	if fallbackErr != nil {
		data, _ := os.ReadFile(fallbackLog)
		t.Fatalf("GRUB fallback boot failed: %v\n%s", fallbackErr, tail(string(data), 8000))
	}
	fallbackData, _ := os.ReadFile(fallbackLog)
	if !strings.Contains(string(fallbackData), "CHR-GRUB-FALLBACK") {
		t.Fatalf("the boot after the writer did not select the fallback entry\n%s", tail(string(fallbackData), 8000))
	}
}

func TestStagedWriterKexecQEMU(t *testing.T) {
	if os.Getenv("CHR_WRITER_INTEGRATION") != "1" {
		t.Skip("set CHR_WRITER_INTEGRATION=1 with kernel version and binary paths")
	}
	if kind := os.Getenv("CHR_WRITER_DISK"); kind != "" && kind != "virtio" {
		t.Skip("the kexec transition is exercised once in the virtio matrix job")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kexec writer integration requires root")
	}
	for _, commandName := range []string{"kexec", "mkinitramfs", "qemu-system-x86_64"} {
		if _, err := exec.LookPath(commandName); err != nil {
			t.Fatalf("%s is required: %v", commandName, err)
		}
	}
	kernel := requireFile(t, "CHR_TEST_KERNEL")
	binaryPath := requireFile(t, "CHR_TEST_BINARY")
	directory := t.TempDir()
	imagePath := filepath.Join(directory, "payload.img")
	targetPath := filepath.Join(directory, "target.img")
	writerInitrd := filepath.Join(directory, "writer-initrd.img")
	launcherInitrd := filepath.Join(directory, "kexec-launcher-initrd.img")
	serialPath := filepath.Join(directory, "kexec-writer-serial.log")
	payload := bytes.Repeat([]byte("chr-install-kexec-writer-integration\n"), 128*1024)
	if err := os.WriteFile(imagePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, make([]byte, 64*1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	targetDisk, diskArguments, err := writerDisk("virtio", targetPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest := install.NewManifest(
		targetDisk,
		imagePath,
		fmt.Sprintf("%x", sha256.Sum256(payload)),
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
	if err := install.BuildInitramfs(context.Background(), command.OSRunner{}, version, writerInitrd, binaryPath, imagePath, manifest); err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(directory, "launcher-config")
	if err := os.Mkdir(configDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	runIntegrationCommand(t, nil, "cp", "-a", "/etc/initramfs-tools/.", configDirectory)
	for _, path := range []string{filepath.Join(configDirectory, "hooks"), filepath.Join(configDirectory, "scripts", "local-premount"), filepath.Join(configDirectory, "conf.d")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDirectory, "conf.d", "zz-chr-kexec-modules"), []byte("MODULES=most\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kexecPath, err := exec.LookPath("kexec")
	if err != nil {
		t.Fatal(err)
	}
	hook := fmt.Sprintf(`#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0 ;; esac
set -eu
. /usr/share/initramfs-tools/hook-functions
copy_exec %s /sbin/kexec
mkdir -p "$DESTDIR/chr-kexec"
cp -p %s "$DESTDIR/chr-kexec/vmlinuz"
cp -p %s "$DESTDIR/chr-kexec/writer-initrd.img"
`, shellQuoteIntegration(kexecPath), shellQuoteIntegration(kernel), shellQuoteIntegration(writerInitrd))
	if err := os.WriteFile(filepath.Join(configDirectory, "hooks", "zz-chr-kexec-launcher"), []byte(hook), 0o700); err != nil {
		t.Fatal(err)
	}
	premount := `#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0 ;; esac
echo "CHR-KEXEC-LAUNCH" >/dev/console
/sbin/kexec -l /chr-kexec/vmlinuz --initrd=/chr-kexec/writer-initrd.img --append="console=ttyS0 root=/dev/vda rootfstype=ext4 ro panic=-1 chr.install=1"
sync
exec /sbin/kexec -e
`
	if err := os.WriteFile(filepath.Join(configDirectory, "scripts", "local-premount", "zz-chr-kexec-launcher"), []byte(premount), 0o700); err != nil {
		t.Fatal(err)
	}
	runIntegrationCommand(t, nil, "mkinitramfs", "-d", configDirectory, "-o", launcherInitrd, version)
	serial, err := os.Create(serialPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	arguments := []string{
		"-machine", "q35,accel=tcg", "-m", "1024", "-nographic", "-no-reboot",
		"-kernel", kernel, "-initrd", launcherInitrd,
		"-append", "console=ttyS0 root=/dev/vda rootfstype=ext4 ro panic=-1",
	}
	arguments = append(arguments, diskArguments...)
	process := exec.CommandContext(ctx, "qemu-system-x86_64", arguments...)
	process.Stdout, process.Stderr = serial, serial
	processErr := process.Run()
	closeErr := serial.Close()
	if processErr != nil || closeErr != nil {
		data, _ := os.ReadFile(serialPath)
		t.Fatalf("kexec-staged writer VM failed: %v, close=%v\n%s", processErr, closeErr, tail(string(data), 16000))
	}
	written, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written[:len(payload)], payload) {
		data, _ := os.ReadFile(serialPath)
		t.Fatalf("kexec-staged writer did not reproduce the authorized payload\n%s", tail(string(data), 16000))
	}
	serialData, _ := os.ReadFile(serialPath)
	for _, marker := range []string{"CHR-KEXEC-LAUNCH", "write and read-back verification succeeded"} {
		if !strings.Contains(string(serialData), marker) {
			t.Fatalf("kexec writer marker %q was not found\n%s", marker, tail(string(serialData), 16000))
		}
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

func partitionDiskImage(t *testing.T, path string) {
	t.Helper()
	input := strings.NewReader("label: dos\nunit: sectors\n\nstart=2048, type=83, bootable\n")
	runIntegrationCommand(t, input, "sfdisk", path)
}

func attachPartitionedLoop(t *testing.T, path string) (string, string) {
	t.Helper()
	loopPath := strings.TrimSpace(runIntegrationCommand(t, nil, "losetup", "--find", "--show", "--partscan", path))
	partitionPath := loopPath + "p1"
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(partitionPath); err == nil {
			return loopPath, partitionPath
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = exec.Command("losetup", "--detach", loopPath).Run()
	t.Fatalf("loop partition %s did not appear", partitionPath)
	return "", ""
}

func runIntegrationCommand(t *testing.T, input *strings.Reader, name string, args ...string) string {
	t.Helper()
	process := exec.Command(name, args...)
	if input != nil {
		process.Stdin = input
	}
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func copyIntegrationFile(source, destination string, mode os.FileMode) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, mode)
}

func shellQuoteIntegration(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
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
