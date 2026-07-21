package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
)

type Stage struct {
	Method         model.InstallMethod
	KernelPath     string
	InitrdPath     string
	Cmdline        string
	GRUBScript     string
	GRUBConfigPath string
	GRUBEnvPath    string
	BuildDir       string
	StageDir       string
}

const (
	kexecStageDir   = "/var/lib/chr-install"
	grubStageDir    = "/boot/chr-install"
	grubScriptPath  = "/etc/grub.d/42_chr_install"
	grubConfigPath  = "/boot/grub/grub.cfg"
	grubEnvPath     = "/boot/grub/grubenv"
	buildSpaceSpare = 128 * 1024 * 1024
	bootSpaceSpare  = 32 * 1024 * 1024
	cleanupTimeout  = 2 * time.Minute
)

func StageAndBoot(ctx context.Context, runner command.Runner, disk model.Disk, preparedImage, executable string, manifest Manifest, memoryBytes uint64) error {
	if disk.Method == model.InstallMethodDirect {
		manifest.ImagePath = preparedImage
		manifestPath := filepath.Join(filepath.Dir(preparedImage), "writer-manifest.json")
		if err := WriteManifest(manifestPath, manifest); err != nil {
			return err
		}
		return RunWriter(manifestPath, true)
	}
	stage, err := PrepareStage(ctx, runner, disk, preparedImage, executable, manifest, memoryBytes)
	if err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "sync"); err != nil {
		return errors.Join(fmt.Errorf("sync staged writer: %w", err), cleanupStage(runner, stage, false, false))
	}
	if stage.Method == model.InstallMethodKexec {
		kexecErr := executeKexec(ctx, runner, stage)
		if kexecErr == nil {
			return nil
		}
		cleanupErr := cleanupStage(runner, stage, false, false)
		if cleanupErr != nil || !disk.GRUB {
			return errors.Join(kexecErr, cleanupErr)
		}
		disk.Method = model.InstallMethodGRUB
		stage, stageErr := PrepareStage(ctx, runner, disk, preparedImage, executable, manifest, memoryBytes)
		if stageErr != nil {
			return errors.Join(kexecErr, fmt.Errorf("GRUB fallback could not be staged: %w", stageErr))
		}
		return executeGRUB(ctx, runner, stage)
	}
	if stage.Method == model.InstallMethodGRUB {
		return executeGRUB(ctx, runner, stage)
	}
	cleanupErr := cleanupStage(runner, stage, false, false)
	return errors.Join(fmt.Errorf("unsupported installation method %q", stage.Method), cleanupErr)
}

func executeKexec(ctx context.Context, runner command.Runner, stage Stage) (returnErr error) {
	loaded := false
	defer func() {
		if returnErr != nil && loaded {
			cleanupContext, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
			defer cancel()
			_, unloadErr := runner.Run(cleanupContext, "kexec", "-u")
			if unloadErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("unload failed kexec image: %w", unloadErr))
			}
		}
	}()
	if _, err := runner.Run(ctx, "kexec", "-l", stage.KernelPath, "--initrd="+stage.InitrdPath, "--append="+stage.Cmdline); err != nil {
		return err
	}
	loaded = true
	if err := cleanupStage(runner, stage, false, false); err != nil {
		return fmt.Errorf("remove loaded kexec staging files: %w", err)
	}
	if _, err := runner.Run(ctx, "systemctl", "kexec"); err != nil {
		_, fallbackErr := runner.Run(ctx, "kexec", "-e")
		if fallbackErr != nil {
			return fmt.Errorf("systemd and direct kexec both failed: %v; %w", err, fallbackErr)
		}
	}
	return nil
}

func executeGRUB(ctx context.Context, runner command.Runner, stage Stage) (returnErr error) {
	refreshAttempted := false
	armAttempted := false
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, cleanupStage(runner, stage, armAttempted, refreshAttempted))
		}
	}()
	refreshAttempted = true
	if _, err := runner.Run(ctx, "update-grub"); err != nil {
		return err
	}
	if err := validateGRUBConfiguration(stage.GRUBConfigPath); err != nil {
		return err
	}
	if err := validateGRUBStorage(ctx, runner, stage.GRUBEnvPath); err != nil {
		return err
	}
	armAttempted = true
	if _, err := runner.Run(ctx, "grub-reboot", "chr-install-writer"); err != nil {
		return err
	}
	if err := verifyGRUBNextEntry(ctx, runner, stage.GRUBEnvPath); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "reboot"); err != nil {
		_, fallbackErr := runner.Run(ctx, "reboot")
		return fallbackErr
	}
	return nil
}

func PrepareStage(ctx context.Context, runner command.Runner, disk model.Disk, imagePath, executable string, manifest Manifest, memoryBytes uint64) (stage Stage, returnErr error) {
	if disk.Method != model.InstallMethodKexec && disk.Method != model.InstallMethodGRUB {
		return Stage{}, fmt.Errorf("%s is not a staged installation method", disk.Method)
	}
	if _, err := os.Stat(disk.KernelPath); err != nil {
		return Stage{}, err
	}
	if _, err := os.Stat(disk.InitrdPath); err != nil {
		return Stage{}, err
	}
	cmdlineData, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return Stage{}, err
	}
	cmdline := writerCmdline(string(cmdlineData))
	stage = Stage{Method: disk.Method, KernelPath: disk.KernelPath, Cmdline: cmdline}
	partialFiles := []string{}
	partialDirs := []string{}
	committed := false
	defer func() {
		if !committed {
			returnErr = errors.Join(returnErr, cleanupPartialStage(partialFiles, partialDirs))
		}
	}()

	if err := os.MkdirAll(kexecStageDir, 0o700); err != nil {
		return Stage{}, err
	}
	partialDirs = append(partialDirs, kexecStageDir)
	buildPath := filepath.Join(kexecStageDir, "initrd.img")
	partialFiles = append(partialFiles, buildPath)
	if err := os.Remove(buildPath); err != nil && !os.IsNotExist(err) {
		return Stage{}, err
	}
	imageInfo, err := os.Stat(imagePath)
	if err != nil {
		return Stage{}, err
	}
	baseInitrdInfo, err := os.Stat(disk.InitrdPath)
	if err != nil {
		return Stage{}, err
	}
	if imageInfo.Size() <= 0 || baseInitrdInfo.Size() <= 0 {
		return Stage{}, fmt.Errorf("image and base initramfs must be non-empty regular files")
	}
	imageBytes := uint64(imageInfo.Size())
	baseInitrdBytes := uint64(baseInitrdInfo.Size())
	if baseInitrdBytes > (^uint64(0)-imageBytes-buildSpaceSpare)/4 {
		return Stage{}, fmt.Errorf("initramfs staging-space estimate overflowed")
	}
	buildRequired := imageBytes + 4*baseInitrdBytes + buildSpaceSpare
	if err := ensureFilesystemSpace(kexecStageDir, buildRequired); err != nil {
		return Stage{}, fmt.Errorf("stage initramfs: %w", err)
	}
	if err := BuildInitramfs(ctx, runner, kernelVersion(disk.KernelPath), buildPath, executable, imagePath, manifest); err != nil {
		return Stage{}, err
	}
	if err := validateInitramfsMemory(ctx, runner, buildPath, memoryBytes, manifest.ImageSize); err != nil {
		return Stage{}, err
	}
	if disk.Method == model.InstallMethodKexec {
		stage.InitrdPath = buildPath
		stage.BuildDir = kexecStageDir
		stage.StageDir = kexecStageDir
		committed = true
		return stage, nil
	}

	if err := os.MkdirAll(grubStageDir, 0o700); err != nil {
		return Stage{}, err
	}
	partialDirs = append(partialDirs, grubStageDir)
	stage.InitrdPath = filepath.Join(grubStageDir, "initrd.img")
	partialFiles = append(partialFiles, stage.InitrdPath)
	builtInfo, err := os.Stat(buildPath)
	if err != nil {
		return Stage{}, err
	}
	if err := ensureFilesystemSpace(grubStageDir, uint64(builtInfo.Size())+bootSpaceSpare); err != nil {
		return Stage{}, fmt.Errorf("stage GRUB initramfs: %w", err)
	}
	if err := copyFileAtomic(buildPath, stage.InitrdPath, 0o600); err != nil {
		return Stage{}, err
	}
	if err := os.Remove(buildPath); err != nil {
		return Stage{}, err
	}
	script, err := grubScript(ctx, runner, stage)
	if err != nil {
		return Stage{}, err
	}
	stage.GRUBScript = grubScriptPath
	stage.GRUBConfigPath = grubConfigPath
	stage.GRUBEnvPath = grubEnvPath
	stage.BuildDir = kexecStageDir
	stage.StageDir = grubStageDir
	partialFiles = append(partialFiles, stage.GRUBScript)
	if err := writeFileAtomic(stage.GRUBScript, []byte(script), 0o755); err != nil {
		return Stage{}, err
	}
	committed = true
	return stage, nil
}

func copyFileAtomic(source, destination string, mode os.FileMode) (returnErr error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".initrd-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, input); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func writeFileAtomic(destination string, data []byte, mode os.FileMode) (returnErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".chr-install-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, destination)
}

func validateGRUBConfiguration(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read generated GRUB configuration: %w", err)
	}
	configuration := string(data)
	for _, required := range []string{
		"load_env next_entry",
		`if [ "${next_entry}" = "chr-install-writer" ]; then`,
		`set default="chr-install-writer"`,
		"set next_entry=",
		"save_env next_entry",
		"menuentry 'CHR Install Writer' --id 'chr-install-writer'",
	} {
		if !strings.Contains(configuration, required) {
			return fmt.Errorf("generated GRUB configuration does not provide verified one-shot handling (%s is absent)", required)
		}
	}
	return nil
}

func validateGRUBStorage(ctx context.Context, runner command.Runner, environmentPath string) error {
	filesystem, err := runner.Run(ctx, "grub-probe", "--target=fs", environmentPath)
	if err != nil {
		return fmt.Errorf("inspect GRUB environment filesystem: %w", err)
	}
	if value := strings.TrimSpace(string(filesystem)); value != "ext2" {
		return fmt.Errorf("GRUB one-shot environment uses unsupported filesystem %q; an ext2/3/4 boot filesystem is required", value)
	}
	abstraction, err := runner.Run(ctx, "grub-probe", "--target=abstraction", environmentPath)
	if err != nil {
		return fmt.Errorf("inspect GRUB environment storage: %w", err)
	}
	if value := strings.TrimSpace(string(abstraction)); value != "" {
		return fmt.Errorf("GRUB one-shot environment is behind unsupported storage abstraction %q", value)
	}
	return nil
}

func verifyGRUBNextEntry(ctx context.Context, runner command.Runner, environmentPath string) error {
	output, err := runner.Run(ctx, "grub-editenv", environmentPath, "list")
	if err != nil {
		return fmt.Errorf("read armed GRUB environment: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.TrimSpace(line) == "next_entry=chr-install-writer" {
			return nil
		}
	}
	return fmt.Errorf("grub-reboot did not arm the chr-install-writer entry")
}

func cleanupStage(runner command.Runner, stage Stage, clearNextEntry, refreshGRUB bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	var cleanupErrors []error
	if clearNextEntry && stage.GRUBEnvPath != "" {
		if _, err := runner.Run(ctx, "grub-editenv", stage.GRUBEnvPath, "unset", "next_entry"); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("clear pending GRUB entry: %w", err))
		}
	}
	for _, path := range []string{stage.GRUBScript, stage.InitrdPath} {
		if path == "" {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove staged file %s: %w", path, err))
		}
	}
	for _, directory := range []string{stage.StageDir, stage.BuildDir} {
		if directory == "." || directory == "" {
			continue
		}
		if err := os.Remove(directory); err != nil && !os.IsNotExist(err) && !isDirectoryNotEmpty(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove staging directory %s: %w", directory, err))
		}
	}
	if refreshGRUB {
		if _, err := runner.Run(ctx, "update-grub"); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove staged GRUB menu entry: %w", err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func cleanupPartialStage(files, directories []string) error {
	var cleanupErrors []error
	for _, path := range files {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove partial staged file %s: %w", path, err))
		}
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Remove(directories[index]); err != nil && !os.IsNotExist(err) && !isDirectoryNotEmpty(err) {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove partial staging directory %s: %w", directories[index], err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func isDirectoryNotEmpty(err error) bool {
	return errors.Is(err, os.ErrExist) || strings.Contains(strings.ToLower(err.Error()), "not empty")
}

func kernelVersion(kernelPath string) string {
	return strings.TrimPrefix(filepath.Base(kernelPath), "vmlinuz-")
}

func writerCmdline(input string) string {
	var result []string
	for _, field := range strings.Fields(input) {
		if strings.HasPrefix(field, "BOOT_IMAGE=") || strings.HasPrefix(field, "initrd=") || strings.HasPrefix(field, "rdinit=") || strings.HasPrefix(field, "chr.install=") {
			continue
		}
		result = append(result, field)
	}
	result = append(result, "chr.install=1")
	return strings.Join(result, " ")
}

func grubScript(ctx context.Context, runner command.Runner, stage Stage) (string, error) {
	if strings.ContainsAny(stage.Cmdline, "\n\r") {
		return "", fmt.Errorf("kernel command line contains a newline")
	}
	uuidOutput, err := runner.Run(ctx, "grub-probe", "--target=fs_uuid", stage.KernelPath)
	if err != nil {
		return "", err
	}
	uuid := strings.TrimSpace(string(uuidOutput))
	if uuid == "" || strings.ContainsAny(uuid, " \n\r\t") {
		return "", fmt.Errorf("invalid GRUB filesystem UUID")
	}
	mountOutput, err := runner.Run(ctx, "findmnt", "-n", "-o", "TARGET", "-T", stage.KernelPath)
	if err != nil {
		return "", err
	}
	mountpoint := strings.TrimSpace(string(mountOutput))
	kernelRelative, err := grubRelativePath(stage.KernelPath, mountpoint)
	if err != nil {
		return "", err
	}
	initrdRelative, err := grubRelativePath(stage.InitrdPath, mountpoint)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`#!/bin/sh
cat <<'CHR_INSTALL_GRUB_ENTRY'
if [ -s $prefix/grubenv ]; then
    load_env next_entry
fi
if [ "${next_entry}" = "chr-install-writer" ]; then
    set default="chr-install-writer"
    set next_entry=
    save_env next_entry
fi
menuentry 'CHR Install Writer' --id 'chr-install-writer' {
    search --no-floppy --fs-uuid --set=root %s
    linux %s %s
    initrd %s
}
CHR_INSTALL_GRUB_ENTRY
`, uuid, kernelRelative, stage.Cmdline, initrdRelative), nil
}

func grubRelativePath(path, mountpoint string) (string, error) {
	cleanPath := filepath.Clean(path)
	cleanMount := filepath.Clean(mountpoint)
	relative, err := filepath.Rel(cleanMount, cleanPath)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
		return "", fmt.Errorf("%s is not on boot filesystem %s", path, mountpoint)
	}
	return "/" + filepath.ToSlash(relative), nil
}
