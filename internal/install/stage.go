package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
)

type Stage struct {
	Method     model.InstallMethod
	KernelPath string
	InitrdPath string
	Cmdline    string
	GRUBScript string
}

func StageAndBoot(ctx context.Context, runner command.Runner, disk model.Disk, preparedImage, executable string, manifest Manifest) error {
	if disk.Method == model.InstallMethodDirect {
		manifest.ImagePath = preparedImage
		manifestPath := filepath.Join(filepath.Dir(preparedImage), "writer-manifest.json")
		if err := WriteManifest(manifestPath, manifest); err != nil {
			return err
		}
		return RunWriter(manifestPath, true)
	}
	stage, err := PrepareStage(ctx, runner, disk, preparedImage, executable, manifest)
	if err != nil {
		return err
	}
	_, _ = runner.Run(ctx, "sync")
	if stage.Method == model.InstallMethodKexec {
		if err := executeKexec(ctx, runner, stage); err == nil {
			return nil
		} else if !disk.GRUB {
			return err
		}
		disk.Method = model.InstallMethodGRUB
		stage, stageErr := PrepareStage(ctx, runner, disk, preparedImage, executable, manifest)
		if stageErr != nil {
			return fmt.Errorf("kexec failed and GRUB fallback could not be staged: %w", stageErr)
		}
		return executeGRUB(ctx, runner, stage)
	}
	if stage.Method == model.InstallMethodGRUB {
		return executeGRUB(ctx, runner, stage)
	}
	return fmt.Errorf("unsupported installation method %q", stage.Method)
}

func executeKexec(ctx context.Context, runner command.Runner, stage Stage) error {
	if _, err := runner.Run(ctx, "kexec", "-l", stage.KernelPath, "--initrd="+stage.InitrdPath, "--append="+stage.Cmdline); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "kexec"); err != nil {
		_, fallbackErr := runner.Run(ctx, "kexec", "-e")
		if fallbackErr != nil {
			return fmt.Errorf("systemd and direct kexec both failed: %v; %w", err, fallbackErr)
		}
	}
	return nil
}

func executeGRUB(ctx context.Context, runner command.Runner, stage Stage) error {
	if _, err := runner.Run(ctx, "update-grub"); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "grub-reboot", "chr-install-writer"); err != nil {
		return err
	}
	if _, err := runner.Run(ctx, "systemctl", "reboot"); err != nil {
		_, fallbackErr := runner.Run(ctx, "reboot")
		return fallbackErr
	}
	return nil
}

func PrepareStage(ctx context.Context, runner command.Runner, disk model.Disk, imagePath, executable string, manifest Manifest) (Stage, error) {
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
	stage := Stage{Method: disk.Method, KernelPath: disk.KernelPath, Cmdline: cmdline}
	if disk.Method == model.InstallMethodKexec {
		workDir := "/var/lib/chr-install"
		if err := os.MkdirAll(workDir, 0o700); err != nil {
			return Stage{}, err
		}
		stage.InitrdPath = filepath.Join(workDir, "initrd.img")
		_ = os.Remove(stage.InitrdPath)
		if err := BuildInitramfs(ctx, runner, kernelVersion(disk.KernelPath), stage.InitrdPath, executable, imagePath, manifest); err != nil {
			return Stage{}, err
		}
		return stage, nil
	}

	workDir := "/boot/chr-install"
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return Stage{}, err
	}
	stage.InitrdPath = filepath.Join(workDir, "initrd.img")
	_ = os.Remove(stage.InitrdPath)
	if err := BuildInitramfs(ctx, runner, kernelVersion(disk.KernelPath), stage.InitrdPath, executable, imagePath, manifest); err != nil {
		return Stage{}, err
	}
	script, err := grubScript(ctx, runner, stage)
	if err != nil {
		return Stage{}, err
	}
	stage.GRUBScript = "/etc/grub.d/42_chr_install"
	if err := os.WriteFile(stage.GRUBScript, []byte(script), 0o755); err != nil {
		return Stage{}, err
	}
	return stage, nil
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
	return fmt.Sprintf("#!/bin/sh\ncat <<'CHR_INSTALL_GRUB_ENTRY'\nmenuentry 'CHR Install Writer' --id 'chr-install-writer' {\n    search --no-floppy --fs-uuid --set=root %s\n    linux %s %s\n    initrd %s\n}\nCHR_INSTALL_GRUB_ENTRY\n", uuid, kernelRelative, stage.Cmdline, initrdRelative), nil
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
