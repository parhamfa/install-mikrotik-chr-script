package install

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/parhamfa/chr-install/internal/command"
)

func BuildInitramfs(ctx context.Context, runner command.Runner, kernelVersion, outputPath, executable, imagePath string, manifest Manifest) error {
	return buildInitramfs(ctx, runner, kernelVersion, outputPath, executable, imagePath, manifest, "/etc/initramfs-tools", "/lib/modules")
}

func buildInitramfs(ctx context.Context, runner command.Runner, kernelVersion, outputPath, executable, imagePath string, manifest Manifest, configSource, modulesRoot string) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	kernelVersion = strings.TrimSpace(kernelVersion)
	if kernelVersion == "" || strings.ContainsAny(kernelVersion, "/\\\r\n\t") {
		return fmt.Errorf("invalid kernel version %q", kernelVersion)
	}
	if info, err := os.Stat(filepath.Join(modulesRoot, kernelVersion)); err != nil || !info.IsDir() {
		return fmt.Errorf("kernel modules for %s are unavailable", kernelVersion)
	}
	for _, path := range []string{executable, imagePath} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("initramfs payload %s is not a regular file", path)
		}
	}
	if _, err := os.Lstat(outputPath); err == nil {
		return fmt.Errorf("initramfs output already exists: %s", outputPath)
	} else if !os.IsNotExist(err) {
		return err
	}
	configDir, err := os.MkdirTemp(filepath.Dir(outputPath), ".chr-install-initramfs-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(configDir)
	if err := copyTree(configSource, configDir); err != nil {
		return fmt.Errorf("copy initramfs configuration: %w", err)
	}
	for _, path := range []string{filepath.Join(configDir, "hooks"), filepath.Join(configDir, "scripts", "local-premount"), filepath.Join(configDir, "chr-install-payload")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	}

	manifest.ImagePath = "/chr-install/chr.img"
	manifestPath := filepath.Join(configDir, "chr-install-payload", "manifest.json")
	if err := WriteManifest(manifestPath, manifest); err != nil {
		return err
	}
	hook := fmt.Sprintf(`#!/bin/sh
PREREQ=""
prereqs() { echo "$PREREQ"; }
case "${1:-}" in prereqs) prereqs; exit 0 ;; esac
set -eu
mkdir -p "$DESTDIR/chr-install"
cp -p %s "$DESTDIR/chr-install/chr-install"
cp -p %s "$DESTDIR/chr-install/chr.img"
cp -p %s "$DESTDIR/chr-install/manifest.json"
chmod 0700 "$DESTDIR/chr-install/chr-install"
chmod 0600 "$DESTDIR/chr-install/chr.img" "$DESTDIR/chr-install/manifest.json"
`, shellQuote(executable), shellQuote(imagePath), shellQuote(manifestPath))
	if err := writeExclusive(filepath.Join(configDir, "hooks", "zz-chr-install-writer"), []byte(hook), 0o700); err != nil {
		return err
	}
	premount := []byte("#!/bin/sh\nPREREQ=\"\"\nprereqs() { echo \"$PREREQ\"; }\ncase \"${1:-}\" in prereqs) prereqs; exit 0 ;; esac\ncmdline=\"\"\nIFS= read -r cmdline </proc/cmdline || true\ncase \" $cmdline \" in\n  *\" chr.install=1 \"*) exec /chr-install/chr-install --internal-writer /chr-install/manifest.json ;;\nesac\nexit 0\n")
	if err := writeExclusive(filepath.Join(configDir, "scripts", "local-premount", "zz-chr-install-writer"), premount, 0o700); err != nil {
		return err
	}

	if _, err := runner.Run(ctx, "mkinitramfs", "-m", "most", "-d", configDir, "-o", outputPath, kernelVersion); err != nil {
		_ = os.Remove(outputPath)
		return err
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		_ = os.Remove(outputPath)
		return fmt.Errorf("mkinitramfs did not create a regular non-empty image")
	}
	return nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

func copyTree(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	switch {
	case info.IsDir():
		if err := os.MkdirAll(destination, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyTree(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		input, err := os.Open(source)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(source)
		if err != nil {
			return err
		}
		return os.Symlink(target, destination)
	default:
		return fmt.Errorf("unsupported initramfs configuration file %s", source)
	}
}
