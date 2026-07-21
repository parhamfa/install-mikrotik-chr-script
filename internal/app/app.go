package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/disk"
	"github.com/parhamfa/chr-install/internal/install"
	"github.com/parhamfa/chr-install/internal/mikrotik"
	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/network"
	"github.com/parhamfa/chr-install/internal/preflight"
	"github.com/parhamfa/chr-install/internal/report"
	"github.com/parhamfa/chr-install/internal/ui"
)

type Options struct {
	PreflightOnly bool
	Output        io.Writer
}

func Run(ctx context.Context, options Options) error {
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("chr-install must run on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run chr-install as root; preflight needs access to network and disk metadata")
	}
	runner := command.OSRunner{}
	client := mikrotik.NewClient()
	fmt.Fprintln(options.Output, "Inspecting host, disk, routes, leases, and DHCP availability…")
	reportValue := preflight.Run(ctx, runner, network.DefaultProber{}, client, "/")
	if options.PreflightOnly {
		fmt.Fprint(options.Output, report.Format(reportValue))
		if reportValue.Blocked() {
			return fmt.Errorf("preflight found blocking conditions")
		}
		return nil
	}
	if reportValue.Blocked() {
		fmt.Fprint(options.Output, report.Format(reportValue))
		return fmt.Errorf("preflight found blocking conditions")
	}
	review, err := ui.ReviewPreflight(reportValue)
	if err != nil {
		return err
	}
	workDir, err := os.MkdirTemp("/var/tmp", "chr-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)
	fmt.Fprintf(options.Output, "Downloading and validating RouterOS %s from MikroTik…\n", reportValue.Release.Version)
	prepared, err := client.Prepare(ctx, runner, reportValue.Release, review.Network, workDir)
	if err != nil {
		return err
	}
	if reportValue.Disk.RootBacked {
		required := uint64(prepared.SizeBytes) + 512*1024*1024
		if reportValue.Host.MemoryBytes < required {
			return fmt.Errorf("staged writer needs at least %d bytes of RAM before its exact initramfs can be measured; host has %d", required, reportValue.Host.MemoryBytes)
		}
	}
	if !reportValue.Release.Tested {
		if err := ui.ConfirmUntested(reportValue.Release.Version); err != nil {
			return err
		}
	}
	if err := ui.ConfirmDestruction(reportValue, review.Network); err != nil {
		return err
	}
	revalidatedDisk, revalidationIssues := disk.Detect(ctx, runner, "/")
	for _, issue := range revalidationIssues {
		if issue.Severity == model.SeverityBlocker {
			return fmt.Errorf("target revalidation failed: %s", issue.Message)
		}
	}
	if !sameInstallTarget(reportValue.Disk, revalidatedDisk) {
		return fmt.Errorf("target disk or installation method changed after review; refusing to continue")
	}
	executable, err := os.Readlink("/proc/self/exe")
	if err != nil {
		executable = filepath.Clean(os.Args[0])
	}
	manifest := install.NewManifest(reportValue.Disk.Fingerprint, prepared.Path, prepared.SHA256, prepared.SizeBytes, prepared.Release, review.Network)
	return install.StageAndBoot(ctx, runner, reportValue.Disk, prepared.Path, executable, manifest, reportValue.Host.MemoryBytes)
}

func ReadyForInstall(report model.Preflight) bool {
	return !report.Blocked()
}

func sameInstallTarget(before, after model.Disk) bool {
	return before.RootBacked == after.RootBacked && before.Method == after.Method && install.FingerprintsMatch(before.Fingerprint, after.Fingerprint)
}
