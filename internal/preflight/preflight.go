package preflight

import (
	"context"
	"fmt"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/disk"
	"github.com/parhamfa/chr-install/internal/mikrotik"
	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/network"
	"github.com/parhamfa/chr-install/internal/platform"
)

type ReleaseResolver interface {
	ResolveLatest(ctx context.Context) (model.Release, error)
}

func Run(ctx context.Context, runner command.Runner, prober network.Prober, resolver ReleaseResolver, root string) model.Preflight {
	report := model.Preflight{GeneratedAt: time.Now().UTC()}
	report.Host, report.Issues = platform.Detect(root)
	report.Issues = append(report.Issues, requiredToolIssues(runner)...)
	diskResult, diskIssues := disk.Detect(ctx, runner, root)
	report.Disk, report.Issues = appendResult(diskResult, diskIssues, report.Issues)
	networkResult, networkIssues := network.Detect(ctx, runner, prober, root)
	report.Network, report.Issues = appendNetwork(networkResult, networkIssues, report.Issues)
	if resolver == nil {
		resolver = mikrotik.NewClient()
	}
	release, err := resolver.ResolveLatest(ctx)
	if err != nil {
		report.Issues = append(report.Issues, model.Issue{Severity: model.SeverityBlocker, Code: "mikrotik-release", Message: err.Error()})
	} else {
		report.Release = release
		report.Issues = append(report.Issues, assessRelease(report.Host, release)...)
	}
	return report
}

func requiredToolIssues(runner command.Runner) []model.Issue {
	var issues []model.Issue
	for _, tool := range []string{"mount", "umount"} {
		if _, err := runner.LookPath(tool); err != nil {
			issues = append(issues, model.Issue{Severity: model.SeverityBlocker, Code: "required-tool", Message: fmt.Sprintf("required command %s is unavailable", tool)})
		}
	}
	return issues
}

func assessRelease(host model.Host, release model.Release) []model.Issue {
	var issues []model.Issue
	if host.Firmware == "UEFI" && !release.UEFIBoot {
		issues = append(issues, model.Issue{Severity: model.SeverityBlocker, Code: "uefi-boot", Message: fmt.Sprintf("the official CHR %s raw image has not passed native UEFI boot validation; v1 refuses to erase this UEFI-booted host", release.Version)})
	}
	if !release.Tested {
		issues = append(issues, model.Issue{Severity: model.SeverityWarning, Code: "untested-release", Message: fmt.Sprintf("RouterOS %s has not completed this installer's QEMU test matrix; its image structure will be checked before confirmation", release.Version)})
	}
	return issues
}

func appendResult(diskResult model.Disk, diskIssues []model.Issue, existing []model.Issue) (model.Disk, []model.Issue) {
	return diskResult, append(existing, diskIssues...)
}

func appendNetwork(networkResult model.NetworkPlan, networkIssues []model.Issue, existing []model.Issue) (model.NetworkPlan, []model.Issue) {
	return networkResult, append(existing, networkIssues...)
}
