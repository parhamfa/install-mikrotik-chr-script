package preflight

import (
	"testing"

	"github.com/parhamfa/chr-install/internal/model"
)

func TestUEFIRequiresVersionSpecificBootValidation(t *testing.T) {
	issues := assessRelease(model.Host{Firmware: "UEFI"}, model.Release{Version: "7.21.5", Tested: true})
	if !hasIssue(issues, "uefi-boot", model.SeverityBlocker) {
		t.Fatalf("expected a UEFI blocker, got %#v", issues)
	}
	issues = assessRelease(model.Host{Firmware: "UEFI"}, model.Release{Version: "future", Tested: true, UEFIBoot: true})
	if hasIssue(issues, "uefi-boot", model.SeverityBlocker) {
		t.Fatalf("validated UEFI release was blocked: %#v", issues)
	}
}

func TestUntestedReleaseIsAWarningOnBIOS(t *testing.T) {
	issues := assessRelease(model.Host{Firmware: "BIOS"}, model.Release{Version: "7.99"})
	if !hasIssue(issues, "untested-release", model.SeverityWarning) || hasIssue(issues, "untested-release", model.SeverityBlocker) {
		t.Fatalf("unexpected release assessment: %#v", issues)
	}
}

func hasIssue(issues []model.Issue, code string, severity model.Severity) bool {
	for _, issue := range issues {
		if issue.Code == code && issue.Severity == severity {
			return true
		}
	}
	return false
}
