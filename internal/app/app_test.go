package app

import (
	"testing"

	"github.com/parhamfa/chr-install/internal/model"
)

func TestSameInstallTargetRequiresMethodAndFingerprint(t *testing.T) {
	before := model.Disk{
		RootBacked: true,
		Method:     model.InstallMethodKexec,
		Fingerprint: model.DiskFingerprint{
			KernelName: "vda",
			MajorMinor: "252:0",
			SizeBytes:  1024,
			Serial:     "disk-1",
			Driver:     "virtio_blk",
		},
	}
	after := before
	after.Fingerprint.KernelName = "vdb"
	after.Fingerprint.MajorMinor = "252:16"
	if !sameInstallTarget(before, after) {
		t.Fatal("a stable serial may survive a kernel-name change")
	}
	after.Method = model.InstallMethodGRUB
	if sameInstallTarget(before, after) {
		t.Fatal("an installation-method change must be rejected")
	}
	after = before
	after.Fingerprint.Serial = "disk-2"
	if sameInstallTarget(before, after) {
		t.Fatal("a target-identity change must be rejected")
	}
}
