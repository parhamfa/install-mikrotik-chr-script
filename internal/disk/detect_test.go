package disk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parhamfa/chr-install/internal/model"
)

type fakeRunner struct {
	responses map[string][]byte
	paths     map[string]bool
}

func (runner fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if output, ok := runner.responses[key]; ok {
		return output, nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

func (runner fakeRunner) LookPath(name string) (string, error) {
	if runner.paths[name] {
		return "/usr/bin/" + name, nil
	}
	return "", os.ErrNotExist
}

func TestDetectSingleRootDisk(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"boot/vmlinuz-test", "boot/initrd.img-test", "sys/class/block/sda/device/driver"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		value := "fixture"
		if strings.HasSuffix(path, "/driver") {
			value = "sd\n"
		}
		if err := os.WriteFile(full, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := fakeRunner{
		paths: map[string]bool{"kexec": true, "mkinitramfs": true},
		responses: map[string][]byte{
			"findmnt -J -n -o SOURCE,FSTYPE /": []byte(`{"filesystems":[{"source":"/dev/sda1","fstype":"ext4"}]}`),
			"readlink -f /dev/sda1":            []byte("/dev/sda1\n"),
			"uname -r":                         []byte("test\n"),
			"lsblk -J -b -o NAME,KNAME,PATH,TYPE,PKNAME,SIZE,MODEL,SERIAL,WWN,TRAN,MAJ:MIN,RO,RM,MOUNTPOINTS": []byte(`{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":10737418240,"model":"QEMU DISK","serial":"disk-1","tran":"scsi","maj:min":"8:0","ro":false,"rm":false,"mountpoints":[null],"children":[{"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","pkname":"sda","size":10736369664,"maj:min":"8:1","mountpoints":["/"]}]}]}`),
		},
	}
	detected, issues := Detect(context.Background(), runner, root)
	for _, issue := range issues {
		if issue.Severity == model.SeverityBlocker {
			t.Fatalf("unexpected blocker: %#v", issue)
		}
	}
	if detected.Fingerprint.Path != "/dev/sda" || detected.Fingerprint.Serial != "disk-1" {
		t.Fatalf("unexpected disk: %#v", detected)
	}
	if detected.Method != model.InstallMethodKexec || !detected.RootBacked {
		t.Fatalf("unexpected install method: %#v", detected)
	}
}

func TestSupportedStorageDrivers(t *testing.T) {
	for _, driver := range []string{"sd", "virtio_blk", "nvme", "xen-blkfront"} {
		if !supportedStorageDriver(driver) {
			t.Fatalf("expected %s to be supported", driver)
		}
	}
	if supportedStorageDriver("mystery_controller") {
		t.Fatal("unknown storage driver must fail closed")
	}
}

func TestReadDriverWalksNVMeDeviceAncestry(t *testing.T) {
	root := t.TempDir()
	controller := filepath.Join(root, "sys", "devices", "pci0000:00", "0000:00:03.0")
	namespace := filepath.Join(controller, "nvme", "nvme0", "nvme0n1")
	driverTarget := filepath.Join(root, "sys", "bus", "pci", "drivers", "nvme")
	if err := os.MkdirAll(namespace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(driverTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(driverTarget, filepath.Join(controller, "driver")); err != nil {
		t.Fatal(err)
	}
	classPath := filepath.Join(root, "sys", "class", "block", "nvme0n1")
	if err := os.MkdirAll(classPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(namespace, filepath.Join(classPath, "device")); err != nil {
		t.Fatal(err)
	}
	if driver := readDriver(root, "nvme0n1"); driver != "nvme" {
		t.Fatalf("readDriver() = %q", driver)
	}
}

func TestRescueRefusesMultipleDisks(t *testing.T) {
	runner := fakeRunner{responses: map[string][]byte{
		"findmnt -J -n -o SOURCE,FSTYPE /": []byte(`{"filesystems":[{"source":"overlay","fstype":"overlay"}]}`),
		"lsblk -J -b -o NAME,KNAME,PATH,TYPE,PKNAME,SIZE,MODEL,SERIAL,WWN,TRAN,MAJ:MIN,RO,RM,MOUNTPOINTS": []byte(`{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":10737418240,"maj:min":"8:0","ro":false,"rm":false,"mountpoints":[null]},{"name":"sdb","kname":"sdb","path":"/dev/sdb","type":"disk","size":10737418240,"maj:min":"8:16","ro":false,"rm":false,"mountpoints":[null]}]}`),
	}}
	_, issues := Detect(context.Background(), runner, t.TempDir())
	found := false
	for _, issue := range issues {
		found = found || issue.Code == "disk-ambiguity"
	}
	if !found {
		t.Fatalf("expected disk ambiguity blocker, got %#v", issues)
	}
}
