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

const lsblkCommand = "lsblk -J -b -o NAME,KNAME,PATH,TYPE,PKNAME,SIZE,TRAN,MAJ:MIN,RO,RM,MOUNTPOINTS"

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
	for _, path := range []string{"boot/vmlinuz-test", "boot/initrd.img-test"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDiskSysfsFixture(t, root, "sda", 10737418240, "8:0", "sd", "disk-1")
	runner := fakeRunner{
		paths: map[string]bool{"kexec": true, "mkinitramfs": true, "lsinitramfs": true},
		responses: map[string][]byte{
			"findmnt -J -n -o SOURCE,FSTYPE /": []byte(`{"filesystems":[{"source":"/dev/sda1","fstype":"ext4"}]}`),
			"readlink -f /dev/sda1":            []byte("/dev/sda1\n"),
			"uname -r":                         []byte("test\n"),
			lsblkCommand:                       []byte(`{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":10737418240,"tran":"scsi","maj:min":"8:0","ro":false,"rm":false,"mountpoints":[null],"children":[{"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","pkname":"sda","size":10736369664,"maj:min":"8:1","mountpoints":["/"]}]}]}`),
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

func TestFingerprintWalksNVMeDeviceAncestry(t *testing.T) {
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
	if driver := FingerprintFromSysfs(root, "nvme0n1").Driver; driver != "nvme" {
		t.Fatalf("Driver = %q", driver)
	}
}

func TestRescueRefusesMultipleDisks(t *testing.T) {
	runner := fakeRunner{responses: map[string][]byte{
		"findmnt -J -n -o SOURCE,FSTYPE /": []byte(`{"filesystems":[{"source":"overlay","fstype":"overlay"}]}`),
		lsblkCommand:                       []byte(`{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":10737418240,"maj:min":"8:0","ro":false,"rm":false,"mountpoints":[null]},{"name":"sdb","kname":"sdb","path":"/dev/sdb","type":"disk","size":10737418240,"maj:min":"8:16","ro":false,"rm":false,"mountpoints":[null]}]}`),
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

func TestRootInstallRefusesMultipleDisksWithoutStableTargetIdentity(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"boot/vmlinuz-test", "boot/initrd.img-test"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDiskSysfsFixture(t, root, "sda", 10737418240, "8:0", "sd", "")
	runner := fakeRunner{
		paths: map[string]bool{"kexec": true, "mkinitramfs": true, "lsinitramfs": true},
		responses: map[string][]byte{
			"findmnt -J -n -o SOURCE,FSTYPE /": []byte(`{"filesystems":[{"source":"/dev/sda1","fstype":"ext4"}]}`),
			"readlink -f /dev/sda1":            []byte("/dev/sda1\n"),
			"uname -r":                         []byte("test\n"),
			lsblkCommand:                       []byte(`{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":10737418240,"tran":"scsi","maj:min":"8:0","ro":false,"rm":false,"mountpoints":[null],"children":[{"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","pkname":"sda","size":10736369664,"maj:min":"8:1","mountpoints":["/"]}]},{"name":"sdb","kname":"sdb","path":"/dev/sdb","type":"disk","size":10737418240,"tran":"scsi","maj:min":"8:16","ro":false,"rm":false,"mountpoints":[null]}]}`),
		},
	}
	_, issues := Detect(context.Background(), runner, root)
	for _, issue := range issues {
		if issue.Code == "disk-identity" && issue.Severity == model.SeverityBlocker {
			return
		}
	}
	t.Fatalf("expected stable disk identity blocker, got %#v", issues)
}

func TestDetectDoesNotAuthorizeLsblkOnlySerial(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"boot/vmlinuz-test", "boot/initrd.img-test"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeDiskSysfsFixture(t, root, "sda", 10737418240, "8:0", "sd", "")
	runner := fakeRunner{
		paths: map[string]bool{"kexec": true, "mkinitramfs": true, "lsinitramfs": true},
		responses: map[string][]byte{
			"findmnt -J -n -o SOURCE,FSTYPE /": []byte(`{"filesystems":[{"source":"/dev/sda1","fstype":"ext4"}]}`),
			"readlink -f /dev/sda1":            []byte("/dev/sda1\n"),
			"uname -r":                         []byte("test\n"),
			lsblkCommand:                       []byte(`{"blockdevices":[{"name":"sda","kname":"sda","path":"/dev/sda","type":"disk","size":10737418240,"serial":"lsblk-only","tran":"scsi","maj:min":"8:0","ro":false,"rm":false,"mountpoints":[null],"children":[{"name":"sda1","kname":"sda1","path":"/dev/sda1","type":"part","pkname":"sda","size":10736369664,"maj:min":"8:1","mountpoints":["/"]}]}]}`),
		},
	}
	detected, issues := Detect(context.Background(), runner, root)
	if detected.Fingerprint.Serial != "" || detected.Fingerprint.WWN != "" {
		t.Fatalf("lsblk-only identity was authorized: %#v", detected.Fingerprint)
	}
	for _, issue := range issues {
		if issue.Code == "disk-identity" && issue.Severity == model.SeverityWarning {
			return
		}
	}
	t.Fatalf("expected single-disk identity warning, got %#v", issues)
}

func writeDiskSysfsFixture(t *testing.T, root, name string, size uint64, majorMinor, driver, serial string) {
	t.Helper()
	base := filepath.Join(root, "sys", "class", "block", name)
	values := map[string]string{
		filepath.Join(base, "size"):             fmt.Sprintf("%d\n", size/512),
		filepath.Join(base, "dev"):              majorMinor + "\n",
		filepath.Join(base, "device", "driver"): driver + "\n",
		filepath.Join(base, "device", "type"):   "0\n",
	}
	if serial != "" {
		values[filepath.Join(base, "device", "serial")] = serial + "\n"
	}
	for path, value := range values {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInspectGRUBEnvironmentRequiresPlainExtFilesystem(t *testing.T) {
	root := t.TempDir()
	environmentPath := filepath.Join(root, "boot", "grub", "grubenv")
	runner := fakeRunner{responses: map[string][]byte{
		"grub-probe --target=fs " + environmentPath:          []byte("ext2\n"),
		"grub-probe --target=abstraction " + environmentPath: []byte("lvm\n"),
	}}
	supported, reason := inspectGRUBEnvironment(context.Background(), runner, root)
	if supported || !strings.Contains(reason, "lvm") {
		t.Fatalf("expected LVM abstraction to be rejected, got supported=%t reason=%q", supported, reason)
	}
	runner.responses["grub-probe --target=abstraction "+environmentPath] = []byte("\n")
	supported, reason = inspectGRUBEnvironment(context.Background(), runner, root)
	if !supported || reason != "" {
		t.Fatalf("expected plain ext filesystem to pass, got supported=%t reason=%q", supported, reason)
	}
}
