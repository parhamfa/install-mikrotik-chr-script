package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
)

func TestCopyAndHashImage(t *testing.T) {
	source := bytes.Repeat([]byte("chr-install"), 1024)
	var target bytes.Buffer
	hash, err := CopyImage(bytes.NewReader(source), &target, int64(len(source)), nil)
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256(source))
	if hash != expected || !bytes.Equal(source, target.Bytes()) {
		t.Fatal("copy did not preserve image bytes")
	}
	verified, err := HashPrefix(bytes.NewReader(target.Bytes()), int64(len(source)), nil)
	if err != nil || verified != expected {
		t.Fatalf("verification failed: %s, %v", verified, err)
	}
}

func TestCopyImageRejectsShortWrite(t *testing.T) {
	source := []byte("chr-install")
	if _, err := CopyImage(bytes.NewReader(source), shortWriter{}, int64(len(source)), nil); err != io.ErrShortWrite {
		t.Fatalf("expected io.ErrShortWrite, got %v", err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) {
	return len(value) - 1, nil
}

func TestBuildInitramfsContainsPayload(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "config")
	modules := filepath.Join(directory, "modules")
	binary := filepath.Join(directory, "chr-install")
	image := filepath.Join(directory, "chr.img")
	output := filepath.Join(directory, "staged.img")
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(modules, "6.12-test"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{filepath.Join(config, "initramfs.conf"): "MODULES=most\n", binary: "BINARY", image: "IMAGE"} {
		if err := os.WriteFile(path, []byte(value), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := validManifest(image)
	runner := &initramfsFixtureRunner{}
	if err := buildInitramfs(context.Background(), runner, "6.12-test", output, binary, image, manifest, config, modules); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "BUILT INITRAMFS" || !runner.inspected {
		t.Fatalf("mkinitramfs runner was not used correctly: %q %#v", data, runner)
	}
}

type initramfsFixtureRunner struct {
	inspected bool
}

func (runner *initramfsFixtureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "mkinitramfs" || len(args) != 5 || args[0] != "-d" || args[2] != "-o" || args[4] != "6.12-test" {
		return nil, fmt.Errorf("unexpected command: %s %v", name, args)
	}
	configDir, output := args[1], args[3]
	for _, path := range []string{
		filepath.Join(configDir, "hooks", "zz-chr-install-writer"),
		filepath.Join(configDir, "scripts", "local-premount", "zz-chr-install-writer"),
		filepath.Join(configDir, "conf.d", "zz-chr-install-modules"),
		filepath.Join(configDir, "chr-install-payload", "manifest.json"),
	} {
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			return nil, fmt.Errorf("missing generated initramfs input %s: %w", path, err)
		}
		if filepath.Base(path) == "zz-chr-install-modules" && string(data) != "MODULES=most\n" {
			return nil, fmt.Errorf("unexpected modules override %q", data)
		}
	}
	runner.inspected = true
	return nil, os.WriteFile(output, []byte("BUILT INITRAMFS"), 0o600)
}

func (*initramfsFixtureRunner) LookPath(name string) (string, error) {
	return "/usr/sbin/" + name, nil
}

func TestWriterCmdline(t *testing.T) {
	got := writerCmdline("BOOT_IMAGE=/boot/vmlinuz root=/dev/sda1 ro quiet initrd=/boot/initrd chr.install=old")
	if got != "root=/dev/sda1 ro quiet chr.install=1" {
		t.Fatalf("writerCmdline() = %q", got)
	}
}

func TestManifestTimestampAcceptsRecordedRTCOffset(t *testing.T) {
	created := time.Date(2026, time.July, 21, 12, 0, 0, 0, time.UTC)
	manifest := validManifest("/chr.img")
	manifest.CreatedAt = created
	manifest.RTCOffset = -2 * 60 * 60
	if err := manifest.validateTimestamp(created.Add(2 * time.Hour)); err != nil {
		t.Fatalf("recorded RTC offset should recover a bounded clock skew: %v", err)
	}
}

func TestManifestTimestampRejectsStaleEntryWithDiagnostics(t *testing.T) {
	created := time.Date(2026, time.July, 20, 10, 0, 0, 0, time.UTC)
	manifest := validManifest("/chr.img")
	manifest.CreatedAt = created
	err := manifest.validateTimestamp(created.Add(25 * time.Hour))
	if err == nil || !strings.Contains(err.Error(), "created=2026-07-20T10:00:00Z") || !strings.Contains(err.Error(), "writer_clock=2026-07-21T11:00:00Z") {
		t.Fatalf("expected timestamp diagnostics, got %v", err)
	}
}

func validManifest(image string) Manifest {
	return Manifest{
		Schema:      manifestSchema,
		CreatedAt:   time.Now().UTC(),
		Disk:        model.DiskFingerprint{Path: "/dev/sda", KernelName: "sda", MajorMinor: "8:0", SizeBytes: 1024},
		ImagePath:   image,
		ImageSHA256: strings.Repeat("a", 64),
		ImageSize:   5,
		Release:     model.Release{Version: "7.21.5"},
		Network: model.NetworkPlan{
			InterfaceName: "ens3",
			MAC:           "02:00:00:00:00:01",
			MTU:           1500,
			IPv4:          model.IPv4Plan{Mode: "dhcp"},
		},
	}
}
