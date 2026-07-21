package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parhamfa/chr-install/internal/model"
)

type recordingRunner struct {
	outputs map[string][]byte
	errors  map[string]error
	calls   []string
}

func (runner *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	runner.calls = append(runner.calls, key)
	if err := runner.errors[key]; err != nil {
		return nil, err
	}
	return runner.outputs[key], nil
}

func (*recordingRunner) LookPath(name string) (string, error) {
	return "/usr/bin/" + name, nil
}

func (runner *recordingRunner) countCall(expected string) int {
	count := 0
	for _, call := range runner.calls {
		if call == expected {
			count++
		}
	}
	return count
}

func TestExecuteKexecUnloadsFailedImage(t *testing.T) {
	directory := t.TempDir()
	initrdPath := filepath.Join(directory, "initrd.img")
	if err := os.WriteFile(initrdPath, []byte("initrd"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{errors: map[string]error{
		"systemctl kexec": errors.New("systemd failed"),
		"kexec -e":        errors.New("execution failed"),
	}}
	stage := Stage{KernelPath: "/boot/vmlinuz", InitrdPath: initrdPath, Cmdline: "chr.install=1", BuildDir: directory, StageDir: directory}
	if err := executeKexec(context.Background(), runner, stage); err == nil {
		t.Fatal("expected kexec execution failure")
	}
	if runner.countCall("kexec -u") != 1 {
		t.Fatalf("failed image was not unloaded: %#v", runner.calls)
	}
	if _, err := os.Stat(initrdPath); !os.IsNotExist(err) {
		t.Fatalf("loaded kexec initramfs was not unlinked: %v", err)
	}
}

func TestExecuteGRUBFailureDisarmsAndCleansStage(t *testing.T) {
	directory := t.TempDir()
	stageDir := filepath.Join(directory, "stage")
	buildDir := filepath.Join(directory, "build")
	for _, path := range []string{stageDir, buildDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stage := Stage{
		Method:         model.InstallMethodGRUB,
		InitrdPath:     filepath.Join(stageDir, "initrd.img"),
		GRUBScript:     filepath.Join(stageDir, "42_chr_install"),
		GRUBConfigPath: filepath.Join(directory, "grub.cfg"),
		GRUBEnvPath:    filepath.Join(directory, "grubenv"),
		BuildDir:       buildDir,
		StageDir:       stageDir,
	}
	for _, path := range []string{stage.InitrdPath, stage.GRUBScript, stage.GRUBEnvPath} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configuration := "load_env next_entry\nif [ \"${next_entry}\" = \"chr-install-writer\" ]; then\n set default=\"chr-install-writer\"\n set next_entry=\n save_env next_entry\nfi\nmenuentry 'CHR Install Writer' --id 'chr-install-writer' {}\n"
	if err := os.WriteFile(stage.GRUBConfigPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{
		outputs: map[string][]byte{
			"grub-probe --target=fs " + stage.GRUBEnvPath:          []byte("ext2\n"),
			"grub-probe --target=abstraction " + stage.GRUBEnvPath: []byte("\n"),
			"grub-editenv " + stage.GRUBEnvPath + " list":          []byte("next_entry=chr-install-writer\n"),
		},
		errors: map[string]error{
			"systemctl reboot": errors.New("systemd reboot failed"),
			"reboot":           errors.New("reboot failed"),
		},
	}
	if err := executeGRUB(context.Background(), runner, stage); err == nil {
		t.Fatal("expected reboot failure")
	}
	if runner.countCall("grub-editenv "+stage.GRUBEnvPath+" unset next_entry") != 1 {
		t.Fatalf("pending GRUB entry was not cleared: %#v", runner.calls)
	}
	if runner.countCall("update-grub") != 2 {
		t.Fatalf("GRUB configuration was not refreshed during cleanup: %#v", runner.calls)
	}
	for _, path := range []string{stage.InitrdPath, stage.GRUBScript, stageDir, buildDir} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("staging residue remains at %s: %v", path, err)
		}
	}
}

func TestValidateGRUBStorageRejectsAbstraction(t *testing.T) {
	runner := &recordingRunner{outputs: map[string][]byte{
		"grub-probe --target=fs /boot/grub/grubenv":          []byte("ext2\n"),
		"grub-probe --target=abstraction /boot/grub/grubenv": []byte("lvm\n"),
	}}
	err := validateGRUBStorage(context.Background(), runner, "/boot/grub/grubenv")
	if err == nil || !strings.Contains(err.Error(), "lvm") {
		t.Fatalf("expected LVM-backed GRUB environment to be rejected, got %v", err)
	}
}

func TestValidateInitramfsMemoryUsesUnpackedInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initrd.img")
	if err := os.WriteFile(path, []byte("compressed"), 0o600); err != nil {
		t.Fatal(err)
	}
	listing := []byte("-rw------- 1 root root 100 Jul 21 12:00 chr.img\n-rwx------ 1 root root 23 Jul 21 12:00 chr-install\n")
	runner := &recordingRunner{outputs: map[string][]byte{"lsinitramfs -l " + path: listing}}
	required := uint64(123+len("compressed")) + writerMemorySpare
	if err := validateInitramfsMemory(context.Background(), runner, path, required, 100); err != nil {
		t.Fatal(err)
	}
	if err := validateInitramfsMemory(context.Background(), runner, path, required-1, 100); err == nil {
		t.Fatal("expected exact unpacked-memory shortfall to fail")
	}
	if total, err := parseInitramfsListing(listing); err != nil || total != 123 {
		t.Fatalf("unexpected listing total: %d, %v", total, err)
	}
}

func TestValidateGRUBConfigurationRequiresOneShotLogic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grub.cfg")
	if err := os.WriteFile(path, []byte("menuentry writer --id chr-install-writer {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateGRUBConfiguration(path); err == nil {
		t.Fatal("configuration without next_entry handling must fail")
	}
	configuration := fmt.Sprint(
		"load_env next_entry\n",
		"if [ \"${next_entry}\" = \"chr-install-writer\" ]; then\n",
		"set default=\"chr-install-writer\"\n",
		"set next_entry=\n",
		"save_env next_entry\n",
		"menuentry 'CHR Install Writer' --id 'chr-install-writer' {}\n",
	)
	if err := os.WriteFile(path, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateGRUBConfiguration(path); err != nil {
		t.Fatal(err)
	}
}

func TestGRUBScriptProvidesIndependentOneShotHandling(t *testing.T) {
	directory := t.TempDir()
	kernelPath := filepath.Join(directory, "vmlinuz")
	initrdPath := filepath.Join(directory, "initrd.img")
	stage := Stage{KernelPath: kernelPath, InitrdPath: initrdPath, Cmdline: "console=ttyS0 chr.install=1"}
	runner := &recordingRunner{outputs: map[string][]byte{
		"grub-probe --target=fs_uuid " + kernelPath: []byte("test-uuid\n"),
		"findmnt -n -o TARGET -T " + kernelPath:     []byte(directory + "\n"),
	}}
	script, err := grubScript(context.Background(), runner, stage)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"load_env next_entry", `set default="chr-install-writer"`, "set next_entry=", "save_env next_entry"} {
		if !strings.Contains(script, required) {
			t.Fatalf("generated GRUB script lacks %q:\n%s", required, script)
		}
	}
}
