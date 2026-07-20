package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	values := ParseOSRelease("# comment\nID=ubuntu\nVERSION_ID=\"24.04\"\nNAME='Ubuntu'\n")
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != "24.04" || values["NAME"] != "Ubuntu" {
		t.Fatalf("unexpected os-release values: %#v", values)
	}
}

func TestParseMemoryBytes(t *testing.T) {
	if got := ParseMemoryBytes("MemTotal:        1048576 kB\nMemFree: 1 kB\n"); got != 1024*1024*1024 {
		t.Fatalf("ParseMemoryBytes() = %d", got)
	}
}

func TestDetectConsole(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "proc", "cmdline")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("root=/dev/vda1 console=tty0 console=ttyS0,115200n8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := DetectConsole(root); got != "ttyS0" {
		t.Fatalf("DetectConsole() = %q", got)
	}
}
