package install

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
)

func driverFromSysfsDevice(devicePath string) string {
	current, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		return ""
	}
	for depth := 0; depth < 16; depth++ {
		if resolved, err := filepath.EvalSymlinks(filepath.Join(current, "driver")); err == nil && filepath.Base(resolved) != "driver" {
			return filepath.Base(resolved)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return ""
}

func readSCSIVPDSerial(base string) string {
	data, err := os.ReadFile(filepath.Join(base, "device", "vpd_pg80"))
	if err != nil || len(data) < 4 || data[1] != 0x80 {
		return ""
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length == 0 || length > len(data)-4 {
		return ""
	}
	return strings.TrimSpace(string(data[4 : 4+length]))
}
