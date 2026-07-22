package disk

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/parhamfa/chr-install/internal/model"
)

func TestCraftikVPD83Regression(t *testing.T) {
	page := []byte{
		0x00, 0x83, 0x00, 0x0f,
		0x02, 0x00, 0x00, 0x0b,
		0x64, 0x72, 0x69, 0x76, 0x65, 0x2d, 0x73, 0x63, 0x73, 0x69, 0x30,
	}
	identity, ok := parseVPD83(page)
	if !ok || identity.serial != "drive-scsi0" || identity.wwn != "" {
		t.Fatalf("craftik page 0x83 identity = %#v, ok=%t", identity, ok)
	}
}

func TestVPD83IdentityKinds(t *testing.T) {
	tests := []struct {
		name       string
		descriptor []byte
		serial     string
		wwn        string
	}{
		{name: "NAA", descriptor: vpdDescriptor(vpdCodeSetBinary, vpdIDNAA, 0, []byte{0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}), wwn: "naa.6001020304050607"},
		{name: "ASCII NAA", descriptor: vpdDescriptor(vpdCodeSetASCII, vpdIDNAA, 0, []byte("NAA.6001020304050607")), wwn: "naa.6001020304050607"},
		{name: "EUI-64", descriptor: vpdDescriptor(vpdCodeSetBinary, vpdIDEUI64, 0, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}), wwn: "eui.0011223344556677"},
		{name: "T10 vendor", descriptor: vpdDescriptor(vpdCodeSetASCII, vpdIDT10Vendor, 0, []byte("QEMU    disk-01")), serial: "QEMU    disk-01"},
		{name: "vendor specific", descriptor: vpdDescriptor(vpdCodeSetASCII, vpdIDVendorSpecific, 0, []byte("drive-scsi0")), serial: "drive-scsi0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity, ok := parseVPD83(vpdPage(test.descriptor))
			if !ok || identity.serial != test.serial || identity.wwn != test.wwn {
				t.Fatalf("identity = %#v, ok=%t", identity, ok)
			}
		})
	}
}

func TestVPD83DescriptorPriority(t *testing.T) {
	page := vpdPage(
		vpdDescriptor(vpdCodeSetASCII, vpdIDVendorSpecific, 0, []byte("vendor-id")),
		vpdDescriptor(vpdCodeSetASCII, vpdIDT10Vendor, 0, []byte("T10 id")),
		vpdDescriptor(vpdCodeSetBinary, vpdIDEUI64, 0, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}),
		vpdDescriptor(vpdCodeSetBinary, vpdIDNAA, 0, []byte{0x50, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
		vpdDescriptor(vpdCodeSetBinary, vpdIDNAA, 0, []byte{0x60, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70}),
	)
	identity, ok := parseVPD83(page)
	if !ok || identity.wwn != "naa.6010203040506070" {
		t.Fatalf("priority identity = %#v, ok=%t", identity, ok)
	}
}

func TestVPD83RejectsTargetPortAndMalformedDescriptors(t *testing.T) {
	targetPort := vpdPage(vpdDescriptor(vpdCodeSetBinary, vpdIDNAA, 1, []byte{0x60, 1, 2, 3, 4, 5, 6, 7}))
	if identity, ok := parseVPD83(targetPort); ok {
		t.Fatalf("target-port descriptor was accepted: %#v", identity)
	}

	tests := map[string][]byte{
		"truncated page":       {0x00, 0x83, 0x00, 0x08, 0x02, 0x00, 0x00, 0x04, 'i', 'd'},
		"truncated descriptor": {0x00, 0x83, 0x00, 0x06, 0x02, 0x00, 0x00, 0x04, 'i', 'd'},
		"dangling header":      {0x00, 0x83, 0x00, 0x02, 0x02, 0x00},
		"zero length":          vpdPage(vpdDescriptor(vpdCodeSetASCII, vpdIDVendorSpecific, 0, nil)),
		"empty ASCII":          vpdPage(vpdDescriptor(vpdCodeSetASCII, vpdIDVendorSpecific, 0, []byte("   "))),
		"empty binary":         vpdPage(vpdDescriptor(vpdCodeSetBinary, vpdIDEUI64, 0, make([]byte, 8))),
	}
	for name, page := range tests {
		t.Run(name, func(t *testing.T) {
			if identity, ok := parseVPD83(page); ok {
				t.Fatalf("malformed or empty descriptor was accepted: %#v", identity)
			}
		})
	}
}

func TestFingerprintFromSysfsFallsBackToPage80(t *testing.T) {
	root := t.TempDir()
	writeDiskSysfsFixture(t, root, "sda", 1024*1024*1024, "8:0", "sd", "direct-serial")
	device := filepath.Join(root, "sys", "class", "block", "sda", "device")
	if err := os.WriteFile(filepath.Join(device, "vpd_pg83"), vpdPage(vpdDescriptor(vpdCodeSetBinary, vpdIDNAA, 1, []byte{0x60, 1, 2, 3, 4, 5, 6, 7})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(device, "vpd_pg80"), vpd80Page("page-80-serial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fingerprint := FingerprintFromSysfs(root, "sda"); fingerprint.Serial != "page-80-serial" {
		t.Fatalf("fingerprint = %#v", fingerprint)
	}
}

func TestFingerprintFromSysfsPrefersPage83(t *testing.T) {
	root := t.TempDir()
	writeDiskSysfsFixture(t, root, "sda", 20*1024*1024*1024, "8:0", "sd", "direct-serial")
	device := filepath.Join(root, "sys", "class", "block", "sda", "device")
	craftikPage := []byte{0x00, 0x83, 0x00, 0x0f, 0x02, 0x00, 0x00, 0x0b, 0x64, 0x72, 0x69, 0x76, 0x65, 0x2d, 0x73, 0x63, 0x73, 0x69, 0x30}
	if err := os.WriteFile(filepath.Join(device, "vpd_pg83"), craftikPage, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(device, "vpd_pg80"), vpd80Page("page-80-serial"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := FingerprintFromSysfs(root, "sda")
	if fingerprint.Serial != "drive-scsi0" || fingerprint.SizeBytes != 20*1024*1024*1024 || fingerprint.MajorMinor != "8:0" || fingerprint.Driver != "sd" {
		t.Fatalf("fingerprint = %#v", fingerprint)
	}
}

func TestFingerprintFromSysfsDirectSerials(t *testing.T) {
	tests := []struct {
		name       string
		kernelName string
		driver     string
		classFile  bool
	}{
		{name: "NVMe device serial", kernelName: "nvme0n1", driver: "nvme"},
		{name: "virtio block serial", kernelName: "vda", driver: "virtio_blk", classFile: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeDiskSysfsFixture(t, root, test.kernelName, 1024*1024*1024, "252:0", test.driver, "")
			base := filepath.Join(root, "sys", "class", "block", test.kernelName)
			serialPath := filepath.Join(base, "device", "serial")
			if test.classFile {
				serialPath = filepath.Join(base, "serial")
			}
			if err := os.WriteFile(serialPath, []byte("direct-id\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if fingerprint := FingerprintFromSysfs(root, test.kernelName); fingerprint.Serial != "direct-id" {
				t.Fatalf("fingerprint = %#v", fingerprint)
			}
		})
	}
}

func TestSingleDiskFallbackAndStableIdentitySelection(t *testing.T) {
	fallback := model.DiskFingerprint{KernelName: "vda", MajorMinor: "252:0", SizeBytes: 1024, Driver: "virtio_blk"}
	candidate := fallback
	candidate.Path = "/dev/vda"
	selected, err := SelectAuthorizedFingerprint(fallback, []model.DiskFingerprint{candidate})
	if err != nil || selected.Path != "/dev/vda" {
		t.Fatalf("single-disk fallback failed: selected=%#v err=%v", selected, err)
	}
	if _, err := SelectAuthorizedFingerprint(fallback, []model.DiskFingerprint{candidate, {Path: "/dev/vdb", KernelName: "vdb", MajorMinor: "252:16", SizeBytes: 1024, Driver: "virtio_blk"}}); err == nil || !strings.Contains(err.Error(), "exactly one physical disk") {
		t.Fatalf("multi-disk fallback was not blocked: %v", err)
	}

	stable := fallback
	stable.Serial = "Disk-01"
	renumbered := model.DiskFingerprint{Path: "/dev/vdb", KernelName: "vdb", MajorMinor: "252:16", SizeBytes: 1024, Serial: "disk01", Driver: "virtio_blk"}
	if selected, err := SelectAuthorizedFingerprint(stable, []model.DiskFingerprint{candidate, renumbered}); err != nil || selected.Path != "/dev/vdb" {
		t.Fatalf("stable identity did not select the renumbered disk: selected=%#v err=%v", selected, err)
	}
	if _, err := SelectAuthorizedFingerprint(stable, []model.DiskFingerprint{candidate}); err == nil {
		t.Fatal("fallback replaced a stable identity that disappeared")
	}
	changed := renumbered
	changed.Serial = "different"
	if FingerprintsMatch(stable, changed) {
		t.Fatal("changed stable identity matched")
	}
	changed = renumbered
	changed.Driver = "nvme"
	if FingerprintsMatch(stable, changed) {
		t.Fatal("changed storage driver matched")
	}
}

func vpdDescriptor(codeSet, idType, association int, payload []byte) []byte {
	descriptor := make([]byte, 4+len(payload))
	descriptor[0] = byte(codeSet)
	descriptor[1] = byte((association << 4) | idType)
	descriptor[3] = byte(len(payload))
	copy(descriptor[4:], payload)
	return descriptor
}

func vpdPage(descriptors ...[]byte) []byte {
	length := 0
	for _, descriptor := range descriptors {
		length += len(descriptor)
	}
	page := make([]byte, 4, 4+length)
	page[1] = 0x83
	binary.BigEndian.PutUint16(page[2:4], uint16(length))
	for _, descriptor := range descriptors {
		page = append(page, descriptor...)
	}
	return page
}

func vpd80Page(serial string) []byte {
	page := make([]byte, 4+len(serial))
	page[1] = 0x80
	binary.BigEndian.PutUint16(page[2:4], uint16(len(serial)))
	copy(page[4:], serial)
	return page
}
