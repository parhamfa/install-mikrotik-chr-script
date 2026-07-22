package disk

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/parhamfa/chr-install/internal/model"
)

const (
	vpdCodeSetBinary = 1
	vpdCodeSetASCII  = 2

	vpdIDVendorSpecific = 0
	vpdIDT10Vendor      = 1
	vpdIDEUI64          = 2
	vpdIDNAA            = 3
)

type vpdIdentity struct {
	serial string
	wwn    string
	rank   int
}

// FingerprintFromSysfs constructs the identity that remains observable in the
// initramfs after the machine reboots. Callers may add topology-only fields,
// such as Transport, after collection.
func FingerprintFromSysfs(root, kernelName string) model.DiskFingerprint {
	if root == "" {
		root = "/"
	}
	base := filepath.Join(root, "sys", "class", "block", kernelName)
	sectors, _ := strconv.ParseUint(readTrim(filepath.Join(base, "size")), 10, 64)
	fingerprint := model.DiskFingerprint{
		Path:       "/dev/" + kernelName,
		KernelName: kernelName,
		MajorMinor: readTrim(filepath.Join(base, "dev")),
		Model:      readIdentityText(filepath.Join(base, "device", "model")),
		Driver:     driverFromSysfsDevice(filepath.Join(base, "device")),
	}
	if sectors <= ^uint64(0)/512 {
		fingerprint.SizeBytes = sectors * 512
	}
	// Regular files stand in for sysfs driver links in unit-test fixtures.
	if fingerprint.Driver == "" {
		fingerprint.Driver = readIdentityText(filepath.Join(base, "device", "driver"))
	}

	if page, err := os.ReadFile(filepath.Join(base, "device", "vpd_pg83")); err == nil {
		if identity, ok := parseVPD83(page); ok {
			fingerprint.Serial = identity.serial
			fingerprint.WWN = identity.wwn
			return fingerprint
		}
	}

	for _, path := range []string{filepath.Join(base, "wwid"), filepath.Join(base, "device", "wwid")} {
		if value, ok := canonicalWWN(readIdentityText(path)); ok {
			fingerprint.WWN = value
			return fingerprint
		}
	}
	if page, err := os.ReadFile(filepath.Join(base, "device", "vpd_pg80")); err == nil {
		if value, ok := parseVPD80(page); ok {
			fingerprint.Serial = value
			return fingerprint
		}
	}
	for _, path := range []string{filepath.Join(base, "device", "serial"), filepath.Join(base, "serial")} {
		if value := readIdentityText(path); value != "" {
			fingerprint.Serial = value
			return fingerprint
		}
	}
	return fingerprint
}

// SysfsDisks returns physical, whole-disk devices visible to the rebooted
// writer. Pseudo block devices and SCSI devices that are not direct-access
// disks are excluded.
func SysfsDisks(root string) ([]model.DiskFingerprint, error) {
	if root == "" {
		root = "/"
	}
	classPath := filepath.Join(root, "sys", "class", "block")
	entries, err := os.ReadDir(classPath)
	if err != nil {
		return nil, err
	}
	var fingerprints []model.DiskFingerprint
	for _, entry := range entries {
		base := filepath.Join(classPath, entry.Name())
		if _, err := os.Stat(filepath.Join(base, "partition")); err == nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
			continue
		}
		// SCSI peripheral type 0 is a direct-access disk; type 5, for
		// example, is an optical drive. Non-SCSI disks do not expose type.
		if deviceType := readTrim(filepath.Join(base, "device", "type")); deviceType != "" && deviceType != "0" {
			continue
		}
		fingerprint := FingerprintFromSysfs(root, entry.Name())
		if fingerprint.SizeBytes == 0 {
			continue
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	sort.Slice(fingerprints, func(i, j int) bool {
		return fingerprints[i].KernelName < fingerprints[j].KernelName
	})
	return fingerprints, nil
}

// SelectAuthorizedFingerprint applies the stable-identity or single-disk
// fallback policy and returns the sole authorized disk.
func SelectAuthorizedFingerprint(expected model.DiskFingerprint, candidates []model.DiskFingerprint) (model.DiskFingerprint, error) {
	if !hasStableIdentity(expected) && len(candidates) != 1 {
		return model.DiskFingerprint{}, fmt.Errorf("fallback disk identity requires exactly one physical disk; observed %d", len(candidates))
	}
	var matches []model.DiskFingerprint
	for _, candidate := range candidates {
		if FingerprintsMatch(expected, candidate) {
			matches = append(matches, candidate)
		}
	}
	if len(matches) != 1 {
		return model.DiskFingerprint{}, fmt.Errorf("disk fingerprint matched %d devices; expected exactly one", len(matches))
	}
	return matches[0], nil
}

func FingerprintsMatch(expected, candidate model.DiskFingerprint) bool {
	if expected.SizeBytes == 0 || expected.SizeBytes != candidate.SizeBytes {
		return false
	}
	if strings.TrimSpace(expected.WWN) != "" {
		if strings.TrimSpace(candidate.WWN) == "" || normalizeIdentity(expected.WWN) != normalizeIdentity(candidate.WWN) {
			return false
		}
	} else if strings.TrimSpace(expected.Serial) != "" {
		if strings.TrimSpace(candidate.Serial) == "" || normalizeIdentity(expected.Serial) != normalizeIdentity(candidate.Serial) {
			return false
		}
	} else {
		if expected.KernelName == "" || expected.MajorMinor == "" || expected.Driver == "" {
			return false
		}
		if expected.KernelName != candidate.KernelName || expected.MajorMinor != candidate.MajorMinor {
			return false
		}
	}
	if strings.TrimSpace(expected.Driver) != "" {
		return strings.TrimSpace(candidate.Driver) != "" && strings.EqualFold(strings.TrimSpace(expected.Driver), strings.TrimSpace(candidate.Driver))
	}
	return true
}

func hasStableIdentity(fingerprint model.DiskFingerprint) bool {
	return strings.TrimSpace(fingerprint.WWN) != "" || strings.TrimSpace(fingerprint.Serial) != ""
}

func normalizeIdentity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"naa.", "eui.", "0x"} {
		value = strings.TrimPrefix(value, prefix)
	}
	return strings.ReplaceAll(value, "-", "")
}

func parseVPD83(data []byte) (vpdIdentity, bool) {
	if len(data) < 4 || data[1] != 0x83 {
		return vpdIdentity{}, false
	}
	pageLength := int(binary.BigEndian.Uint16(data[2:4]))
	if pageLength == 0 || pageLength > len(data)-4 {
		return vpdIdentity{}, false
	}
	end := 4 + pageLength
	identities := make([]vpdIdentity, 0, 4)
	for offset := 4; offset < end; {
		if end-offset < 4 {
			return vpdIdentity{}, false
		}
		length := int(data[offset+3])
		next := offset + 4 + length
		if next > end {
			return vpdIdentity{}, false
		}
		if length > 0 {
			association := (data[offset+1] >> 4) & 0x3
			if association == 0 {
				if identity, ok := descriptorIdentity(data[offset:next]); ok {
					identities = append(identities, identity)
				}
			}
		}
		offset = next
	}
	if len(identities) == 0 {
		return vpdIdentity{}, false
	}
	sort.SliceStable(identities, func(i, j int) bool { return identities[i].rank < identities[j].rank })
	return identities[0], true
}

func descriptorIdentity(descriptor []byte) (vpdIdentity, bool) {
	if len(descriptor) < 5 || int(descriptor[3])+4 != len(descriptor) {
		return vpdIdentity{}, false
	}
	codeSet := int(descriptor[0] & 0x0f)
	idType := int(descriptor[1] & 0x0f)
	if codeSet != vpdCodeSetBinary && codeSet != vpdCodeSetASCII {
		return vpdIdentity{}, false
	}
	if idType < vpdIDVendorSpecific || idType > vpdIDNAA {
		return vpdIdentity{}, false
	}
	payload := descriptor[4:]
	if idType == vpdIDNAA || idType == vpdIDEUI64 {
		prefix := "naa."
		baseRank := 0
		if idType == vpdIDEUI64 {
			prefix = "eui."
			baseRank = 6
		}
		hexValue, naaType, ok := descriptorHex(payload, codeSet)
		if !ok {
			return vpdIdentity{}, false
		}
		rank := baseRank
		if idType == vpdIDNAA {
			switch naaType {
			case 6:
				rank = 0
			case 5:
				rank = 2
			default:
				rank = 4
			}
		}
		if codeSet == vpdCodeSetASCII {
			rank++
		}
		return vpdIdentity{wwn: prefix + hexValue, rank: rank}, true
	}

	baseRank := 8
	label := "t10"
	if idType == vpdIDVendorSpecific {
		baseRank = 10
		label = "vendor"
	}
	if codeSet == vpdCodeSetASCII {
		value, ok := textIdentifier(payload)
		if !ok {
			return vpdIdentity{}, false
		}
		return vpdIdentity{serial: value, rank: baseRank + 1}, true
	}
	if allZero(payload) {
		return vpdIdentity{}, false
	}
	return vpdIdentity{serial: "vpd83-" + label + "-" + hex.EncodeToString(payload), rank: baseRank}, true
}

func descriptorHex(payload []byte, codeSet int) (string, int, bool) {
	var value []byte
	if codeSet == vpdCodeSetBinary {
		value = append([]byte(nil), payload...)
	} else {
		text, ok := textIdentifier(payload)
		if !ok {
			return "", 0, false
		}
		lower := strings.ToLower(text)
		for _, prefix := range []string{"naa.", "eui.", "0x"} {
			lower = strings.TrimPrefix(lower, prefix)
		}
		lower = strings.NewReplacer("-", "", ":", "", " ", "").Replace(lower)
		decoded, err := hex.DecodeString(lower)
		if err != nil {
			return "", 0, false
		}
		value = decoded
	}
	if len(value) == 0 || allZero(value) {
		return "", 0, false
	}
	return hex.EncodeToString(value), int(value[0] >> 4), true
}

func parseVPD80(data []byte) (string, bool) {
	if len(data) < 4 || data[1] != 0x80 {
		return "", false
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	if length == 0 || length > len(data)-4 {
		return "", false
	}
	return textIdentifier(data[4 : 4+length])
}

func canonicalWWN(value string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(value))
	prefix := ""
	for _, candidate := range []string{"naa.", "eui.", "0x"} {
		if strings.HasPrefix(lower, candidate) {
			prefix = candidate
			lower = strings.TrimPrefix(lower, candidate)
			break
		}
	}
	if prefix == "" {
		return "", false
	}
	lower = strings.NewReplacer("-", "", ":", "", " ", "").Replace(lower)
	decoded, err := hex.DecodeString(lower)
	if err != nil || len(decoded) == 0 || allZero(decoded) {
		return "", false
	}
	return prefix + hex.EncodeToString(decoded), true
}

func readTrim(path string) string {
	data, _ := os.ReadFile(path)
	return strings.TrimSpace(string(data))
}

func readIdentityText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	value, _ := textIdentifier(data)
	return value
}

func textIdentifier(data []byte) (string, bool) {
	value := strings.Trim(string(data), "\x00 \t\r\n")
	if value == "" || !utf8.ValidString(value) {
		return "", false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", false
		}
	}
	return value, true
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

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
