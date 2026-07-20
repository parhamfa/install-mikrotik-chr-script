package install

import (
	"strings"

	"github.com/parhamfa/chr-install/internal/model"
)

func fingerprintsMatch(expected, candidate model.DiskFingerprint) bool {
	if expected.SizeBytes != candidate.SizeBytes {
		return false
	}
	if strings.TrimSpace(expected.WWN) != "" {
		return strings.TrimSpace(candidate.WWN) != "" && normalizeIdentity(expected.WWN) == normalizeIdentity(candidate.WWN)
	}
	if strings.TrimSpace(expected.Serial) != "" {
		return strings.TrimSpace(candidate.Serial) != "" && normalizeIdentity(expected.Serial) == normalizeIdentity(candidate.Serial)
	}
	return expected.KernelName == candidate.KernelName && expected.MajorMinor == candidate.MajorMinor
}

func FingerprintsMatch(expected, candidate model.DiskFingerprint) bool {
	if !fingerprintsMatch(expected, candidate) {
		return false
	}
	if strings.TrimSpace(expected.Driver) != "" {
		return strings.TrimSpace(candidate.Driver) != "" && strings.EqualFold(strings.TrimSpace(expected.Driver), strings.TrimSpace(candidate.Driver))
	}
	return true
}

func normalizeIdentity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"naa.", "eui.", "0x"} {
		value = strings.TrimPrefix(value, prefix)
	}
	return strings.ReplaceAll(value, "-", "")
}
