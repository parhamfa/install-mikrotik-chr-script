package install

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/network"
)

const (
	manifestSchema       = 1
	manifestMaxAge       = 24 * time.Hour
	manifestFutureLeeway = 5 * time.Minute
	maxRTCOffset         = 24 * time.Hour
	rtcEpochPath         = "/sys/class/rtc/rtc0/since_epoch"
)

type Manifest struct {
	Schema      int                   `json:"schema"`
	CreatedAt   time.Time             `json:"created_at"`
	RTCOffset   int64                 `json:"rtc_offset_seconds,omitempty"`
	Disk        model.DiskFingerprint `json:"disk"`
	ImagePath   string                `json:"image_path"`
	ImageSHA256 string                `json:"image_sha256"`
	ImageSize   int64                 `json:"image_size"`
	Release     model.Release         `json:"release"`
	Network     model.NetworkPlan     `json:"network"`
}

func NewManifest(disk model.DiskFingerprint, imagePath, imageHash string, imageSize int64, release model.Release, network model.NetworkPlan) Manifest {
	now := time.Now().UTC()
	return Manifest{
		Schema:      manifestSchema,
		CreatedAt:   now,
		RTCOffset:   measuredRTCOffset(now, rtcEpochPath),
		Disk:        disk,
		ImagePath:   imagePath,
		ImageSHA256: imageHash,
		ImageSize:   imageSize,
		Release:     release,
		Network:     network,
	}
}

func (manifest Manifest) Validate() error {
	if manifest.Schema != manifestSchema {
		return fmt.Errorf("unsupported writer manifest schema %d", manifest.Schema)
	}
	if manifest.Disk.Path == "" || manifest.Disk.KernelName == "" || manifest.Disk.SizeBytes == 0 {
		return fmt.Errorf("writer manifest has an incomplete disk fingerprint")
	}
	if manifest.Disk.WWN == "" && manifest.Disk.Serial == "" && manifest.Disk.MajorMinor == "" {
		return fmt.Errorf("writer manifest has no stable or fallback disk identity")
	}
	if manifest.ImagePath == "" || len(manifest.ImageSHA256) != 64 || manifest.ImageSize <= 0 {
		return fmt.Errorf("writer manifest has incomplete image metadata")
	}
	if _, err := hex.DecodeString(manifest.ImageSHA256); err != nil {
		return fmt.Errorf("writer manifest has an invalid image checksum")
	}
	if uint64(manifest.ImageSize) > manifest.Disk.SizeBytes {
		return fmt.Errorf("CHR image is larger than the target disk")
	}
	if manifest.Release.Version == "" {
		return fmt.Errorf("writer manifest has no RouterOS release")
	}
	if err := network.Validate(manifest.Network); err != nil {
		return fmt.Errorf("writer manifest network plan: %w", err)
	}
	if err := manifest.validateTimestamp(time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

func (manifest Manifest) validateTimestamp(writerClock time.Time) error {
	if manifest.CreatedAt.IsZero() {
		return fmt.Errorf("writer manifest has no creation timestamp")
	}
	writerClock = writerClock.UTC()
	if timestampWithinWindow(manifest.CreatedAt, writerClock) {
		return nil
	}
	adjustedClock := writerClock
	if manifest.RTCOffset != 0 && manifest.RTCOffset >= -int64(maxRTCOffset/time.Second) && manifest.RTCOffset <= int64(maxRTCOffset/time.Second) {
		adjustedClock = writerClock.Add(time.Duration(manifest.RTCOffset) * time.Second)
		if timestampWithinWindow(manifest.CreatedAt, adjustedClock) {
			return nil
		}
	}
	return fmt.Errorf("writer manifest timestamp is outside the allowed window: created=%s writer_clock=%s adjusted_clock=%s max_age=%s future_leeway=%s", manifest.CreatedAt.Format(time.RFC3339), writerClock.Format(time.RFC3339), adjustedClock.Format(time.RFC3339), manifestMaxAge, manifestFutureLeeway)
}

func timestampWithinWindow(createdAt, current time.Time) bool {
	age := current.Sub(createdAt)
	return age >= -manifestFutureLeeway && age <= manifestMaxAge
}

func measuredRTCOffset(now time.Time, path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	rtcSeconds, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	offset := now.Unix() - rtcSeconds
	limit := int64(maxRTCOffset / time.Second)
	if offset < -limit || offset > limit {
		return 0
	}
	return offset
}

func WriteManifest(path string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func ReadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, manifest.Validate()
}
