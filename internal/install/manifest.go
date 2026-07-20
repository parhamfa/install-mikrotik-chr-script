package install

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/network"
)

const manifestSchema = 1

type Manifest struct {
	Schema      int                   `json:"schema"`
	CreatedAt   time.Time             `json:"created_at"`
	Disk        model.DiskFingerprint `json:"disk"`
	ImagePath   string                `json:"image_path"`
	ImageSHA256 string                `json:"image_sha256"`
	ImageSize   int64                 `json:"image_size"`
	Release     model.Release         `json:"release"`
	Network     model.NetworkPlan     `json:"network"`
}

func NewManifest(disk model.DiskFingerprint, imagePath, imageHash string, imageSize int64, release model.Release, network model.NetworkPlan) Manifest {
	return Manifest{
		Schema:      manifestSchema,
		CreatedAt:   time.Now().UTC(),
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
	if manifest.CreatedAt.IsZero() || time.Since(manifest.CreatedAt) > 24*time.Hour || time.Until(manifest.CreatedAt) > 5*time.Minute {
		return fmt.Errorf("writer manifest is stale or has an invalid timestamp")
	}
	return nil
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
