package mikrotik

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/parhamfa/chr-install/internal/command"
)

const sectorSize = 512

type Partition struct {
	Index       int    `json:"index"`
	Type        byte   `json:"type"`
	Bootable    bool   `json:"bootable"`
	StartSector uint32 `json:"start_sector"`
	Sectors     uint32 `json:"sectors"`
	OffsetBytes int64  `json:"offset_bytes"`
	SizeBytes   int64  `json:"size_bytes"`
}

type Layout struct {
	Partitions       []Partition `json:"partitions"`
	AutorunPartition int         `json:"autorun_partition"`
}

func Inspect(path string) (Layout, error) {
	file, err := os.Open(path)
	if err != nil {
		return Layout{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Layout{}, err
	}
	sector := make([]byte, sectorSize)
	if _, err := file.ReadAt(sector, 0); err != nil {
		return Layout{}, fmt.Errorf("read MBR: %w", err)
	}
	if sector[510] != 0x55 || sector[511] != 0xaa {
		return Layout{}, fmt.Errorf("missing MBR signature")
	}
	var layout Layout
	for index := 0; index < 4; index++ {
		offset := 446 + index*16
		entry := sector[offset : offset+16]
		partitionType := entry[4]
		start := binary.LittleEndian.Uint32(entry[8:12])
		sectors := binary.LittleEndian.Uint32(entry[12:16])
		if partitionType == 0 || sectors == 0 {
			continue
		}
		if entry[0] != 0 && entry[0] != 0x80 {
			return Layout{}, fmt.Errorf("partition %d has an invalid boot flag", index+1)
		}
		partition := Partition{
			Index:       index + 1,
			Type:        partitionType,
			Bootable:    entry[0] == 0x80,
			StartSector: start,
			Sectors:     sectors,
			OffsetBytes: int64(start) * sectorSize,
			SizeBytes:   int64(sectors) * sectorSize,
		}
		if partition.OffsetBytes < sectorSize || partition.OffsetBytes+partition.SizeBytes > info.Size() {
			return Layout{}, fmt.Errorf("partition %d is outside the image", partition.Index)
		}
		layout.Partitions = append(layout.Partitions, partition)
	}
	if len(layout.Partitions) == 0 {
		return Layout{}, fmt.Errorf("image has no MBR partitions")
	}
	ordered := append([]Partition(nil), layout.Partitions...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].OffsetBytes < ordered[j].OffsetBytes })
	for index := 1; index < len(ordered); index++ {
		if ordered[index].OffsetBytes < ordered[index-1].OffsetBytes+ordered[index-1].SizeBytes {
			return Layout{}, fmt.Errorf("partitions %d and %d overlap", ordered[index-1].Index, ordered[index].Index)
		}
	}
	return layout, nil
}

func InjectAutorun(ctx context.Context, runner command.Runner, imagePath string, layout Layout, script string) (Layout, error) {
	for _, partition := range layout.Partitions {
		if partition.Type != 0x83 {
			continue
		}
		mountpoint, err := os.MkdirTemp("", "chr-install-mount-")
		if err != nil {
			return layout, err
		}
		options := fmt.Sprintf("loop,rw,offset=%d,sizelimit=%d", partition.OffsetBytes, partition.SizeBytes)
		_, mountErr := runner.Run(ctx, "mount", "-o", options, imagePath, mountpoint)
		if mountErr != nil {
			_ = os.Remove(mountpoint)
			continue
		}
		rwPath := filepath.Join(mountpoint, "rw")
		info, statErr := os.Lstat(rwPath)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_, _ = runner.Run(ctx, "umount", mountpoint)
			_ = os.Remove(mountpoint)
			continue
		}
		autorunPath := filepath.Join(rwPath, "autorun.scr")
		if existing, err := os.Lstat(autorunPath); err == nil && existing.Mode()&os.ModeSymlink != 0 {
			_, _ = runner.Run(ctx, "umount", mountpoint)
			_ = os.Remove(mountpoint)
			return layout, fmt.Errorf("autorun path is a symlink")
		}
		file, writeErr := os.OpenFile(autorunPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if writeErr == nil {
			_, writeErr = file.WriteString(strings.ReplaceAll(script, "\r\n", "\n"))
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		if file != nil {
			if closeErr := file.Close(); writeErr == nil {
				writeErr = closeErr
			}
		}
		_, unmountErr := runner.Run(ctx, "umount", mountpoint)
		_ = os.Remove(mountpoint)
		if writeErr != nil {
			return layout, writeErr
		}
		if unmountErr != nil {
			return layout, unmountErr
		}
		layout.AutorunPartition = partition.Index
		return layout, nil
	}
	return layout, fmt.Errorf("no Linux partition containing /rw was found")
}
