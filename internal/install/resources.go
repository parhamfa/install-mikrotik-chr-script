package install

import (
	"context"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/parhamfa/chr-install/internal/command"
)

const writerMemorySpare = 384 * 1024 * 1024

func ensureFilesystemSpace(path string, required uint64) error {
	var statistics syscall.Statfs_t
	if err := syscall.Statfs(path, &statistics); err != nil {
		return fmt.Errorf("inspect free space at %s: %w", path, err)
	}
	if statistics.Bavail < 0 || statistics.Bsize <= 0 {
		return fmt.Errorf("filesystem at %s reported invalid free-space metadata", path)
	}
	blocks := uint64(statistics.Bavail)
	blockSize := uint64(statistics.Bsize)
	if blocks > math.MaxUint64/blockSize {
		return fmt.Errorf("filesystem at %s reported overflowing free-space metadata", path)
	}
	available := blocks * blockSize
	if available < required {
		return fmt.Errorf("%s needs %d free bytes for safe staging; only %d are available", path, required, available)
	}
	return nil
}

func validateInitramfsMemory(ctx context.Context, runner command.Runner, path string, memoryBytes uint64, imageSize int64) error {
	if memoryBytes == 0 {
		return fmt.Errorf("cannot validate staged-writer memory without installed RAM metadata")
	}
	output, err := runner.Run(ctx, "lsinitramfs", "-l", path)
	if err != nil {
		return fmt.Errorf("inspect built initramfs: %w", err)
	}
	unpackedBytes, err := parseInitramfsListing(output)
	if err != nil {
		return err
	}
	if imageSize <= 0 || unpackedBytes < uint64(imageSize) {
		return fmt.Errorf("built initramfs inventory is incomplete: found %d unpacked bytes for a %d-byte image", unpackedBytes, imageSize)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	compressedBytes := uint64(info.Size())
	if compressedBytes > math.MaxUint64-writerMemorySpare || unpackedBytes > math.MaxUint64-compressedBytes-writerMemorySpare {
		return fmt.Errorf("built initramfs memory estimate overflowed")
	}
	required := unpackedBytes + compressedBytes + writerMemorySpare
	if memoryBytes < required {
		return fmt.Errorf("built staged writer needs at least %d bytes of RAM at boot; host has %d", required, memoryBytes)
	}
	return nil
}

func parseInitramfsListing(data []byte) (uint64, error) {
	var total uint64
	regularFiles := 0
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || !strings.HasPrefix(fields[0], "-") {
			continue
		}
		size, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse lsinitramfs size in %q: %w", line, err)
		}
		if total > math.MaxUint64-size {
			return 0, fmt.Errorf("initramfs file sizes overflowed")
		}
		total += size
		regularFiles++
	}
	if regularFiles == 0 {
		return 0, fmt.Errorf("lsinitramfs returned no regular files")
	}
	return total, nil
}
