package mikrotik

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/network"
)

const (
	defaultUpgradeURL  = "https://upgrade.mikrotik.com/routeros/NEWESTa7.long-term"
	defaultDownloadURL = "https://download.mikrotik.com/routeros"
	maxMetadataBytes   = 64 * 1024
	maxArchiveBytes    = 1024 * 1024 * 1024
	maxImageBytes      = 4 * 1024 * 1024 * 1024
)

var versionPattern = regexp.MustCompile(`^7\.[0-9]+(?:\.[0-9]+)?$`)

type testedRelease struct {
	BIOS bool
	UEFI bool
}

// Versions are added only after image injection and real CHR boot testing. The
// official 7.21.5 raw image boots with legacy BIOS but has no EFI boot partition
// and falls through to the OVMF shell.
var testedVersions = map[string]testedRelease{
	"7.21.5": {BIOS: true, UEFI: false},
}

type Client struct {
	HTTP         *http.Client
	UpgradeURL   string
	DownloadBase string
}

type PreparedImage struct {
	Path          string
	SizeBytes     int64
	SHA256        string
	SourceSHA256  string
	Release       model.Release
	Layout        Layout
	AutorunScript string
}

func NewClient() *Client {
	return &Client{
		HTTP:         &http.Client{Timeout: 15 * time.Minute},
		UpgradeURL:   defaultUpgradeURL,
		DownloadBase: defaultDownloadURL,
	}
}

func (client *Client) ResolveLatest(ctx context.Context) (model.Release, error) {
	body, err := client.getSmall(ctx, client.UpgradeURL)
	if err != nil {
		return model.Release{}, fmt.Errorf("resolve latest long-term release: %w", err)
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 || !versionPattern.MatchString(fields[0]) {
		return model.Release{}, fmt.Errorf("MikroTik returned an invalid long-term version")
	}
	version := fields[0]
	support := testedVersions[version]
	base := strings.TrimRight(client.DownloadBase, "/") + "/" + version + "/chr-" + version + ".img.zip"
	release := model.Release{
		Version:       version,
		ImageURL:      base,
		ChecksumURL:   base + ".sha256",
		Tested:        support.BIOS,
		UEFIBoot:      support.UEFI,
		Compatibility: "pending structural validation",
	}
	checksum, err := client.fetchChecksum(ctx, release.ChecksumURL)
	if err != nil {
		return model.Release{}, err
	}
	release.Checksum = checksum
	return release, nil
}

func (client *Client) Prepare(ctx context.Context, runner command.Runner, release model.Release, plan model.NetworkPlan, workDir string) (PreparedImage, error) {
	if err := network.Validate(plan); err != nil {
		return PreparedImage{}, err
	}
	if release.Version == "" || release.ImageURL == "" || release.Checksum == "" {
		return PreparedImage{}, fmt.Errorf("release metadata is incomplete")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return PreparedImage{}, err
	}
	archivePath := filepath.Join(workDir, "chr-"+release.Version+".img.zip")
	if err := client.download(ctx, release.ImageURL, archivePath, maxArchiveBytes); err != nil {
		return PreparedImage{}, fmt.Errorf("download official CHR archive: %w", err)
	}
	archiveHash, _, err := HashFile(archivePath)
	if err != nil {
		return PreparedImage{}, fmt.Errorf("hash official CHR archive: %w", err)
	}
	if !strings.EqualFold(archiveHash, release.Checksum) {
		return PreparedImage{}, fmt.Errorf("official archive checksum mismatch: expected %s, received %s", release.Checksum, archiveHash)
	}
	imagePath := filepath.Join(workDir, "chr-"+release.Version+".img")
	if err := extractImage(archivePath, imagePath); err != nil {
		return PreparedImage{}, fmt.Errorf("extract official CHR archive: %w", err)
	}
	layout, err := Inspect(imagePath)
	if err != nil {
		return PreparedImage{}, fmt.Errorf("CHR image is structurally incompatible: %w", err)
	}
	script, err := network.RouterOSScript(plan)
	if err != nil {
		return PreparedImage{}, err
	}
	layout, err = InjectAutorun(ctx, runner, imagePath, layout, script)
	if err != nil {
		return PreparedImage{}, fmt.Errorf("CHR image is structurally incompatible: %w", err)
	}
	imageHash, imageSize, err := HashFile(imagePath)
	if err != nil {
		return PreparedImage{}, fmt.Errorf("hash prepared CHR image: %w", err)
	}
	release.Compatibility = "structure validated"
	return PreparedImage{
		Path:          imagePath,
		SizeBytes:     imageSize,
		SHA256:        imageHash,
		SourceSHA256:  archiveHash,
		Release:       release,
		Layout:        layout,
		AutorunScript: script,
	}, nil
}

func (client *Client) fetchChecksum(ctx context.Context, url string) (string, error) {
	body, err := client.getSmall(ctx, url)
	if err != nil {
		return "", fmt.Errorf("download official checksum: %w", err)
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 || len(fields[0]) != sha256.Size*2 {
		return "", fmt.Errorf("official checksum response is invalid")
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return "", fmt.Errorf("official checksum response is invalid")
	}
	return strings.ToLower(fields[0]), nil
}

func (client *Client) getSmall(ctx context.Context, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %s", url, response.Status)
	}
	if response.ContentLength > maxMetadataBytes {
		return nil, fmt.Errorf("GET %s exceeded the %d byte metadata limit", url, maxMetadataBytes)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxMetadataBytes {
		return nil, fmt.Errorf("GET %s exceeded the %d byte metadata limit", url, maxMetadataBytes)
	}
	return body, nil
}

func (client *Client) download(ctx context.Context, url, destination string, maximum int64) error {
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		if err := client.downloadOnce(ctx, url, destination, maximum); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt < 5 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}
	return fmt.Errorf("download failed after 5 attempts: %w", lastErr)
}

func (client *Client) downloadOnce(ctx context.Context, url, destination string, maximum int64) error {
	temporary := destination + ".partial"
	var offset int64
	if info, err := os.Lstat(temporary); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("partial download is not a regular file")
		}
		offset = info.Size()
		if offset > maximum {
			return fmt.Errorf("partial CHR archive exceeds the %d byte safety limit", maximum)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if offset > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := client.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("download CHR image: %w", err)
	}
	defer response.Body.Close()
	var expectedTotal int64 = -1
	switch response.StatusCode {
	case http.StatusOK:
		// The origin ignored Range. Restart this attempt from byte zero.
		offset = 0
		expectedTotal = response.ContentLength
	case http.StatusPartialContent:
		start, _, total, parseErr := parseContentRange(response.Header.Get("Content-Range"))
		if parseErr != nil {
			return parseErr
		}
		if start != offset {
			return fmt.Errorf("resumed CHR response starts at byte %d, expected %d", start, offset)
		}
		expectedTotal = total
	default:
		return fmt.Errorf("download CHR image: %s", response.Status)
	}
	if expectedTotal > maximum || response.ContentLength > maximum-offset {
		return fmt.Errorf("CHR archive exceeds the %d byte safety limit", maximum)
	}
	flags := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(temporary, flags, 0o600)
	if err != nil {
		return err
	}
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			_ = file.Close()
			return err
		}
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, maximum-offset+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	finalSize := offset + written
	if copyErr != nil {
		return fmt.Errorf("CHR response interrupted after %d of %d bytes: %w", finalSize, expectedTotal, copyErr)
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if finalSize > maximum {
		return fmt.Errorf("CHR archive exceeds the %d byte safety limit", maximum)
	}
	if response.ContentLength >= 0 && written != response.ContentLength {
		return fmt.Errorf("truncated response segment: received %d of %d bytes", written, response.ContentLength)
	}
	if expectedTotal >= 0 && finalSize != expectedTotal {
		return fmt.Errorf("incomplete CHR archive: received %d of %d bytes", finalSize, expectedTotal)
	}
	return os.Rename(temporary, destination)
}

func parseContentRange(value string) (start, end, total int64, err error) {
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, fmt.Errorf("invalid CHR Content-Range %q", value)
	}
	rangeValue, totalValue, ok := strings.Cut(strings.TrimPrefix(value, "bytes "), "/")
	if !ok || totalValue == "*" {
		return 0, 0, 0, fmt.Errorf("invalid CHR Content-Range %q", value)
	}
	startValue, endValue, ok := strings.Cut(rangeValue, "-")
	if !ok {
		return 0, 0, 0, fmt.Errorf("invalid CHR Content-Range %q", value)
	}
	start, startErr := strconv.ParseInt(startValue, 10, 64)
	end, endErr := strconv.ParseInt(endValue, 10, 64)
	total, totalErr := strconv.ParseInt(totalValue, 10, 64)
	if startErr != nil || endErr != nil || totalErr != nil || start < 0 || end < start || total <= end {
		return 0, 0, 0, fmt.Errorf("invalid CHR Content-Range %q", value)
	}
	return start, end, total, nil
}

func extractImage(archivePath, destination string) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("open CHR zip: %w", err)
	}
	defer archive.Close()
	var image *zip.File
	for _, candidate := range archive.File {
		if strings.EqualFold(filepath.Ext(candidate.Name), ".img") && !strings.Contains(candidate.Name, "..") && filepath.Base(candidate.Name) == candidate.Name {
			if image != nil {
				return fmt.Errorf("CHR zip contains multiple raw images")
			}
			image = candidate
		}
	}
	if image == nil {
		return fmt.Errorf("CHR zip does not contain a raw .img file")
	}
	if image.UncompressedSize64 > maxImageBytes {
		return fmt.Errorf("CHR raw image exceeds the safety limit")
	}
	source, err := image.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(target, io.LimitReader(source, maxImageBytes+1))
	syncErr := target.Sync()
	closeErr := target.Close()
	if copyErr != nil {
		return copyErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if written > maxImageBytes {
		return fmt.Errorf("CHR raw image exceeds the safety limit")
	}
	if uint64(written) != image.UncompressedSize64 {
		return fmt.Errorf("CHR raw image is truncated: extracted %d of %d bytes", written, image.UncompressedSize64)
	}
	return nil
}

func HashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	count, err := io.Copy(hash, bufio.NewReaderSize(file, 4*1024*1024))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}
