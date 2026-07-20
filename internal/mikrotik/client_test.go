package mikrotik

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResolveLatest(t *testing.T) {
	checksum := fmt.Sprintf("%x", sha256.Sum256([]byte("archive")))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/latest":
			_, _ = writer.Write([]byte("7.21.5 1234\n"))
		case "/7.21.5/chr-7.21.5.img.zip.sha256":
			_, _ = fmt.Fprintf(writer, "%s  chr-7.21.5.img.zip\n", checksum)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := NewClient()
	client.UpgradeURL = server.URL + "/latest"
	client.DownloadBase = server.URL
	release, err := client.ResolveLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if release.Version != "7.21.5" || release.Checksum != checksum || !release.Tested || release.UEFIBoot {
		t.Fatalf("unexpected release: %#v", release)
	}
}

func TestDefaultResolverUsesArchitectureAwareV7Endpoint(t *testing.T) {
	if !strings.Contains(defaultUpgradeURL, "NEWESTa7.long-term") {
		t.Fatalf("default upgrade endpoint is not the architecture-aware RouterOS 7 channel: %s", defaultUpgradeURL)
	}
}

func TestGetSmallRejectsOversizedMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Length", fmt.Sprint(maxMetadataBytes+1))
		_, _ = writer.Write(make([]byte, maxMetadataBytes+1))
	}))
	defer server.Close()
	client := NewClient()
	if _, err := client.getSmall(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "metadata limit") {
		t.Fatalf("expected oversized metadata to fail, got %v", err)
	}
}

func TestDownloadResumesTruncatedResponse(t *testing.T) {
	payload := []byte("complete archive")
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if attempts.Add(1) == 1 {
			writer.Header().Set("Content-Length", fmt.Sprint(len(payload)+10))
			_, _ = writer.Write(payload[:5])
			return
		}
		if request.Header.Get("Range") != "bytes=5-" {
			t.Errorf("resume Range = %q", request.Header.Get("Range"))
		}
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes 5-%d/%d", len(payload)-1, len(payload)))
		writer.Header().Set("Content-Length", fmt.Sprint(len(payload)-5))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(payload[5:])
	}))
	defer server.Close()
	client := NewClient()
	destination := filepath.Join(t.TempDir(), "archive.zip")
	if err := client.download(context.Background(), server.URL, destination, 1024); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) || attempts.Load() != 2 {
		t.Fatalf("resume did not recover truncated response: attempts=%d data=%q", attempts.Load(), data)
	}
}

func TestParseContentRange(t *testing.T) {
	start, end, total, err := parseContentRange("bytes 5-15/16")
	if err != nil || start != 5 || end != 15 || total != 16 {
		t.Fatalf("unexpected parsed range: %d %d %d %v", start, end, total, err)
	}
	for _, value := range []string{"", "bytes 5-15/*", "bytes 16-15/20", "items 5-15/20"} {
		if _, _, _, err := parseContentRange(value); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func TestInspectMBR(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.img")
	data := make([]byte, 8*1024*1024)
	data[510], data[511] = 0x55, 0xaa
	entry := data[446:462]
	entry[0], entry[4] = 0x80, 0x83
	putLittle32(entry[8:12], 2048)
	putLittle32(entry[12:16], 4096)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	layout, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.Partitions) != 1 || layout.Partitions[0].OffsetBytes != 2048*512 || layout.Partitions[0].SizeBytes != 4096*512 {
		t.Fatalf("unexpected layout: %#v", layout)
	}
}

func TestInspectRejectsOverlappingPartitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlap.img")
	data := make([]byte, 8*1024*1024)
	data[510], data[511] = 0x55, 0xaa
	first := data[446:462]
	first[4] = 0x83
	putLittle32(first[8:12], 2048)
	putLittle32(first[12:16], 4096)
	second := data[462:478]
	second[4] = 0x83
	putLittle32(second[8:12], 4096)
	putLittle32(second[12:16], 2048)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("expected overlapping layout to fail, got %v", err)
	}
}

func putLittle32(target []byte, value uint32) {
	target[0], target[1], target[2], target[3] = byte(value), byte(value>>8), byte(value>>16), byte(value>>24)
}
