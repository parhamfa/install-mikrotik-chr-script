package platform

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/parhamfa/chr-install/internal/model"
)

var supported = map[string]map[string]bool{
	"debian": {"12": true, "13": true},
	"ubuntu": {"22.04": true, "24.04": true, "26.04": true},
}

func Detect(root string) (model.Host, []model.Issue) {
	if root == "" {
		root = "/"
	}
	host := model.Host{Architecture: runtime.GOARCH}
	var issues []model.Issue

	data, err := os.ReadFile(filepath.Join(root, "etc", "os-release"))
	if err != nil {
		issues = append(issues, blocker("os-release", "cannot read /etc/os-release"))
	} else {
		values := ParseOSRelease(string(data))
		host.Distribution = strings.ToLower(values["ID"])
		host.Version = values["VERSION_ID"]
	}

	if release, err := os.ReadFile(filepath.Join(root, "proc", "sys", "kernel", "osrelease")); err == nil {
		host.Kernel = strings.TrimSpace(string(release))
	}
	if _, err := os.Stat(filepath.Join(root, "sys", "firmware", "efi")); err == nil {
		host.Firmware = "UEFI"
	} else {
		host.Firmware = "BIOS"
	}
	host.Console = DetectConsole(root)
	if memory, err := os.ReadFile(filepath.Join(root, "proc", "meminfo")); err == nil {
		host.MemoryBytes = ParseMemoryBytes(string(memory))
	}

	host.Supported = host.Architecture == "amd64" && supported[host.Distribution][host.Version]
	if host.Architecture != "amd64" {
		issues = append(issues, blocker("architecture", fmt.Sprintf("unsupported architecture %q; v1 requires amd64", host.Architecture)))
	}
	if !supported[host.Distribution][host.Version] {
		issues = append(issues, blocker("distribution", fmt.Sprintf("unsupported operating system %s %s", host.Distribution, host.Version)))
	}
	if host.MemoryBytes == 0 {
		issues = append(issues, blocker("memory", "cannot determine installed RAM"))
	} else if host.MemoryBytes < 512*1024*1024 {
		issues = append(issues, blocker("memory", "less than 512 MiB of RAM is not enough for the staged writer"))
	}
	return host, issues
}

func DetectConsole(root string) string {
	data, _ := os.ReadFile(filepath.Join(root, "proc", "cmdline"))
	for _, field := range strings.Fields(string(data)) {
		value, found := strings.CutPrefix(field, "console=")
		if !found {
			continue
		}
		device, _, _ := strings.Cut(value, ",")
		if strings.HasPrefix(device, "ttyS") || strings.HasPrefix(device, "hvc") || strings.HasPrefix(device, "xvc") {
			return device
		}
	}
	return "not detected"
}

func ParseOSRelease(input string) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		result[strings.TrimSpace(key)] = value
	}
	return result
}

func ParseMemoryBytes(input string) uint64 {
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, _ := strconv.ParseUint(fields[1], 10, 64)
			return value * 1024
		}
	}
	return 0
}

func blocker(code, message string) model.Issue {
	return model.Issue{Severity: model.SeverityBlocker, Code: code, Message: message}
}
