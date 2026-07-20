package disk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
)

type blockNode struct {
	Name        string      `json:"name"`
	KName       string      `json:"kname"`
	Path        string      `json:"path"`
	Type        string      `json:"type"`
	PKName      string      `json:"pkname"`
	Size        uint64      `json:"size"`
	Model       string      `json:"model"`
	Serial      string      `json:"serial"`
	WWN         string      `json:"wwn"`
	Transport   string      `json:"tran"`
	MajorMinor  string      `json:"maj:min"`
	ReadOnly    bool        `json:"ro"`
	Removable   bool        `json:"rm"`
	Mountpoints []any       `json:"mountpoints"`
	Children    []blockNode `json:"children"`
}

type lsblkDocument struct {
	Devices []blockNode `json:"blockdevices"`
}

type findmntDocument struct {
	Filesystems []struct {
		Source string `json:"source"`
		FSType string `json:"fstype"`
	} `json:"filesystems"`
}

type graph struct {
	byKey    map[string]*blockNode
	parents  map[string][]*blockNode
	children map[string][]*blockNode
	disks    []*blockNode
}

func Detect(ctx context.Context, runner command.Runner, root string) (model.Disk, []model.Issue) {
	if root == "" {
		root = "/"
	}
	var result model.Disk
	var issues []model.Issue

	findmntOutput, err := runner.Run(ctx, "findmnt", "-J", "-n", "-o", "SOURCE,FSTYPE", "/")
	if err != nil {
		return result, []model.Issue{blocker("root-device", err.Error())}
	}
	var mounts findmntDocument
	if err := json.Unmarshal(findmntOutput, &mounts); err != nil || len(mounts.Filesystems) != 1 {
		return result, []model.Issue{blocker("root-device", "cannot parse the root filesystem source")}
	}
	rootSource := mounts.Filesystems[0].Source
	rootFSType := mounts.Filesystems[0].FSType
	if strings.EqualFold(rootFSType, "btrfs") {
		issues = append(issues, blocker("disk-stack", "btrfs root filesystems are not supported because v1 cannot prove single-device ancestry"))
	}
	if strings.HasPrefix(rootSource, "/dev/") {
		if resolved, err := runner.Run(ctx, "readlink", "-f", rootSource); err == nil {
			rootSource = strings.TrimSpace(string(resolved))
		}
	}

	lsblkOutput, err := runner.Run(ctx, "lsblk", "-J", "-b", "-o", "NAME,KNAME,PATH,TYPE,PKNAME,SIZE,MODEL,SERIAL,WWN,TRAN,MAJ:MIN,RO,RM,MOUNTPOINTS")
	if err != nil {
		return result, []model.Issue{blocker("block-devices", err.Error())}
	}
	g, err := parseGraph(lsblkOutput)
	if err != nil {
		return result, []model.Issue{blocker("block-devices", err.Error())}
	}

	rootNode := g.lookup(rootSource)
	var target *blockNode
	if rootNode != nil {
		backing, unsafeTypes := g.backingDisks(rootNode)
		if len(unsafeTypes) > 0 {
			issues = append(issues, blocker("disk-stack", "unsupported root storage stack: "+strings.Join(unsafeTypes, ", ")))
		}
		if len(backing) != 1 {
			issues = append(issues, blocker("disk-ambiguity", fmt.Sprintf("root filesystem resolves to %d physical disks", len(backing))))
			return result, issues
		}
		target = backing[0]
		result.RootBacked = true
		result.Mounted = true
	} else {
		if !isLiveFilesystem(rootSource, rootFSType) {
			return result, append(issues, blocker("root-device", fmt.Sprintf("root source %q is not a block device or recognized rescue filesystem", rootSource)))
		}
		candidates := make([]*blockNode, 0, len(g.disks))
		for _, candidate := range g.disks {
			if !candidate.ReadOnly && !candidate.Removable && !g.hasMountedDescendant(candidate) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) != 1 {
			return result, append(issues, blocker("disk-ambiguity", fmt.Sprintf("rescue environment exposes %d unmounted writable disks; exactly one is required", len(candidates))))
		}
		target = candidates[0]
		result.Method = model.InstallMethodDirect
		issues = append(issues, model.Issue{Severity: model.SeverityInfo, Code: "rescue", Message: "running root is memory-backed; direct rescue writing is available"})
	}

	if target == nil {
		return result, append(issues, blocker("target-disk", "no target disk was selected"))
	}
	result.Fingerprint = fingerprint(root, target)
	if target.Size < 256*1024*1024 {
		issues = append(issues, blocker("disk-size", "target disk is smaller than 256 MiB"))
	}
	if !supportedKernelName(target.KName) {
		issues = append(issues, blocker("disk-driver", fmt.Sprintf("disk %s is not a supported SCSI, virtio, Xen, or NVMe device", target.Path)))
	}
	if result.Fingerprint.Driver == "" {
		issues = append(issues, blocker("disk-driver", fmt.Sprintf("cannot identify the storage driver for %s", target.Path)))
	} else if !supportedStorageDriver(result.Fingerprint.Driver) {
		issues = append(issues, blocker("disk-driver", fmt.Sprintf("storage driver %s has not been validated for CHR", result.Fingerprint.Driver)))
	}
	if target.Serial == "" && target.WWN == "" {
		issues = append(issues, model.Issue{Severity: model.SeverityWarning, Code: "disk-identity", Message: "target disk has no serial or WWN; the writer will require name, size, and major/minor identity to remain unchanged"})
	}
	if len(g.disks) > 1 && result.RootBacked {
		issues = append(issues, model.Issue{Severity: model.SeverityWarning, Code: "extra-disks", Message: fmt.Sprintf("%d disks are visible; only the disk backing / is targeted", len(g.disks))})
	}

	if result.RootBacked {
		configureStaging(ctx, runner, root, &result, &issues)
	}
	return result, issues
}

func parseGraph(data []byte) (*graph, error) {
	var document lsblkDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse lsblk JSON: %w", err)
	}
	g := &graph{
		byKey:    make(map[string]*blockNode),
		parents:  make(map[string][]*blockNode),
		children: make(map[string][]*blockNode),
	}
	var walk func(nodes []blockNode, parent *blockNode)
	walk = func(nodes []blockNode, parent *blockNode) {
		for i := range nodes {
			node := &nodes[i]
			for _, key := range []string{node.Name, node.KName, node.Path, "/dev/" + node.Name, "/dev/" + node.KName} {
				if key != "" && key != "/dev/" {
					g.byKey[key] = node
				}
			}
			if node.Type == "disk" {
				g.disks = append(g.disks, node)
			}
			if parent != nil {
				g.parents[node.KName] = appendUnique(g.parents[node.KName], parent)
				g.children[parent.KName] = appendUnique(g.children[parent.KName], node)
			}
			walk(node.Children, node)
		}
	}
	walk(document.Devices, nil)
	for _, node := range g.byKey {
		if node.PKName == "" {
			continue
		}
		if parent := g.lookup(node.PKName); parent != nil {
			g.parents[node.KName] = appendUnique(g.parents[node.KName], parent)
			g.children[parent.KName] = appendUnique(g.children[parent.KName], node)
		}
	}
	return g, nil
}

func appendUnique(nodes []*blockNode, candidate *blockNode) []*blockNode {
	for _, node := range nodes {
		if node.KName == candidate.KName {
			return nodes
		}
	}
	return append(nodes, candidate)
}

func (g *graph) lookup(key string) *blockNode {
	key = strings.TrimSpace(key)
	if base, _, found := strings.Cut(key, "["); found {
		key = base
	}
	if node := g.byKey[key]; node != nil {
		return node
	}
	return g.byKey[filepath.Base(key)]
}

func (g *graph) backingDisks(start *blockNode) ([]*blockNode, []string) {
	disks := make(map[string]*blockNode)
	unsafe := make(map[string]bool)
	seen := make(map[string]bool)
	var visit func(*blockNode)
	visit = func(node *blockNode) {
		if node == nil || seen[node.KName] {
			return
		}
		seen[node.KName] = true
		switch node.Type {
		case "disk", "part", "crypt", "lvm":
		default:
			unsafe[node.Type] = true
		}
		if node.Type == "disk" {
			disks[node.KName] = node
			return
		}
		for _, parent := range g.parents[node.KName] {
			visit(parent)
		}
	}
	visit(start)
	result := make([]*blockNode, 0, len(disks))
	for _, node := range disks {
		result = append(result, node)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].KName < result[j].KName })
	unsafeTypes := make([]string, 0, len(unsafe))
	for value := range unsafe {
		unsafeTypes = append(unsafeTypes, value)
	}
	sort.Strings(unsafeTypes)
	return result, unsafeTypes
}

func (g *graph) hasMountedDescendant(start *blockNode) bool {
	seen := make(map[string]bool)
	var visit func(*blockNode) bool
	visit = func(node *blockNode) bool {
		if node == nil || seen[node.KName] {
			return false
		}
		seen[node.KName] = true
		for _, mountpoint := range node.Mountpoints {
			if value, ok := mountpoint.(string); ok && strings.TrimSpace(value) != "" {
				return true
			}
		}
		for _, child := range g.children[node.KName] {
			if visit(child) {
				return true
			}
		}
		return false
	}
	return visit(start)
}

func fingerprint(root string, node *blockNode) model.DiskFingerprint {
	path := node.Path
	if path == "" {
		path = "/dev/" + node.KName
	}
	return model.DiskFingerprint{
		Path:       path,
		KernelName: node.KName,
		MajorMinor: node.MajorMinor,
		SizeBytes:  node.Size,
		Model:      strings.TrimSpace(node.Model),
		Serial:     strings.TrimSpace(node.Serial),
		WWN:        strings.TrimSpace(node.WWN),
		Transport:  strings.TrimSpace(node.Transport),
		Driver:     readDriver(root, node.KName),
	}
}

func readDriver(root, kernelName string) string {
	devicePath := filepath.Join(root, "sys", "class", "block", kernelName, "device")
	if driver := driverFromDevice(devicePath); driver != "" {
		return driver
	}
	// Test fixtures use a regular file because git cannot represent sysfs links.
	if data, readErr := os.ReadFile(filepath.Join(devicePath, "driver")); readErr == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func driverFromDevice(devicePath string) string {
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

func supportedStorageDriver(driver string) bool {
	canonical := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(driver)), "-", "_")
	switch canonical {
	case "sd", "virtio_blk", "virtio_scsi", "nvme", "xen_blkfront", "hv_storvsc", "ata_piix", "ahci", "mptspi", "mptsas", "vmw_pvscsi", "pvscsi":
		return true
	default:
		return false
	}
}

func supportedKernelName(name string) bool {
	if strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "xvd") {
		return true
	}
	if strings.HasPrefix(name, "nvme") && !strings.Contains(name, "p") {
		return true
	}
	return false
}

func isLiveFilesystem(source, fsType string) bool {
	if strings.HasPrefix(source, "/dev/") {
		return false
	}
	switch strings.ToLower(fsType) {
	case "overlay", "squashfs", "tmpfs", "ramfs", "rootfs":
		return true
	default:
		return false
	}
}

func configureStaging(ctx context.Context, runner command.Runner, root string, result *model.Disk, issues *[]model.Issue) {
	releaseOutput, err := runner.Run(ctx, "uname", "-r")
	if err != nil {
		*issues = append(*issues, blocker("kernel", err.Error()))
		return
	}
	release := strings.TrimSpace(string(releaseOutput))
	result.KernelPath = filepath.Join(root, "boot", "vmlinuz-"+release)
	result.InitrdPath = filepath.Join(root, "boot", "initrd.img-"+release)
	if _, err := os.Stat(result.KernelPath); err != nil {
		*issues = append(*issues, blocker("kernel", "current kernel image is not available at "+result.KernelPath))
	}
	if _, err := os.Stat(result.InitrdPath); err != nil {
		*issues = append(*issues, blocker("initramfs", "current initramfs is not available at "+result.InitrdPath))
	}
	if _, err := runner.LookPath("mkinitramfs"); err != nil {
		*issues = append(*issues, blocker("initramfs-builder", "mkinitramfs is required to build the RAM-backed writer from the host kernel and modules"))
	}

	_, kexecErr := runner.LookPath("kexec")
	result.Kexec = kexecErr == nil && !secureBootEnabled(root) && !kexecDisabled(root)
	_, grubRebootErr := runner.LookPath("grub-reboot")
	_, updateGrubErr := runner.LookPath("update-grub")
	_, grubProbeErr := runner.LookPath("grub-probe")
	result.GRUB = grubRebootErr == nil && updateGrubErr == nil && grubProbeErr == nil

	switch {
	case result.Kexec:
		result.Method = model.InstallMethodKexec
	case result.GRUB:
		result.Method = model.InstallMethodGRUB
	default:
		*issues = append(*issues, blocker("staging", "neither usable kexec nor one-shot GRUB staging is available"))
	}
}

func secureBootEnabled(root string) bool {
	matches, _ := filepath.Glob(filepath.Join(root, "sys", "firmware", "efi", "efivars", "SecureBoot-*"))
	for _, match := range matches {
		data, err := os.ReadFile(match)
		if err == nil && len(data) >= 5 && data[4] == 1 {
			return true
		}
	}
	return false
}

func kexecDisabled(root string) bool {
	data, err := os.ReadFile(filepath.Join(root, "proc", "sys", "kernel", "kexec_load_disabled"))
	if err != nil {
		return false
	}
	value, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return value != 0
}

func blocker(code, message string) model.Issue {
	return model.Issue{Severity: model.SeverityBlocker, Code: code, Message: message}
}
