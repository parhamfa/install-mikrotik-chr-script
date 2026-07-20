package model

import (
	"fmt"
	"strings"
	"time"
)

type Evidence string

const (
	EvidenceVerified Evidence = "verified"
	EvidenceInferred Evidence = "inferred"
	EvidenceUser     Evidence = "user-supplied"
)

type Severity string

const (
	SeverityInfo    Severity = "info"
	SeverityWarning Severity = "warning"
	SeverityBlocker Severity = "blocker"
)

type Issue struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

type Host struct {
	Distribution string `json:"distribution"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Kernel       string `json:"kernel"`
	Firmware     string `json:"firmware"`
	Console      string `json:"console"`
	MemoryBytes  uint64 `json:"memory_bytes"`
	Supported    bool   `json:"supported"`
}

type DiskFingerprint struct {
	Path       string `json:"path"`
	KernelName string `json:"kernel_name"`
	MajorMinor string `json:"major_minor"`
	SizeBytes  uint64 `json:"size_bytes"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	WWN        string `json:"wwn,omitempty"`
	Transport  string `json:"transport,omitempty"`
	Driver     string `json:"driver,omitempty"`
}

func (d DiskFingerprint) StableIdentity() string {
	for _, value := range []string{d.WWN, d.Serial} {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return fmt.Sprintf("%s:%d:%s", d.KernelName, d.SizeBytes, d.MajorMinor)
}

type InstallMethod string

const (
	InstallMethodDirect InstallMethod = "rescue-direct"
	InstallMethodKexec  InstallMethod = "staged-kexec"
	InstallMethodGRUB   InstallMethod = "staged-grub"
)

type Disk struct {
	Fingerprint DiskFingerprint `json:"fingerprint"`
	RootBacked  bool            `json:"root_backed"`
	Mounted     bool            `json:"mounted"`
	Method      InstallMethod   `json:"method"`
	KernelPath  string          `json:"kernel_path,omitempty"`
	InitrdPath  string          `json:"initrd_path,omitempty"`
	Kexec       bool            `json:"kexec"`
	GRUB        bool            `json:"grub"`
}

type DHCPProbe struct {
	Attempted bool   `json:"attempted"`
	Offered   bool   `json:"offered"`
	Address   string `json:"address,omitempty"`
	Server    string `json:"server,omitempty"`
	Message   string `json:"message,omitempty"`
}

type IPv4Plan struct {
	Mode          string   `json:"mode"`
	Addresses     []string `json:"addresses,omitempty"`
	Gateway       string   `json:"gateway,omitempty"`
	GatewayOnLink bool     `json:"gateway_on_link"`
	UsePeerDNS    bool     `json:"use_peer_dns"`
	Evidence      Evidence `json:"evidence"`
}

type IPv6Plan struct {
	SLAAC         bool     `json:"slaac"`
	DHCP          bool     `json:"dhcp"`
	Addresses     []string `json:"addresses,omitempty"`
	Gateway       string   `json:"gateway,omitempty"`
	GatewayOnLink bool     `json:"gateway_on_link"`
	UsePeerDNS    bool     `json:"use_peer_dns"`
	Evidence      Evidence `json:"evidence"`
}

type NetworkPlan struct {
	InterfaceName string    `json:"interface_name"`
	MAC           string    `json:"mac"`
	Driver        string    `json:"driver,omitempty"`
	MTU           int       `json:"mtu"`
	IPv4          IPv4Plan  `json:"ipv4"`
	IPv6          IPv6Plan  `json:"ipv6"`
	DNS           []string  `json:"dns,omitempty"`
	DHCPProbe     DHCPProbe `json:"dhcp_probe"`
	Evidence      Evidence  `json:"evidence"`
	Sources       []string  `json:"sources,omitempty"`
}

type Release struct {
	Version       string `json:"version"`
	ImageURL      string `json:"image_url"`
	ChecksumURL   string `json:"checksum_url"`
	Checksum      string `json:"checksum,omitempty"`
	Tested        bool   `json:"tested"`
	UEFIBoot      bool   `json:"uefi_boot"`
	Compatibility string `json:"compatibility,omitempty"`
}

type Preflight struct {
	GeneratedAt time.Time   `json:"generated_at"`
	Host        Host        `json:"host"`
	Disk        Disk        `json:"disk"`
	Network     NetworkPlan `json:"network"`
	Release     Release     `json:"release"`
	Issues      []Issue     `json:"issues,omitempty"`
}

func (p Preflight) Blocked() bool {
	for _, issue := range p.Issues {
		if issue.Severity == SeverityBlocker {
			return true
		}
	}
	return false
}
