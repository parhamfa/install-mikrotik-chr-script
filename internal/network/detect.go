package network

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/model"
)

type Prober interface {
	Probe(ctx context.Context, interfaceName string, mac net.HardwareAddr, timeout time.Duration) (model.DHCPProbe, error)
}

type DefaultProber struct{}

func (DefaultProber) Probe(ctx context.Context, interfaceName string, mac net.HardwareAddr, timeout time.Duration) (model.DHCPProbe, error) {
	return ProbeDHCP(ctx, interfaceName, mac, timeout)
}

type route struct {
	Destination string   `json:"dst"`
	Gateway     string   `json:"gateway"`
	Device      string   `json:"dev"`
	Protocol    string   `json:"protocol"`
	Scope       string   `json:"scope"`
	Metric      int      `json:"metric"`
	Flags       []string `json:"flags"`
}

type link struct {
	Index    int             `json:"ifindex"`
	Name     string          `json:"ifname"`
	Flags    []string        `json:"flags"`
	MTU      int             `json:"mtu"`
	Master   json.RawMessage `json:"master"`
	Address  string          `json:"address"`
	LinkType string          `json:"link_type"`
	LinkInfo struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type interfaceAddress struct {
	Index     int    `json:"ifindex"`
	Name      string `json:"ifname"`
	LinkType  string `json:"link_type"`
	Address   string `json:"address"`
	AddrInfos []struct {
		Family     string `json:"family"`
		Local      string `json:"local"`
		PrefixLen  int    `json:"prefixlen"`
		Scope      string `json:"scope"`
		Dynamic    bool   `json:"dynamic"`
		Protocol   string `json:"protocol"`
		Temporary  bool   `json:"temporary"`
		Deprecated bool   `json:"deprecated"`
	} `json:"addr_info"`
}

type rule struct {
	Priority int    `json:"priority"`
	Table    string `json:"table"`
	Action   string `json:"action"`
}

type sourceEvidence struct {
	DHCP4  bool
	DHCP6  bool
	Lease4 bool
	Lease6 bool
	Paths  []string
}

func Detect(ctx context.Context, runner command.Runner, prober Prober, root string) (model.NetworkPlan, []model.Issue) {
	if prober == nil {
		prober = DefaultProber{}
	}
	if root == "" {
		root = "/"
	}
	var plan model.NetworkPlan
	var issues []model.Issue

	v4Routes, err := readRoutes(ctx, runner, "-4")
	if err != nil {
		return plan, []model.Issue{blocker("ipv4-routes", err.Error())}
	}
	v6Routes, err := readRoutes(ctx, runner, "-6")
	if err != nil {
		return plan, append(issues, blocker("ipv6-routes", err.Error()))
	}
	v4Default, v4Issue := selectDefault(v4Routes, "IPv4")
	v6Default, v6Issue := selectDefault(v6Routes, "IPv6")
	issues = appendIssue(issues, v4Issue)
	issues = appendIssue(issues, v6Issue)

	interfaceName := ""
	if v4Default != nil {
		interfaceName = v4Default.Device
	}
	if v6Default != nil {
		if interfaceName != "" && interfaceName != v6Default.Device {
			issues = append(issues, blocker("multi-wan", fmt.Sprintf("IPv4 and IPv6 default routes use different interfaces (%s and %s)", interfaceName, v6Default.Device)))
		} else {
			interfaceName = v6Default.Device
		}
	}
	if interfaceName == "" {
		return plan, append(issues, blocker("default-route", "no IPv4 or IPv6 default route is active"))
	}
	plan.InterfaceName = interfaceName
	issues = append(issues, inspectRouteSet(v4Routes, v4Default, interfaceName, "IPv4")...)
	issues = append(issues, inspectRouteSet(v6Routes, v6Default, interfaceName, "IPv6")...)

	if policyIssues := inspectRules(ctx, runner); len(policyIssues) > 0 {
		issues = append(issues, policyIssues...)
	}

	linksOutput, err := runner.Run(ctx, "ip", "-j", "link", "show", "dev", interfaceName)
	if err != nil {
		return plan, append(issues, blocker("uplink", err.Error()))
	}
	var links []link
	if err := json.Unmarshal(linksOutput, &links); err != nil || len(links) != 1 {
		return plan, append(issues, blocker("uplink", "cannot parse the active uplink"))
	}
	selectedLink := links[0]
	plan.MAC = normalizeMAC(selectedLink.Address)
	plan.Driver = readNetworkDriver(root, interfaceName)
	plan.MTU = selectedLink.MTU
	if plan.Driver == "" {
		issues = append(issues, blocker("nic-driver", fmt.Sprintf("cannot identify the kernel driver for %s", interfaceName)))
	} else if !supportedNetworkDriver(plan.Driver) {
		issues = append(issues, blocker("nic-driver", fmt.Sprintf("network driver %s has not been validated for CHR", plan.Driver)))
	}
	if hasMaster(selectedLink.Master) || selectedLink.LinkInfo.Kind != "" {
		kind := selectedLink.LinkInfo.Kind
		if kind == "" {
			kind = "enslaved"
		}
		issues = append(issues, blocker("complex-uplink", fmt.Sprintf("interface %s uses unsupported %s networking", interfaceName, kind)))
	}
	if selectedLink.LinkType != "ether" && selectedLink.LinkType != "" {
		issues = append(issues, blocker("uplink-type", fmt.Sprintf("interface %s has unsupported link type %s", interfaceName, selectedLink.LinkType)))
	}
	if plan.MAC == "" {
		issues = append(issues, blocker("uplink-mac", "active uplink has no usable Ethernet MAC address"))
	}
	issues = append(issues, inspectAdditionalPhysicalUplinks(ctx, runner, root, interfaceName)...)

	addressesOutput, err := runner.Run(ctx, "ip", "-j", "address", "show", "dev", interfaceName)
	if err != nil {
		return plan, append(issues, blocker("addresses", err.Error()))
	}
	var interfaces []interfaceAddress
	if err := json.Unmarshal(addressesOutput, &interfaces); err != nil || len(interfaces) != 1 {
		return plan, append(issues, blocker("addresses", "cannot parse active interface addresses"))
	}

	var v4Dynamic, v4Static, v6Dynamic, v6Static []string
	var v6RA, v6DHCPRuntime bool
	for _, address := range interfaces[0].AddrInfos {
		if address.Scope != "global" || address.Deprecated {
			continue
		}
		prefix := fmt.Sprintf("%s/%d", address.Local, address.PrefixLen)
		switch address.Family {
		case "inet":
			if address.Dynamic || strings.EqualFold(address.Protocol, "dhcp") {
				v4Dynamic = append(v4Dynamic, prefix)
			} else {
				v4Static = append(v4Static, prefix)
			}
		case "inet6":
			if address.Temporary {
				continue
			}
			protocol := strings.ToLower(address.Protocol)
			if address.Dynamic || strings.Contains(protocol, "ra") || strings.Contains(protocol, "dhcp") {
				v6Dynamic = append(v6Dynamic, prefix)
				if strings.Contains(protocol, "ra") {
					v6RA = true
				}
				if strings.Contains(protocol, "dhcp") {
					v6DHCPRuntime = true
				}
			} else {
				v6Static = append(v6Static, prefix)
			}
		}
	}
	sort.Strings(v4Dynamic)
	sort.Strings(v4Static)
	sort.Strings(v6Dynamic)
	sort.Strings(v6Static)

	evidence := inspectConfiguration(root, interfaceName, selectedLink.Index, plan.MAC, append(append([]string{}, v4Dynamic...), v4Static...))
	plan.Sources = evidence.Paths

	switch {
	case len(v4Dynamic) > 0 && len(v4Static) > 0:
		issues = append(issues, blocker("mixed-ipv4", "uplink has both DHCP and static global IPv4 addresses"))
	case len(v4Dynamic) > 0:
		plan.IPv4 = model.IPv4Plan{Mode: "dhcp", Addresses: v4Dynamic, UsePeerDNS: true, Evidence: model.EvidenceVerified}
	case len(v4Static) > 0:
		plan.IPv4 = model.IPv4Plan{Mode: "static", Addresses: v4Static, Evidence: model.EvidenceVerified}
	case evidence.DHCP4:
		plan.IPv4 = model.IPv4Plan{Mode: "dhcp", UsePeerDNS: true, Evidence: model.EvidenceInferred}
	default:
		plan.IPv4 = model.IPv4Plan{Mode: "none", Evidence: model.EvidenceVerified}
	}
	if v4Default != nil {
		plan.IPv4.Gateway = v4Default.Gateway
		plan.IPv4.GatewayOnLink = hasFlag(v4Default.Flags, "onlink") || gatewayOutside(v4Default.Gateway, append(v4Dynamic, v4Static...))
	}

	plan.IPv6.Addresses = v6Static
	plan.IPv6.SLAAC = v6RA || (v6Default != nil && strings.Contains(strings.ToLower(v6Default.Protocol), "ra"))
	plan.IPv6.DHCP = v6DHCPRuntime || evidence.DHCP6 || evidence.Lease6
	if len(v6Dynamic) > 0 && !plan.IPv6.SLAAC && !plan.IPv6.DHCP {
		plan.IPv6.SLAAC = true
		plan.IPv6.Evidence = model.EvidenceInferred
	}
	if len(v6Static) > 0 || len(v6Dynamic) > 0 || v6Default != nil {
		if plan.IPv6.Evidence == "" {
			plan.IPv6.Evidence = model.EvidenceVerified
		}
	}
	if plan.IPv6.Evidence == "" {
		if plan.IPv6.DHCP && !evidence.Lease6 {
			plan.IPv6.Evidence = model.EvidenceInferred
		} else {
			plan.IPv6.Evidence = model.EvidenceVerified
		}
	}
	if v6Default != nil {
		plan.IPv6.Gateway = v6Default.Gateway
		plan.IPv6.GatewayOnLink = hasFlag(v6Default.Flags, "onlink") || gatewayOutside(v6Default.Gateway, append(v6Static, v6Dynamic...))
	}
	plan.IPv6.UsePeerDNS = plan.IPv6.DHCP

	plan.DNS = detectDNS(ctx, runner, root, interfaceName)
	if len(plan.DNS) == 0 && plan.IPv4.Mode == "static" && !plan.IPv6.DHCP {
		issues = append(issues, model.Issue{Severity: model.SeverityWarning, Code: "dns", Message: "no non-loopback DNS servers were detected"})
	}

	if hardware, err := net.ParseMAC(plan.MAC); err == nil {
		probe, probeErr := prober.Probe(ctx, interfaceName, hardware, 4*time.Second)
		plan.DHCPProbe = probe
		if probeErr != nil {
			plan.DHCPProbe.Message = probeErr.Error()
		}
	}
	if plan.IPv4.Mode == "dhcp" && !evidence.Lease4 && !plan.DHCPProbe.Offered {
		issues = append(issues, blocker("dhcp-unverified", "IPv4 DHCP is configured but no active lease file or DHCP offer was established"))
	}
	if plan.IPv4.Mode == "dhcp" && (evidence.Lease4 || plan.DHCPProbe.Offered) {
		plan.IPv4.Evidence = model.EvidenceVerified
	}
	if plan.IPv4.Mode == "static" && plan.DHCPProbe.Attempted && !plan.DHCPProbe.Offered {
		issues = append(issues, model.Issue{Severity: model.SeverityInfo, Code: "dhcp-absent", Message: "no DHCP offer was observed; preserving the active static configuration"})
	}
	if plan.IPv4.Mode == "none" && len(v6Static) == 0 && len(v6Dynamic) == 0 {
		issues = append(issues, blocker("network", "uplink has no usable global IPv4 or IPv6 configuration"))
	}

	plan.Evidence = model.EvidenceVerified
	if plan.IPv4.Evidence != model.EvidenceVerified || plan.IPv6.Evidence != model.EvidenceVerified {
		plan.Evidence = model.EvidenceInferred
	}
	for _, issue := range issues {
		if issue.Severity == model.SeverityBlocker || issue.Severity == model.SeverityWarning {
			plan.Evidence = model.EvidenceInferred
			break
		}
	}
	if validation := Validate(plan); validation != nil {
		issues = append(issues, blocker("network-plan", validation.Error()))
	}
	return plan, issues
}

func readRoutes(ctx context.Context, runner command.Runner, family string) ([]route, error) {
	output, err := runner.Run(ctx, "ip", "-j", family, "route", "show", "table", "main")
	if err != nil {
		return nil, err
	}
	var routes []route
	if err := json.Unmarshal(output, &routes); err != nil {
		return nil, fmt.Errorf("parse %s routes: %w", family, err)
	}
	return routes, nil
}

func selectDefault(routes []route, family string) (*route, *model.Issue) {
	var defaults []route
	for _, candidate := range routes {
		if candidate.Destination == "default" || candidate.Destination == "0.0.0.0/0" || candidate.Destination == "::/0" {
			defaults = append(defaults, candidate)
		}
	}
	if len(defaults) == 0 {
		return nil, nil
	}
	sort.SliceStable(defaults, func(i, j int) bool { return defaults[i].Metric < defaults[j].Metric })
	selected := defaults[0]
	for _, candidate := range defaults[1:] {
		if candidate.Device != selected.Device || candidate.Gateway != selected.Gateway {
			issue := blocker("multiple-defaults", family+" has multiple distinct default routes")
			return &selected, &issue
		}
	}
	return &selected, nil
}

func inspectRouteSet(routes []route, defaultRoute *route, interfaceName, family string) []model.Issue {
	var issues []model.Issue
	for _, candidate := range routes {
		if isDefaultRoute(candidate.Destination) {
			continue
		}
		protocol := strings.ToLower(candidate.Protocol)
		if protocol == "kernel" || (family == "IPv6" && protocol == "ra") {
			continue
		}
		if candidate.Device != "" && candidate.Device != interfaceName {
			issues = append(issues, blocker("multi-uplink", fmt.Sprintf("%s route %s uses additional interface %s", family, candidate.Destination, candidate.Device)))
			continue
		}
		if defaultRoute != nil && candidate.Gateway == "" && isGatewayHostRoute(candidate.Destination, defaultRoute.Gateway) {
			continue
		}
		issues = append(issues, blocker("unsupported-route", fmt.Sprintf("%s route %s (protocol %s) cannot be preserved by v1", family, candidate.Destination, emptyRouteValue(protocol))))
	}
	return issues
}

func isDefaultRoute(destination string) bool {
	return destination == "default" || destination == "0.0.0.0/0" || destination == "::/0"
}

func isGatewayHostRoute(destination, gateway string) bool {
	prefix, prefixErr := netip.ParsePrefix(strings.TrimSpace(destination))
	address, addressErr := netip.ParseAddr(strings.TrimSpace(strings.Split(gateway, "%")[0]))
	return prefixErr == nil && addressErr == nil && prefix.Bits() == prefix.Addr().BitLen() && prefix.Addr() == address
}

func emptyRouteValue(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func inspectRules(ctx context.Context, runner command.Runner) []model.Issue {
	var issues []model.Issue
	for _, family := range []string{"-4", "-6"} {
		output, err := runner.Run(ctx, "ip", "-j", family, "rule", "show")
		if err != nil {
			issues = append(issues, blocker("policy-routing", fmt.Sprintf("cannot inspect %s policy rules: %v", family, err)))
			continue
		}
		var rules []rule
		if err := json.Unmarshal(output, &rules); err != nil {
			issues = append(issues, blocker("policy-routing", fmt.Sprintf("cannot parse %s policy rules: %v", family, err)))
			continue
		}
		for _, candidate := range rules {
			switch candidate.Priority {
			case 0, 32766, 32767:
			default:
				issues = append(issues, blocker("policy-routing", fmt.Sprintf("custom routing rule with priority %d is unsupported", candidate.Priority)))
			}
		}
	}
	return issues
}

func inspectAdditionalPhysicalUplinks(ctx context.Context, runner command.Runner, root, selected string) []model.Issue {
	output, err := runner.Run(ctx, "ip", "-j", "address", "show")
	if err != nil {
		return []model.Issue{blocker("uplink-enumeration", err.Error())}
	}
	var interfaces []interfaceAddress
	if err := json.Unmarshal(output, &interfaces); err != nil {
		return []model.Issue{blocker("uplink-enumeration", "cannot parse the host interface inventory")}
	}
	var issues []model.Issue
	for _, candidate := range interfaces {
		if candidate.Name == selected || candidate.Name == "lo" || readNetworkDriver(root, candidate.Name) == "" {
			continue
		}
		for _, address := range candidate.AddrInfos {
			if address.Scope == "global" && !address.Deprecated {
				issues = append(issues, blocker("multi-uplink", fmt.Sprintf("additional physical interface %s has global address %s/%d", candidate.Name, address.Local, address.PrefixLen)))
				break
			}
		}
	}
	return issues
}

func inspectConfiguration(root, interfaceName string, interfaceIndex int, mac string, addresses []string) sourceEvidence {
	patterns := []string{
		"etc/netplan/*.yaml", "etc/netplan/*.yml",
		"etc/systemd/network/*.network",
		"etc/network/interfaces", "etc/network/interfaces.d/*",
		"etc/NetworkManager/system-connections/*",
		"var/lib/dhcp/*", "var/lib/NetworkManager/*lease*", "run/systemd/netif/leases/*",
	}
	var evidence sourceEvidence
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() || info.Size() > 2*1024*1024 {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			content := strings.ToLower(string(data))
			relevant := strings.Contains(content, strings.ToLower(interfaceName)) || strings.Contains(content, strings.ToLower(mac))
			for _, address := range addresses {
				host, _, _ := strings.Cut(address, "/")
				relevant = relevant || strings.Contains(content, strings.ToLower(host))
			}
			isSystemdLease := strings.Contains(filepath.ToSlash(path), "/run/systemd/netif/leases/")
			if isSystemdLease {
				relevant = filepath.Base(path) == strconv.Itoa(interfaceIndex)
			}
			if !relevant {
				continue
			}
			if !seen[path] {
				evidence.Paths = append(evidence.Paths, strings.TrimPrefix(path, root))
				seen[path] = true
			}
			lowerPath := strings.ToLower(path)
			if strings.Contains(content, "dhcp4: true") || strings.Contains(content, "inet dhcp") || strings.Contains(content, "method=auto") || strings.Contains(content, "dhcp=ipv4") || strings.Contains(content, "dhcp=yes") {
				evidence.DHCP4 = true
			}
			if strings.Contains(content, "dhcp6: true") || strings.Contains(content, "inet6 dhcp") || strings.Contains(content, "dhcp=ipv6") || strings.Contains(content, "dhcp=yes") {
				evidence.DHCP6 = true
			}
			if strings.Contains(lowerPath, "lease") {
				if strings.Contains(content, "address=") || strings.Contains(content, "fixed-address") {
					evidence.Lease4 = true
				}
				if strings.Contains(content, "dhcp6") || strings.Contains(content, "ia-na") {
					evidence.Lease6 = true
				}
			}
		}
	}
	sort.Strings(evidence.Paths)
	return evidence
}

func detectDNS(ctx context.Context, runner command.Runner, root, interfaceName string) []string {
	var servers []string
	if output, err := runner.Run(ctx, "resolvectl", "dns", interfaceName); err == nil {
		line := strings.TrimSpace(string(output))
		if _, values, ok := strings.Cut(line, ":"); ok {
			servers = append(servers, strings.Fields(values)...)
		}
	}
	for _, path := range []string{"run/systemd/resolve/resolv.conf", "etc/resolv.conf"} {
		if len(servers) > 0 {
			break
		}
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) == 2 && fields[0] == "nameserver" {
				servers = append(servers, fields[1])
			}
		}
		_ = file.Close()
	}
	unique := make(map[string]bool)
	result := make([]string, 0, len(servers))
	for _, server := range servers {
		address, err := netip.ParseAddr(strings.TrimSpace(server))
		if err != nil || address.IsLoopback() || address.IsUnspecified() || unique[address.String()] {
			continue
		}
		if address.IsLinkLocalUnicast() && address.Zone() == "" {
			address = address.WithZone(interfaceName)
		}
		unique[address.String()] = true
		result = append(result, address.String())
	}
	return result
}

func gatewayOutside(gateway string, prefixes []string) bool {
	address, err := netip.ParseAddr(strings.TrimSpace(strings.Split(gateway, "%")[0]))
	if err != nil || address.IsLinkLocalUnicast() {
		return false
	}
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(address) {
			return false
		}
	}
	return gateway != ""
}

func normalizeMAC(value string) string {
	address, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(address) != 6 {
		return ""
	}
	return strings.ToUpper(address.String())
}

func readNetworkDriver(root, interfaceName string) string {
	path := filepath.Join(root, "sys", "class", "net", interfaceName, "device", "driver")
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil && filepath.Base(resolved) != "driver" {
		return filepath.Base(resolved)
	}
	// Test fixtures use a regular file because git cannot represent sysfs links.
	if data, readErr := os.ReadFile(path); readErr == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

func supportedNetworkDriver(driver string) bool {
	canonical := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(driver)), "-", "_")
	switch canonical {
	case "virtio_net", "virtio_pci", "e1000", "e1000e", "vmxnet3", "hv_netvsc", "xen_netfront", "vif", "8139cp", "8139too":
		return true
	default:
		return false
	}
}

func hasFlag(flags []string, expected string) bool {
	for _, value := range flags {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func hasMaster(value json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(value))
	return trimmed != "" && trimmed != "null" && trimmed != "0" && trimmed != `""`
}

func appendIssue(issues []model.Issue, issue *model.Issue) []model.Issue {
	if issue == nil {
		return issues
	}
	return append(issues, *issue)
}

func blocker(code, message string) model.Issue {
	return model.Issue{Severity: model.SeverityBlocker, Code: code, Message: message}
}

func parseMTU(value string) int {
	mtu, _ := strconv.Atoi(strings.TrimSpace(value))
	return mtu
}
