package report

import (
	"fmt"
	"strings"

	"github.com/parhamfa/chr-install/internal/model"
)

func Format(preflight model.Preflight) string {
	var output strings.Builder
	fmt.Fprintf(&output, "chr-install preflight\n")
	fmt.Fprintf(&output, "Host:       %s %s (%s), kernel %s, %s, console %s\n", preflight.Host.Distribution, preflight.Host.Version, preflight.Host.Architecture, preflight.Host.Kernel, preflight.Host.Firmware, preflight.Host.Console)
	fmt.Fprintf(&output, "Memory:     %s\n", bytes(preflight.Host.MemoryBytes))
	fmt.Fprintf(&output, "Target:     %s, %s, id %s, major:minor %s\n", preflight.Disk.Fingerprint.Path, bytes(preflight.Disk.Fingerprint.SizeBytes), preflight.Disk.Fingerprint.StableIdentity(), empty(preflight.Disk.Fingerprint.MajorMinor, "unknown"))
	fmt.Fprintf(&output, "Storage:    model %s, transport %s, driver %s\n", empty(preflight.Disk.Fingerprint.Model, "unknown"), empty(preflight.Disk.Fingerprint.Transport, "unknown"), empty(preflight.Disk.Fingerprint.Driver, "unknown"))
	fmt.Fprintf(&output, "Method:     %s\n", preflight.Disk.Method)
	fmt.Fprintf(&output, "Uplink:     %s, MAC %s, MTU %d, driver %s\n", preflight.Network.InterfaceName, preflight.Network.MAC, preflight.Network.MTU, empty(preflight.Network.Driver, "unknown"))
	fmt.Fprintf(&output, "IPv4:      %s", preflight.Network.IPv4.Mode)
	if len(preflight.Network.IPv4.Addresses) > 0 {
		fmt.Fprintf(&output, " %s", strings.Join(preflight.Network.IPv4.Addresses, ", "))
	}
	if preflight.Network.IPv4.Gateway != "" {
		fmt.Fprintf(&output, " via %s", preflight.Network.IPv4.Gateway)
		if preflight.Network.IPv4.GatewayOnLink {
			output.WriteString(" (off-link)")
		}
	}
	fmt.Fprintf(&output, " [%s]\n", preflight.Network.IPv4.Evidence)
	fmt.Fprintf(&output, "IPv6:      %s\n", formatIPv6(preflight.Network.IPv6))
	fmt.Fprintf(&output, "DNS:       %s\n", empty(strings.Join(preflight.Network.DNS, ", "), "none detected"))
	fmt.Fprintf(&output, "Evidence:  %s", preflight.Network.Evidence)
	if len(preflight.Network.Sources) > 0 {
		fmt.Fprintf(&output, " from %s", strings.Join(preflight.Network.Sources, ", "))
	}
	output.WriteByte('\n')
	if preflight.Network.DHCPProbe.Attempted {
		if preflight.Network.DHCPProbe.Offered {
			fmt.Fprintf(&output, "DHCP probe: offer %s from %s\n", preflight.Network.DHCPProbe.Address, preflight.Network.DHCPProbe.Server)
		} else {
			fmt.Fprintf(&output, "DHCP probe: no offer")
			if preflight.Network.DHCPProbe.Message != "" {
				fmt.Fprintf(&output, " (%s)", preflight.Network.DHCPProbe.Message)
			}
			output.WriteByte('\n')
		}
	}
	bootMode := "boot not yet validated"
	if preflight.Release.Tested {
		bootMode = "BIOS validated"
	}
	if preflight.Release.Tested && preflight.Release.UEFIBoot {
		bootMode = "BIOS/UEFI validated"
	}
	fmt.Fprintf(&output, "RouterOS:  %s long-term, SHA-256 %s, %s\n", preflight.Release.Version, shortHash(preflight.Release.Checksum), bootMode)
	if len(preflight.Issues) > 0 {
		output.WriteString("\nFindings:\n")
		for _, issue := range preflight.Issues {
			fmt.Fprintf(&output, "  %-7s %-20s %s\n", strings.ToUpper(string(issue.Severity)), issue.Code, issue.Message)
		}
	}
	if preflight.Blocked() {
		output.WriteString("\nResult: BLOCKED\n")
	} else {
		output.WriteString("\nResult: READY FOR REVIEW\n")
	}
	return output.String()
}

func Network(plan model.NetworkPlan) string {
	var output strings.Builder
	fmt.Fprintf(&output, "Uplink %s (%s), MTU %d\n", plan.InterfaceName, plan.MAC, plan.MTU)
	if plan.IPv4.Mode == "dhcp" {
		output.WriteString("IPv4 DHCP\n")
	} else if plan.IPv4.Mode == "static" {
		fmt.Fprintf(&output, "IPv4 %s via %s", strings.Join(plan.IPv4.Addresses, ", "), plan.IPv4.Gateway)
		if plan.IPv4.GatewayOnLink {
			output.WriteString(" (off-link gateway)")
		}
		output.WriteByte('\n')
	}
	fmt.Fprintf(&output, "IPv6 %s\n", formatIPv6(plan.IPv6))
	fmt.Fprintf(&output, "DNS %s\n", empty(strings.Join(plan.DNS, ", "), "none"))
	return output.String()
}

func formatIPv6(plan model.IPv6Plan) string {
	var modes []string
	if plan.SLAAC {
		modes = append(modes, "SLAAC")
	}
	if plan.DHCP {
		modes = append(modes, "DHCPv6")
	}
	if len(plan.Addresses) > 0 {
		modes = append(modes, "static "+strings.Join(plan.Addresses, ", "))
	}
	if len(modes) == 0 {
		return "disabled"
	}
	value := strings.Join(modes, " + ")
	if plan.Gateway != "" {
		value += " via " + plan.Gateway
	}
	return value
}

func bytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	divisor, exponent := uint64(unit), 0
	for quotient := value / unit; quotient >= unit; quotient /= unit {
		divisor *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(divisor), "KMGTPE"[exponent])
}

func shortHash(value string) string {
	if len(value) > 12 {
		return value[:12] + "…"
	}
	return empty(value, "unavailable")
}

func empty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
