package network

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/parhamfa/chr-install/internal/model"
)

func Validate(plan model.NetworkPlan) error {
	if strings.TrimSpace(plan.InterfaceName) == "" {
		return fmt.Errorf("interface name is required")
	}
	mac, err := net.ParseMAC(plan.MAC)
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("a valid Ethernet MAC address is required")
	}
	if plan.MTU < 576 || plan.MTU > 9216 {
		return fmt.Errorf("MTU must be between 576 and 9216")
	}
	switch plan.IPv4.Mode {
	case "dhcp":
	case "static":
		if len(plan.IPv4.Addresses) == 0 {
			return fmt.Errorf("static IPv4 requires at least one address")
		}
		if plan.IPv4.Gateway == "" {
			return fmt.Errorf("static IPv4 requires a default gateway")
		}
	case "none":
	default:
		return fmt.Errorf("invalid IPv4 mode %q", plan.IPv4.Mode)
	}
	for _, value := range plan.IPv4.Addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("invalid IPv4 prefix %q", value)
		}
	}
	if plan.IPv4.Gateway != "" {
		address, err := netip.ParseAddr(strings.TrimSpace(plan.IPv4.Gateway))
		if err != nil || !address.Is4() {
			return fmt.Errorf("invalid IPv4 gateway %q", plan.IPv4.Gateway)
		}
	}
	for _, value := range plan.IPv6.Addresses {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || !prefix.Addr().Is6() {
			return fmt.Errorf("invalid IPv6 prefix %q", value)
		}
	}
	if plan.IPv6.Gateway != "" {
		value := strings.Split(strings.TrimSpace(plan.IPv6.Gateway), "%")[0]
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is6() {
			return fmt.Errorf("invalid IPv6 gateway %q", plan.IPv6.Gateway)
		}
	}
	for _, value := range plan.DNS {
		address, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return fmt.Errorf("invalid DNS server %q", value)
		}
		if address.IsLinkLocalUnicast() && address.Zone() != plan.InterfaceName {
			return fmt.Errorf("link-local DNS server %q must use zone %%%s", value, plan.InterfaceName)
		}
	}
	if plan.IPv4.Mode == "none" && !plan.IPv6.SLAAC && !plan.IPv6.DHCP && len(plan.IPv6.Addresses) == 0 {
		return fmt.Errorf("at least one IPv4 or IPv6 mode is required")
	}
	return nil
}

func ParseList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' })
	result := make([]string, 0, len(fields))
	for _, field := range fields {
		if trimmed := strings.TrimSpace(field); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
