package network

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/parhamfa/chr-install/internal/model"
)

func RouterOSScript(plan model.NetworkPlan) (string, error) {
	if err := Validate(plan); err != nil {
		return "", err
	}
	hardware, _ := net.ParseMAC(plan.MAC)
	mac := strings.ToUpper(hardware.String())
	var lines []string
	lines = append(lines,
		":delay 15s",
		":local targetMac \""+mac+"\"",
		":local uplink [/interface/ethernet/find where mac-address=$targetMac]",
		":if ([:len $uplink] != 1) do={ :log error \"chr-install: uplink MAC not found or ambiguous\"; :error \"chr-install uplink mismatch\" }",
		":local uplinkName [/interface/ethernet/get $uplink name]",
		":log info (\"chr-install: applying network plan to \" . $uplinkName)",
		fmt.Sprintf("/interface/ethernet/set $uplink mtu=%d", plan.MTU),
		"/ip/dhcp-client/remove [find where interface=$uplinkName]",
		"/ip/address/remove [find where interface=$uplinkName and dynamic=no]",
		"/ip/route/remove [find where comment=\"chr-install\"]",
		"/ip/route/remove [find where dst-address=\"0.0.0.0/0\" and dynamic=no]",
		"/ipv6/dhcp-client/remove [find where interface=$uplinkName]",
		"/ipv6/address/remove [find where interface=$uplinkName and dynamic=no]",
		"/ipv6/route/remove [find where comment=\"chr-install\"]",
		"/ipv6/route/remove [find where dst-address=\"::/0\" and dynamic=no]",
		":delay 1s",
	)

	if plan.IPv4.Mode == "dhcp" {
		lines = append(lines, fmt.Sprintf("/ip/dhcp-client/add interface=$uplinkName add-default-route=yes use-peer-dns=%s use-peer-ntp=no disabled=no comment=\"chr-install\"", rosBool(plan.IPv4.UsePeerDNS)))
	} else if plan.IPv4.Mode == "static" {
		addresses := append([]string(nil), plan.IPv4.Addresses...)
		sort.Strings(addresses)
		for _, address := range addresses {
			prefix, _ := netip.ParsePrefix(address)
			lines = append(lines, fmt.Sprintf("/ip/address/add address=%s interface=$uplinkName comment=\"chr-install\"", prefix.String()))
		}
		targetScope := ""
		if plan.IPv4.GatewayOnLink {
			lines = append(lines, fmt.Sprintf("/ip/route/add dst-address=%s/32 gateway=$uplinkName scope=10 comment=\"chr-install\"", plan.IPv4.Gateway))
			targetScope = " target-scope=11"
		}
		lines = append(lines, fmt.Sprintf("/ip/route/add dst-address=0.0.0.0/0 gateway=%s%s comment=\"chr-install\"", plan.IPv4.Gateway, targetScope))
	}

	lines = append(lines, fmt.Sprintf("/ipv6/settings/set accept-router-advertisements=%s", rosBool(plan.IPv6.SLAAC)))
	if plan.IPv6.DHCP {
		lines = append(lines, fmt.Sprintf("/ipv6/dhcp-client/add interface=$uplinkName request=address add-default-route=yes use-peer-dns=%s disabled=no comment=\"chr-install\"", rosBool(plan.IPv6.UsePeerDNS)))
	}
	addresses := append([]string(nil), plan.IPv6.Addresses...)
	sort.Strings(addresses)
	for _, address := range addresses {
		prefix, _ := netip.ParsePrefix(address)
		lines = append(lines, fmt.Sprintf("/ipv6/address/add address=%s interface=$uplinkName advertise=no comment=\"chr-install\"", prefix.String()))
	}
	if plan.IPv6.Gateway != "" {
		gateway := strings.Split(plan.IPv6.Gateway, "%")[0]
		recursiveGateway := plan.IPv6.GatewayOnLink && !mustAddr(gateway).IsLinkLocalUnicast()
		if recursiveGateway {
			lines = append(lines, fmt.Sprintf("/ipv6/route/add dst-address=%s/128 gateway=$uplinkName scope=10 comment=\"chr-install\"", gateway))
		}
		if mustAddr(gateway).IsLinkLocalUnicast() {
			lines = append(lines,
				fmt.Sprintf(":local ipv6Gateway (\"%s%%\" . $uplinkName)", gateway),
				"/ipv6/route/add dst-address=::/0 gateway=$ipv6Gateway comment=\"chr-install\"",
			)
		} else {
			targetScope := ""
			if recursiveGateway {
				targetScope = " target-scope=11"
			}
			lines = append(lines, fmt.Sprintf("/ipv6/route/add dst-address=::/0 gateway=%s%s comment=\"chr-install\"", gateway, targetScope))
		}
	}
	if len(plan.DNS) > 0 {
		servers := append([]string(nil), plan.DNS...)
		sort.Strings(servers)
		if expression, zoned := dnsExpression(servers); zoned {
			lines = append(lines, ":local dnsServers ("+expression+")", "/ip/dns/set servers=$dnsServers")
		} else {
			lines = append(lines, fmt.Sprintf("/ip/dns/set servers=\"%s\"", strings.Join(servers, ",")))
		}
	} else {
		lines = append(lines, "/ip/dns/set servers=\"\"")
	}
	lines = append(lines, ":log info \"chr-install: network plan applied\"")
	return strings.Join(lines, "\n") + "\n", nil
}

func rosBool(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func mustAddr(value string) netip.Addr {
	address, _ := netip.ParseAddr(value)
	return address
}

func dnsExpression(servers []string) (string, bool) {
	var parts []string
	var zoned bool
	for index, value := range servers {
		if index > 0 {
			parts = append(parts, "\",\"")
		}
		address, _ := netip.ParseAddr(value)
		if address.Zone() != "" {
			zoned = true
			parts = append(parts, "\""+address.WithZone("").String()+"%\"", "$uplinkName")
		} else {
			parts = append(parts, "\""+address.String()+"\"")
		}
	}
	return strings.Join(parts, " . "), zoned
}
