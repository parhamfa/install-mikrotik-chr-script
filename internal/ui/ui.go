package ui

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/parhamfa/chr-install/internal/model"
	"github.com/parhamfa/chr-install/internal/network"
	"github.com/parhamfa/chr-install/internal/report"
)

type Review struct {
	Network      model.NetworkPlan
	Recovery     bool
	RiskOverride bool
}

func ReviewPreflight(preflight model.Preflight) (Review, error) {
	decision := Review{Network: preflight.Network}
	if preflight.Blocked() {
		return decision, fmt.Errorf("preflight is blocked")
	}
	continueReview := true
	if err := form(
		huh.NewGroup(
			huh.NewNote().Title("CHR installation preflight").Description(report.Format(preflight)),
			huh.NewConfirm().Title("Review and edit the proposed network configuration?").Value(&continueReview).Affirmative("Continue").Negative("Cancel"),
		),
	).Run(); err != nil {
		return decision, err
	}
	if !continueReview {
		return decision, fmt.Errorf("cancelled")
	}

	v4Addresses := strings.Join(decision.Network.IPv4.Addresses, ", ")
	v6Addresses := strings.Join(decision.Network.IPv6.Addresses, ", ")
	dns := strings.Join(decision.Network.DNS, ", ")
	mtu := strconv.Itoa(decision.Network.MTU)
	features := make([]string, 0, 3)
	if decision.Network.IPv6.SLAAC {
		features = append(features, "slaac")
	}
	if decision.Network.IPv6.DHCP {
		features = append(features, "dhcp")
	}
	if len(decision.Network.IPv6.Addresses) > 0 {
		features = append(features, "static")
	}
	if err := form(
		huh.NewGroup(
			huh.NewInput().Title("Observed Linux uplink").Description("Used for evidence and link-local DNS zones; CHR still matches by MAC").Value(&decision.Network.InterfaceName),
			huh.NewInput().Title("Uplink MAC address").Description("CHR selects its first-boot interface using this address").Value(&decision.Network.MAC),
		),
		huh.NewGroup(
			huh.NewSelect[string]().Title("IPv4 mode").Options(
				huh.NewOption("Static", "static"),
				huh.NewOption("DHCP", "dhcp"),
				huh.NewOption("Disabled", "none"),
			).Value(&decision.Network.IPv4.Mode),
			huh.NewInput().Title("IPv4 address/prefix").Description("Comma-separated; ignored for DHCP").Value(&v4Addresses),
			huh.NewInput().Title("IPv4 default gateway").Value(&decision.Network.IPv4.Gateway),
			huh.NewConfirm().Title("IPv4 gateway is off-link/routed").Value(&decision.Network.IPv4.GatewayOnLink),
			huh.NewConfirm().Title("Use DNS supplied by IPv4 DHCP").Value(&decision.Network.IPv4.UsePeerDNS),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("IPv6 modes").Options(
				huh.NewOption("SLAAC", "slaac"),
				huh.NewOption("DHCPv6 address", "dhcp"),
				huh.NewOption("Static address", "static"),
			).Value(&features),
			huh.NewInput().Title("IPv6 address/prefix").Description("Comma-separated; used when Static is selected").Value(&v6Addresses),
			huh.NewInput().Title("IPv6 default gateway").Description("Leave empty when learned through RA/DHCPv6").Value(&decision.Network.IPv6.Gateway),
			huh.NewConfirm().Title("IPv6 gateway is off-link/routed").Value(&decision.Network.IPv6.GatewayOnLink),
			huh.NewConfirm().Title("Use DNS supplied by DHCPv6").Value(&decision.Network.IPv6.UsePeerDNS),
		),
		huh.NewGroup(
			huh.NewInput().Title("DNS servers").Description("Comma-separated IPv4 or IPv6 addresses").Value(&dns),
			huh.NewInput().Title("Uplink MTU").Value(&mtu),
		),
	).Run(); err != nil {
		return decision, err
	}
	decision.Network.IPv4.Addresses = network.ParseList(v4Addresses)
	decision.Network.IPv6.Addresses = network.ParseList(v6Addresses)
	decision.Network.DNS = network.ParseList(dns)
	decision.Network.IPv6.SLAAC = contains(features, "slaac")
	decision.Network.IPv6.DHCP = contains(features, "dhcp")
	if !contains(features, "static") {
		decision.Network.IPv6.Addresses = nil
	}
	if len(features) == 0 {
		decision.Network.IPv6.Gateway = ""
		decision.Network.IPv6.GatewayOnLink = false
		decision.Network.IPv6.UsePeerDNS = false
	}
	parsedMTU, err := strconv.Atoi(strings.TrimSpace(mtu))
	if err != nil {
		return decision, fmt.Errorf("invalid MTU: %w", err)
	}
	decision.Network.MTU = parsedMTU
	if err := network.Validate(decision.Network); err != nil {
		return decision, err
	}
	if !reflect.DeepEqual(decision.Network, preflight.Network) {
		decision.Network.Evidence = model.EvidenceUser
		decision.Network.IPv4.Evidence = model.EvidenceUser
		decision.Network.IPv6.Evidence = model.EvidenceUser
	}
	if decision.Network.Evidence != model.EvidenceVerified {
		phrase := ""
		if err := form(huh.NewGroup(
			huh.NewInput().Title("Network plan is not fully verified").Description("Type I ACCEPT UNVERIFIED NETWORK to continue").Value(&phrase).Validate(func(value string) error {
				if value != "I ACCEPT UNVERIFIED NETWORK" {
					return fmt.Errorf("exact acknowledgement required")
				}
				return nil
			}),
		)).Run(); err != nil {
			return decision, err
		}
	}

	if err := form(huh.NewGroup(
		huh.NewNote().Title("Installation method").Description(fmt.Sprintf("Target: %s\nMethod: %s\n\nThe target disk will be completely overwritten.", preflight.Disk.Fingerprint.Path, preflight.Disk.Method)),
		huh.NewConfirm().Title("Do you have working provider console or rescue access?").Value(&decision.Recovery).Affirmative("Yes").Negative("No"),
	)).Run(); err != nil {
		return decision, err
	}
	if !decision.Recovery {
		phrase := ""
		if err := form(huh.NewGroup(
			huh.NewInput().Title("No recovery path is available").Description("Type I ACCEPT NO RECOVERY to continue").Value(&phrase).Validate(func(value string) error {
				if value != "I ACCEPT NO RECOVERY" {
					return fmt.Errorf("exact acknowledgement required")
				}
				return nil
			}),
		)).Run(); err != nil {
			return decision, err
		}
		decision.RiskOverride = true
	}
	return decision, nil
}

func ConfirmUntested(version string) error {
	value := ""
	return form(huh.NewGroup(
		huh.NewInput().Title("Untested RouterOS release").Description("The image structure is compatible, but this exact version has not passed the QEMU matrix. Type " + version + " to continue.").Value(&value).Validate(func(input string) error {
			if strings.TrimSpace(input) != version {
				return fmt.Errorf("type the exact RouterOS version")
			}
			return nil
		}),
	)).Run()
}

func ConfirmDestruction(preflight model.Preflight, plan model.NetworkPlan) error {
	phrase := ""
	expected := "ERASE " + preflight.Disk.Fingerprint.Path
	confirmed := false
	err := form(
		huh.NewGroup(
			huh.NewNote().Title("Final installation plan").Description(fmt.Sprintf("RouterOS: %s long-term\nTarget: %s (%s)\nMethod: %s\n\n%s", preflight.Release.Version, preflight.Disk.Fingerprint.Path, preflight.Disk.Fingerprint.StableIdentity(), preflight.Disk.Method, report.Network(plan))),
			huh.NewInput().Title("Authorize disk erasure").Description("Type "+expected).Value(&phrase).Validate(func(input string) error {
				if input != expected {
					return fmt.Errorf("exact disk authorization required")
				}
				return nil
			}),
		),
		huh.NewGroup(
			huh.NewConfirm().Title("Begin installation and reboot now?").Description("There is no countdown. Selecting Begin starts the authorized transaction.").Value(&confirmed).Affirmative("Begin").Negative("Cancel"),
		),
	).Run()
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf("cancelled")
	}
	return nil
}

func form(groups ...*huh.Group) *huh.Form {
	return huh.NewForm(groups...).WithTheme(huh.ThemeCharm()).WithShowHelp(true)
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
