package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
)

type fixtureRunner struct {
	responses map[string][]byte
}

func (runner fixtureRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	if value, ok := runner.responses[key]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("unexpected command: %s", key)
}

func (fixtureRunner) LookPath(name string) (string, error) { return "/usr/bin/" + name, nil }

type fixtureProber struct {
	result model.DHCPProbe
}

func (probe fixtureProber) Probe(_ context.Context, _ string, _ net.HardwareAddr, _ time.Duration) (model.DHCPProbe, error) {
	return probe.result, nil
}

func TestDetectCraftikStaticNetwork(t *testing.T) {
	root := filepath.Join("testdata", "craftik")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	runner := fixtureRunner{responses: map[string][]byte{
		"ip -j -4 route show table main": read("routes4.json"),
		"ip -j -6 route show table main": read("routes6.json"),
		"ip -j -4 rule show":             read("rules4.json"),
		"ip -j -6 rule show":             read("rules6.json"),
		"ip -j address show":             read("addresses.json"),
		"ip -j link show dev ens3":       read("link.json"),
		"ip -j address show dev ens3":    read("addresses.json"),
	}}
	plan, issues := Detect(context.Background(), runner, fixtureProber{result: model.DHCPProbe{Attempted: true, Offered: false}}, root)
	for _, issue := range issues {
		if issue.Severity == model.SeverityBlocker {
			t.Fatalf("unexpected blocker: %#v", issue)
		}
	}
	if plan.InterfaceName != "ens3" || plan.MAC != "D2:CB:48:5C:3E:71" || plan.MTU != 1500 {
		t.Fatalf("unexpected uplink: %#v", plan)
	}
	if plan.Driver != "virtio_net" {
		t.Fatalf("unexpected uplink driver: %q", plan.Driver)
	}
	if plan.IPv4.Mode != "static" || len(plan.IPv4.Addresses) != 1 || plan.IPv4.Addresses[0] != "45.135.242.144/24" {
		t.Fatalf("unexpected IPv4 plan: %#v", plan.IPv4)
	}
	if plan.IPv4.Gateway != "45.135.242.1" || plan.IPv4.GatewayOnLink {
		t.Fatalf("unexpected gateway: %#v", plan.IPv4)
	}
	if strings.Join(plan.DNS, ",") != "8.8.8.8,217.218.127.127" {
		t.Fatalf("unexpected DNS: %#v", plan.DNS)
	}
	if plan.DHCPProbe.Offered {
		t.Fatal("craftik fixture must not have DHCP")
	}
}

func TestDynamicAddressWithoutLeaseOrOfferIsBlocked(t *testing.T) {
	root := filepath.Join("testdata", "craftik")
	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	runner := fixtureRunner{responses: map[string][]byte{
		"ip -j -4 route show table main": []byte(`[{"dst":"default","gateway":"192.0.2.1","dev":"ens3","protocol":"dhcp","metric":100}]`),
		"ip -j -6 route show table main": read("routes6.json"),
		"ip -j -4 rule show":             read("rules4.json"),
		"ip -j -6 rule show":             read("rules6.json"),
		"ip -j address show":             []byte(`[{"ifindex":2,"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.20","prefixlen":24,"scope":"global","dynamic":true,"protocol":"dhcp"}]}]`),
		"ip -j link show dev ens3":       read("link.json"),
		"ip -j address show dev ens3":    []byte(`[{"ifindex":2,"ifname":"ens3","addr_info":[{"family":"inet","local":"192.0.2.20","prefixlen":24,"scope":"global","dynamic":true,"protocol":"dhcp"}]}]`),
	}}
	plan, issues := Detect(context.Background(), runner, fixtureProber{result: model.DHCPProbe{Attempted: true, Offered: false}}, root)
	if plan.IPv4.Mode != "dhcp" {
		t.Fatalf("expected DHCP plan, got %#v", plan.IPv4)
	}
	if plan.Evidence != model.EvidenceInferred {
		t.Fatalf("unverified DHCP plan was labeled %q", plan.Evidence)
	}
	found := false
	for _, issue := range issues {
		found = found || issue.Code == "dhcp-unverified" && issue.Severity == model.SeverityBlocker
	}
	if !found {
		t.Fatalf("expected DHCP evidence blocker, got %#v", issues)
	}
}

func TestSupportedNetworkDrivers(t *testing.T) {
	for _, driver := range []string{"virtio_net", "e1000", "vmxnet3", "hv_netvsc", "xen-netfront"} {
		if !supportedNetworkDriver(driver) {
			t.Fatalf("expected %s to be supported", driver)
		}
	}
	if supportedNetworkDriver("mystery_nic") {
		t.Fatal("unknown network driver must fail closed")
	}
}

func TestValidateOffLinkStaticPlan(t *testing.T) {
	plan := model.NetworkPlan{
		InterfaceName: "ens3",
		MAC:           "02:00:00:00:00:01",
		MTU:           1500,
		IPv4: model.IPv4Plan{
			Mode:          "static",
			Addresses:     []string{"192.0.2.10/32"},
			Gateway:       "192.0.2.1",
			GatewayOnLink: true,
		},
	}
	if err := Validate(plan); err != nil {
		t.Fatal(err)
	}
	script, err := RouterOSScript(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"mac-address=$targetMac",
		"/ip/dhcp-client/remove [find where interface=$uplinkName]",
		"/ip/address/remove [find where interface=$uplinkName and dynamic=no]",
		"accept-router-advertisements=no",
		"address=192.0.2.10/32",
		"dst-address=192.0.2.1/32 gateway=$uplinkName scope=10",
		"dst-address=0.0.0.0/0 gateway=192.0.2.1",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q:\n%s", expected, script)
		}
	}
}

func TestGatewayOutside(t *testing.T) {
	if gatewayOutside("192.0.2.1", []string{"192.0.2.10/24"}) {
		t.Fatal("same-subnet gateway reported off-link")
	}
	if !gatewayOutside("192.0.2.1", []string{"198.51.100.10/32"}) {
		t.Fatal("routed gateway was not reported off-link")
	}
}

func TestSelectDefaultRejectsLowerPriorityFailover(t *testing.T) {
	selected, issue := selectDefault([]route{
		{Destination: "default", Gateway: "192.0.2.1", Device: "ens3", Metric: 100},
		{Destination: "default", Gateway: "198.51.100.1", Device: "ens4", Metric: 200},
	}, "IPv4")
	if selected == nil || issue == nil || issue.Code != "multiple-defaults" {
		t.Fatalf("expected distinct default routes to be blocked: selected=%#v issue=%#v", selected, issue)
	}
}

func TestInspectRouteSetRejectsUntranslatedStaticRoute(t *testing.T) {
	defaultRoute := &route{Destination: "default", Gateway: "192.0.2.1", Device: "ens3"}
	issues := inspectRouteSet([]route{
		*defaultRoute,
		{Destination: "192.0.2.0/24", Device: "ens3", Protocol: "kernel"},
		{Destination: "203.0.113.0/24", Gateway: "192.0.2.2", Device: "ens3", Protocol: "static"},
	}, defaultRoute, "ens3", "IPv4")
	if len(issues) != 1 || issues[0].Code != "unsupported-route" {
		t.Fatalf("expected only the untranslated route to block, got %#v", issues)
	}
}

func TestSystemdLeaseMustMatchSelectedInterfaceIndex(t *testing.T) {
	root := t.TempDir()
	leaseDir := filepath.Join(root, "run", "systemd", "netif", "leases")
	if err := os.MkdirAll(leaseDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leaseDir, "3"), []byte("ADDRESS=192.0.2.20\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if evidence := inspectConfiguration(root, "ens3", 2, "02:00:00:00:00:01", nil); evidence.Lease4 {
		t.Fatalf("lease from another interface was accepted: %#v", evidence)
	}
	if err := os.WriteFile(filepath.Join(leaseDir, "2"), []byte("ADDRESS=192.0.2.21\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if evidence := inspectConfiguration(root, "ens3", 2, "02:00:00:00:00:01", nil); !evidence.Lease4 {
		t.Fatalf("selected interface lease was not accepted: %#v", evidence)
	}
}

func TestRouterOSDualStackAndScopedDNS(t *testing.T) {
	plan := model.NetworkPlan{
		InterfaceName: "ens3",
		MAC:           "02:00:00:00:00:01",
		MTU:           1400,
		IPv4:          model.IPv4Plan{Mode: "dhcp", UsePeerDNS: false},
		IPv6: model.IPv6Plan{
			SLAAC:      true,
			DHCP:       true,
			Addresses:  []string{"2001:db8::10/64"},
			UsePeerDNS: true,
		},
		DNS: []string{"2001:4860:4860::8888", "fe80::53%ens3"},
	}
	script, err := RouterOSScript(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"accept-router-advertisements=yes",
		"request=address add-default-route=yes use-peer-dns=yes",
		"address=2001:db8::10/64",
		`"fe80::53%" . $uplinkName`,
		"/ip/dns/set servers=$dnsServers",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q:\n%s", expected, script)
		}
	}
}
