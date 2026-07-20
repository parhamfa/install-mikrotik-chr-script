//go:build integration && linux

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
	"golang.org/x/sys/unix"
)

func TestNetworkNamespacePlans(t *testing.T) {
	if os.Getenv("CHR_NETNS_INTEGRATION") != "1" {
		t.Skip("set CHR_NETNS_INTEGRATION=1 and run as root")
	}
	if os.Geteuid() != 0 {
		t.Fatal("network namespace integration requires root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatal(err)
	}

	t.Run("static IPv4, DNS, MTU, and off-link gateway", func(t *testing.T) {
		fixture := newNamespaceFixture(t, 1, 1400, "nameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\n", "")
		fixture.ip("address", "add", "198.51.100.10/32", "dev", "uplink")
		fixture.ip("route", "add", "default", "via", "192.0.2.1", "dev", "uplink", "onlink")
		plan, issues := Detect(context.Background(), fixture.runner(), namespaceProber{}, fixture.root)
		assertNoBlockers(t, issues)
		if plan.IPv4.Mode != "static" || strings.Join(plan.IPv4.Addresses, ",") != "198.51.100.10/32" || plan.IPv4.Gateway != "192.0.2.1" || !plan.IPv4.GatewayOnLink {
			t.Fatalf("unexpected off-link IPv4 plan: %#v", plan.IPv4)
		}
		if plan.MTU != 1400 || strings.Join(plan.DNS, ",") != "8.8.8.8,2001:4860:4860::8888" {
			t.Fatalf("unexpected MTU/DNS plan: %#v", plan)
		}
	})

	t.Run("DHCP DISCOVER offer", func(t *testing.T) {
		config := "network:\n  ethernets:\n    uplink:\n      dhcp4: true\n"
		fixture := newNamespaceFixture(t, 2, 1500, "nameserver 192.0.2.53\n", config)
		fixture.startDHCPServer()
		fixture.ip("route", "add", "default", "via", "192.0.2.1", "dev", "uplink", "onlink")
		plan, issues := Detect(context.Background(), fixture.runner(), namespaceDHCPProber{name: fixture.name}, fixture.root)
		assertNoBlockers(t, issues)
		if plan.IPv4.Mode != "dhcp" || !plan.DHCPProbe.Offered || plan.DHCPProbe.Address != "192.0.2.20" {
			t.Fatalf("unexpected DHCP plan: %#v", plan)
		}
		if plan.Evidence != model.EvidenceVerified || plan.IPv4.Evidence != model.EvidenceVerified {
			t.Fatalf("established DHCP offer was not verified: %#v", plan)
		}
	})

	t.Run("SLAAC, DHCPv6, static IPv6, and dual stack", func(t *testing.T) {
		config := "network:\n  ethernets:\n    uplink:\n      dhcp6: true\n"
		fixture := newNamespaceFixture(t, 3, 1500, "nameserver 2001:4860:4860::8844\n", config)
		fixture.ip("address", "add", "192.0.2.20/24", "dev", "uplink")
		fixture.ip("route", "add", "default", "via", "192.0.2.1", "dev", "uplink")
		fixture.startRouterAdvertisement()
		fixture.ip("-6", "address", "add", "2001:db8:2::20/64", "dev", "uplink", "nodad")
		plan, issues := Detect(context.Background(), fixture.runner(), namespaceProber{}, fixture.root)
		assertNoBlockers(t, issues)
		gateway := net.ParseIP(plan.IPv6.Gateway)
		if plan.IPv4.Mode != "static" || !plan.IPv6.SLAAC || !plan.IPv6.DHCP || strings.Join(plan.IPv6.Addresses, ",") != "2001:db8:2::20/64" || gateway == nil || !gateway.IsLinkLocalUnicast() {
			t.Fatalf("unexpected dual-stack plan: %#v", plan)
		}
	})
}

type namespaceFixture struct {
	t      *testing.T
	name   string
	hostIf string
	root   string
	uplink string
}

func newNamespaceFixture(t *testing.T, index, mtu int, resolvConf, netplan string) *namespaceFixture {
	t.Helper()
	suffix := fmt.Sprintf("%d%d", os.Getpid()%10000, index)
	fixture := &namespaceFixture{t: t, name: "cin" + suffix, hostIf: "cih" + suffix, root: t.TempDir(), uplink: "uplink"}
	runIP(t, "netns", "add", fixture.name)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", fixture.name).Run() })
	runIP(t, "link", "add", fixture.hostIf, "type", "veth", "peer", "name", fixture.uplink)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", fixture.hostIf).Run() })
	runIP(t, "link", "set", fixture.uplink, "netns", fixture.name)
	runIP(t, "link", "set", fixture.hostIf, "up")
	fixture.ip("link", "set", "lo", "up")
	fixture.ip("link", "set", fixture.uplink, "mtu", fmt.Sprint(mtu), "up")
	fixture.write("sys/class/net/uplink/device/driver", "virtio_net\n")
	fixture.write("etc/resolv.conf", resolvConf)
	if netplan != "" {
		fixture.write("etc/netplan/50-test.yaml", netplan)
	}
	return fixture
}

func (fixture *namespaceFixture) write(relative, value string) {
	fixture.t.Helper()
	path := filepath.Join(fixture.root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fixture.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *namespaceFixture) ip(args ...string) {
	fixture.t.Helper()
	all := append([]string{"-n", fixture.name}, args...)
	runIP(fixture.t, all...)
}

func (fixture *namespaceFixture) runner() namespaceRunner {
	return namespaceRunner{name: fixture.name}
}

func (fixture *namespaceFixture) startDHCPServer() {
	fixture.t.Helper()
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		fixture.t.Fatal("dnsmasq is required for the DHCP namespace scenario")
	}
	runIP(fixture.t, "address", "add", "192.0.2.1/24", "dev", fixture.hostIf)
	var logs bytes.Buffer
	process := exec.Command("dnsmasq",
		"--no-daemon", "--conf-file=/dev/null", "--port=0", "--bind-interfaces", "--interface="+fixture.hostIf,
		"--dhcp-authoritative", "--dhcp-range=192.0.2.20,192.0.2.20,255.255.255.0,1m",
	)
	process.Stdout, process.Stderr = &logs, &logs
	if err := process.Start(); err != nil {
		fixture.t.Fatal(err)
	}
	fixture.t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	time.Sleep(150 * time.Millisecond)
	if process.ProcessState != nil {
		fixture.t.Fatalf("dnsmasq exited during startup: %s", logs.String())
	}
}

func (fixture *namespaceFixture) startRouterAdvertisement() {
	fixture.t.Helper()
	if _, err := exec.LookPath("dnsmasq"); err != nil {
		fixture.t.Fatal("dnsmasq is required for the SLAAC namespace scenario")
	}
	runIP(fixture.t, "-6", "address", "add", "2001:db8:1::1/64", "dev", fixture.hostIf)
	output, err := exec.Command("ip", "netns", "exec", fixture.name, "sysctl", "-qw", "net.ipv6.conf.uplink.accept_ra=2").CombinedOutput()
	if err != nil {
		fixture.t.Fatalf("enable router advertisements: %v: %s", err, strings.TrimSpace(string(output)))
	}
	var logs bytes.Buffer
	process := exec.Command("dnsmasq",
		"--no-daemon", "--conf-file=/dev/null", "--port=0", "--bind-interfaces", "--interface="+fixture.hostIf,
		"--enable-ra", "--dhcp-range=::,constructor:"+fixture.hostIf+",ra-stateless,64,10m", "--ra-param="+fixture.hostIf+",3,30",
	)
	process.Stdout, process.Stderr = &logs, &logs
	if err := process.Start(); err != nil {
		fixture.t.Fatal(err)
	}
	fixture.t.Cleanup(func() {
		_ = process.Process.Kill()
		_ = process.Wait()
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		addresses, addressErr := exec.Command("ip", "-n", fixture.name, "-j", "-6", "address", "show", "dev", fixture.uplink, "scope", "global").CombinedOutput()
		if addressErr == nil && bytes.Contains(addresses, []byte(`"dynamic":true`)) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	fixture.t.Fatalf("SLAAC address did not arrive: %s", logs.String())
}

func runIP(t *testing.T, args ...string) {
	t.Helper()
	output, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

type namespaceRunner struct {
	name string
}

func (runner namespaceRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "resolvectl" {
		return nil, fmt.Errorf("resolvectl is not active in the fixture namespace")
	}
	if name != "ip" {
		return nil, fmt.Errorf("unexpected namespace command %s", name)
	}
	all := append([]string{"-n", runner.name}, args...)
	output, err := exec.CommandContext(ctx, "ip", all...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %s: %w: %s", strings.Join(all, " "), err, strings.TrimSpace(string(output)))
	}
	if strings.Join(args, " ") == "-j link show dev uplink" {
		var links []map[string]any
		if err := json.Unmarshal(output, &links); err != nil {
			return nil, err
		}
		for _, link := range links {
			delete(link, "linkinfo") // veth is only the namespace test transport.
		}
		return json.Marshal(links)
	}
	return output, nil
}

func (namespaceRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

type namespaceProber struct{}

func (namespaceProber) Probe(_ context.Context, _ string, _ net.HardwareAddr, _ time.Duration) (model.DHCPProbe, error) {
	return model.DHCPProbe{Attempted: true, Offered: false}, nil
}

type namespaceDHCPProber struct {
	name string
}

func (prober namespaceDHCPProber) Probe(ctx context.Context, interfaceName string, mac net.HardwareAddr, timeout time.Duration) (result model.DHCPProbe, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return result, err
	}
	defer current.Close()
	target, err := os.Open(filepath.Join("/var/run/netns", prober.name))
	if err != nil {
		return result, err
	}
	defer target.Close()
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return result, err
	}
	defer func() {
		if restoreErr := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET); err == nil && restoreErr != nil {
			err = restoreErr
		}
	}()
	return ProbeDHCP(ctx, interfaceName, mac, timeout)
}

func assertNoBlockers(t *testing.T, issues []model.Issue) {
	t.Helper()
	for _, issue := range issues {
		if issue.Severity == model.SeverityBlocker {
			t.Fatalf("unexpected blocker: %#v (all issues: %#v)", issue, issues)
		}
	}
}
