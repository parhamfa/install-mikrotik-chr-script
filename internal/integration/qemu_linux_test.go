//go:build integration && linux

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parhamfa/chr-install/internal/command"
	"github.com/parhamfa/chr-install/internal/mikrotik"
	"github.com/parhamfa/chr-install/internal/model"
)

func TestQEMUBoot(t *testing.T) {
	if os.Getenv("CHR_QEMU_INTEGRATION") != "1" {
		t.Skip("set CHR_QEMU_INTEGRATION=1 to download and boot the official image")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration test requires root to mount the CHR image")
	}
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	client := mikrotik.NewClient()
	release, err := client.ResolveLatest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if archivePath := os.Getenv("CHR_QEMU_ARCHIVE"); archivePath != "" {
		if _, err := os.Stat(archivePath); err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			http.ServeFile(writer, request, archivePath)
		}))
		defer server.Close()
		release.ImageURL = server.URL + "/chr.img.zip"
	}
	plan := model.NetworkPlan{
		InterfaceName: "integration0",
		MAC:           "52:54:00:12:34:56",
		MTU:           1500,
		IPv4: model.IPv4Plan{
			Mode:      "static",
			Addresses: []string{"10.0.2.15/24"},
			Gateway:   "10.0.2.2",
			Evidence:  model.EvidenceVerified,
		},
		DNS:      []string{"10.0.2.3"},
		Evidence: model.EvidenceVerified,
	}
	directory := t.TempDir()
	if artifactRoot := os.Getenv("CHR_QEMU_ARTIFACT_DIR"); artifactRoot != "" {
		if err := os.MkdirAll(artifactRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		directory, err = os.MkdirTemp(artifactRoot, "qemu-run-")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("preserving CHR artifacts in %s", directory)
	}
	prepared, err := client.Prepare(ctx, command.OSRunner{}, release, plan, directory)
	if err != nil {
		t.Fatal(err)
	}
	serialPath := filepath.Join(directory, "serial.log")
	serialSocket := filepath.Join(directory, "serial.sock")
	serial, err := os.Create(serialPath)
	if err != nil {
		t.Fatal(err)
	}
	defer serial.Close()
	arguments := []string{
		"-machine", "q35,accel=tcg", "-m", "256", "-display", "none", "-monitor", "none", "-no-reboot",
		"-serial", "unix:" + serialSocket + ",server=on,wait=off",
		"-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22",
	}
	diskArgs, err := qemuDiskArguments(os.Getenv("CHR_QEMU_DISK"), prepared.Path)
	if err != nil {
		t.Fatal(err)
	}
	nicArgs, err := qemuNICArguments(os.Getenv("CHR_QEMU_NIC"))
	if err != nil {
		t.Fatal(err)
	}
	arguments = append(arguments, diskArgs...)
	arguments = append(arguments, nicArgs...)
	expectUEFIBlock := os.Getenv("CHR_QEMU_EXPECT_UEFI_BLOCK") == "1"
	if os.Getenv("CHR_QEMU_FIRMWARE") == "uefi" {
		firmware, err := findOVMF()
		if err != nil {
			t.Fatal(err)
		}
		arguments = append(arguments, "-drive", "if=pflash,format=raw,readonly=on,file="+firmware)
	}
	process := exec.CommandContext(ctx, "qemu-system-x86_64", arguments...)
	process.Stdout, process.Stderr = serial, serial
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	console, err := connectSerialConsole(serialSocket, serial, 15*time.Second)
	if err != nil {
		_ = process.Process.Kill()
		_ = process.Wait()
		t.Fatal(err)
	}
	defer console.Close()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		connection, dialErr := net.DialTimeout("tcp", "127.0.0.1:2222", 2*time.Second)
		if dialErr == nil {
			_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
			banner := make([]byte, 128)
			count, _ := connection.Read(banner)
			_ = connection.Close()
			if strings.HasPrefix(string(banner[:count]), "SSH-") {
				if expectUEFIBlock {
					_ = process.Process.Kill()
					<-done
					t.Fatal("official CHR raw image unexpectedly booted with UEFI; update the version-specific preflight gate after validating it")
				}
				if err := verifyRouterOSConsole(console, plan); err != nil {
					_ = process.Process.Kill()
					<-done
					t.Fatalf("RouterOS serial verification failed: %v\n%s", err, tail(console.Snapshot(), 16000))
				}
				_ = process.Process.Kill()
				<-done
				t.Logf("RouterOS %s became reachable through the configured static address", release.Version)
				return
			}
		}
		if expectUEFIBlock {
			if strings.Contains(console.Snapshot(), "UEFI Interactive Shell") {
				_ = process.Process.Kill()
				<-done
				t.Logf("RouterOS %s raw image was correctly classified as not native-UEFI bootable", release.Version)
				return
			}
		}
		select {
		case processErr := <-done:
			data, _ := os.ReadFile(serialPath)
			t.Fatalf("QEMU exited before CHR became reachable: %v\n%s", processErr, string(data))
		case <-time.After(2 * time.Second):
		}
	}
	_ = process.Process.Kill()
	<-done
	data, _ := os.ReadFile(serialPath)
	t.Fatalf("CHR did not become reachable before timeout\n%s", tail(string(data), 12000))
}

type synchronizedBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.Write(value)
}

func (buffer *synchronizedBuffer) Snapshot() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.String()
}

type serialConsole struct {
	connection net.Conn
	output     *synchronizedBuffer
}

func connectSerialConsole(path string, log io.Writer, timeout time.Duration) (*serialConsole, error) {
	deadline := time.Now().Add(timeout)
	var connection net.Conn
	var err error
	for time.Now().Before(deadline) {
		connection, err = net.DialTimeout("unix", path, 500*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return nil, fmt.Errorf("connect QEMU serial console: %w", err)
	}
	console := &serialConsole{connection: connection, output: &synchronizedBuffer{}}
	go func() { _, _ = io.Copy(io.MultiWriter(log, console.output), connection) }()
	return console, nil
}

func (console *serialConsole) Close() error {
	return console.connection.Close()
}

func (console *serialConsole) Snapshot() string {
	return console.output.Snapshot()
}

func (console *serialConsole) send(value string) error {
	_ = console.connection.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := io.WriteString(console.connection, value)
	return err
}

func (console *serialConsole) waitForAny(after int, timeout time.Duration, markers ...string) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		value := console.Snapshot()
		if after > len(value) {
			after = len(value)
		}
		for _, marker := range markers {
			if strings.Contains(value[after:], marker) {
				return marker, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("serial console did not emit one of %q", markers)
}

func verifyRouterOSConsole(console *serialConsole, plan model.NetworkPlan) error {
	if _, err := console.waitForAny(0, 90*time.Second, "MikroTik Login: "); err != nil {
		return err
	}
	if err := console.send("admin\r"); err != nil {
		return err
	}
	if _, err := console.waitForAny(0, 10*time.Second, "Password: "); err != nil {
		return err
	}
	// RouterOS renders the prompt before its login reader is consistently ready
	// on slower TCG runners.
	time.Sleep(time.Second)
	if err := console.send("\r"); err != nil {
		return err
	}
	marker, err := completeTerminalHandshake(console, 30*time.Second)
	if err != nil {
		return err
	}
	if marker == "Do you want to see the software license? [Y/n]: " {
		if err := console.send("n\r"); err != nil {
			return err
		}
		marker, err = console.waitForAny(0, 10*time.Second, "new password> ", "] > ")
		if err != nil {
			return err
		}
	}
	if marker == "new password> " {
		if err := console.send(string([]byte{3})); err != nil {
			return err
		}
		if _, err := console.waitForAny(0, 10*time.Second, "] > "); err != nil {
			return err
		}
	}
	if _, err := consoleQuery(console, `:delay 20s; :put ("CHRTEST-" . "READY:" . [:len [/ip/address/find where comment="chr-install"]])`, "CHRTEST-READY:", "1"); err != nil {
		return err
	}
	interfaceName, err := consoleQuery(console, `:local i [/interface/ethernet/find where mac-address="`+strings.ToUpper(plan.MAC)+`"]; :put ("CHRTEST-" . "IF:" . [/interface/ethernet/get $i name])`, "CHRTEST-IF:", "")
	if err != nil {
		return fmt.Errorf("MAC-selected interface query failed: %w", err)
	}
	if interfaceName == "" {
		return fmt.Errorf("MAC-selected interface query returned an empty name")
	}
	checks := []struct {
		command  string
		marker   string
		expected string
	}{
		{`:local i [/interface/ethernet/find where mac-address="` + strings.ToUpper(plan.MAC) + `"]; :put ("CHRTEST-" . "MTU:" . [/interface/ethernet/get $i mtu])`, "CHRTEST-MTU:", strconv.Itoa(plan.MTU)},
		{`:put ("CHRTEST-" . "IP4:" . [/ip/address/get [find where comment="chr-install"] address])`, "CHRTEST-IP4:", plan.IPv4.Addresses[0]},
		{`:put ("CHRTEST-" . "IP4IF:" . [/ip/address/get [find where comment="chr-install"] interface])`, "CHRTEST-IP4IF:", interfaceName},
		{`:put ("CHRTEST-" . "GW4:" . [/ip/route/get [find where comment="chr-install" and dst-address="0.0.0.0/0"] gateway])`, "CHRTEST-GW4:", plan.IPv4.Gateway},
		{`:put ("CHRTEST-" . "DNS:" . [/ip/dns/get servers])`, "CHRTEST-DNS:", strings.Join(plan.DNS, ",")},
		{`:local i [/interface/ethernet/find where mac-address="` + strings.ToUpper(plan.MAC) + `"]; :put ("CHRTEST-" . "DHCP4:" . [/ip/dhcp-client/print count-only where interface=$i])`, "CHRTEST-DHCP4:", "0"},
		{`:put ("CHRTEST-" . "PING:" . [/ping address=` + plan.IPv4.Gateway + ` count=1])`, "CHRTEST-PING:", "1"},
	}
	for _, check := range checks {
		if _, err := consoleQuery(console, check.command, check.marker, check.expected); err != nil {
			return err
		}
	}
	return nil
}

func completeTerminalHandshake(console *serialConsole, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	deviceReplies := 0
	cursorReplies := 0
	lastOutputLength := len(console.Snapshot())
	lastActivity := time.Now()
	for time.Now().Before(deadline) {
		output := console.Snapshot()
		if len(output) != lastOutputLength {
			lastOutputLength = len(output)
			lastActivity = time.Now()
		}
		for deviceReplies < strings.Count(output, "\x1bZ") {
			if err := console.send("\x1b[?1;2c"); err != nil {
				return "", err
			}
			deviceReplies++
		}
		for cursorReplies < strings.Count(output, "\x1b[6n") {
			if err := console.send("\x1b[24;80R"); err != nil {
				return "", err
			}
			cursorReplies++
		}
		for _, marker := range []string{"Do you want to see the software license? [Y/n]: ", "] > "} {
			if strings.Contains(output, marker) {
				return marker, nil
			}
		}
		// A blank password can be lost while a heavily loaded TCG guest is
		// switching the serial console into terminal-negotiation mode. Retry
		// only when the guest has emitted nothing for a few seconds.
		if time.Since(lastActivity) >= 3*time.Second {
			if err := console.send("\r"); err != nil {
				return "", err
			}
			lastActivity = time.Now()
		}
		time.Sleep(50 * time.Millisecond)
	}
	return "", fmt.Errorf("RouterOS terminal negotiation did not complete")
}

func consoleQuery(console *serialConsole, command, marker, expected string) (string, error) {
	after := len(console.Snapshot())
	if err := console.send(command + "\r"); err != nil {
		return "", err
	}
	if _, err := console.waitForAny(after, 30*time.Second, marker); err != nil {
		return "", err
	}
	value := console.Snapshot()[after:]
	index := strings.LastIndex(value, marker)
	if index < 0 {
		return "", fmt.Errorf("missing console marker %s", marker)
	}
	value = value[index+len(marker):]
	if end := strings.IndexAny(value, "\r\n"); end >= 0 {
		value = value[:end]
	}
	value = strings.TrimSpace(value)
	if expected != "" && value != expected {
		return value, fmt.Errorf("%s = %q, expected %q", marker, value, expected)
	}
	return value, nil
}

func qemuDiskArguments(kind, imagePath string) ([]string, error) {
	if kind == "" {
		kind = "virtio"
	}
	switch kind {
	case "virtio":
		return []string{"-drive", "if=none,file=" + imagePath + ",format=raw,id=chr", "-device", "virtio-blk-pci,drive=chr"}, nil
	case "scsi":
		return []string{"-device", "virtio-scsi-pci,id=scsi0", "-drive", "if=none,file=" + imagePath + ",format=raw,id=chr", "-device", "scsi-hd,drive=chr,bus=scsi0.0"}, nil
	case "nvme":
		return []string{"-drive", "if=none,file=" + imagePath + ",format=raw,id=chr", "-device", "nvme,drive=chr,serial=chr-install-test"}, nil
	default:
		return nil, fmt.Errorf("unsupported QEMU disk model %q", kind)
	}
}

func qemuNICArguments(kind string) ([]string, error) {
	if kind == "" {
		kind = "virtio"
	}
	device := ""
	switch kind {
	case "virtio":
		device = "virtio-net-pci"
	case "e1000":
		device = "e1000"
	case "vmxnet3":
		device = "vmxnet3"
	default:
		return nil, fmt.Errorf("unsupported QEMU NIC model %q", kind)
	}
	return []string{"-device", device + ",netdev=net0,mac=52:54:00:12:34:56"}, nil
}

func findOVMF() (string, error) {
	for _, path := range []string{"/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_CODE.fd"} {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("OVMF firmware was not found")
}

func tail(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) <= maximum {
		return value
	}
	return value[len(value)-maximum:]
}
