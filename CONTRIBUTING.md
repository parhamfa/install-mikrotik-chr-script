# Contributing

Changes are welcome, but the installer has a deliberately narrow contract: safely replace a supported Linux installation with CHR and preserve reviewed Layer-3 connectivity. RouterOS passwords, users, firewall policy, service restrictions, licensing, and general configuration management belong in separate tools.

Use the bug or feature issue form before proposing a substantial behavior change. Security vulnerabilities belong in a private report as described in [SECURITY.md](SECURITY.md), not a public issue. Redact public IP addresses, MAC addresses, disk serials, WWNs, provider identifiers, and credentials from logs unless they are intentionally public test fixtures.

Before opening a pull request:

```bash
gofmt -w cmd internal
go test ./...
go vet ./...
bash -n installer.sh
shellcheck installer.sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/chr-install
```

Network changes should include fixtures for the relevant `ip -j` output and the expected RouterOS script. Disk changes should include ancestry and ambiguity tests. Any change to image injection, RouterOS script generation, initramfs staging, or the writer needs the full QEMU workflow before release; it covers namespaces, real GRUB and kexec transitions into the writer, serial-console state verification across three CHR disk/NIC combinations, and the UEFI safety probe.

Do not weaken a blocker merely to support a particular hosting brand. Add capability detection and a reproducible fixture instead.
