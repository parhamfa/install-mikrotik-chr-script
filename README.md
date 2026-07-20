# chr-install

`chr-install` is an interactive, fail-closed installer that replaces a supported Debian or Ubuntu server with MikroTik CHR while preserving a reviewed Layer-3 network configuration.

It is intentionally not a RouterOS hardening tool. It does not create passwords or users, change firewall policy, restrict services, configure licensing, or make unrelated RouterOS changes.

> [!CAUTION]
> This installer erases the complete disk that currently contains Linux. A provider console or rescue environment is strongly recommended. No program can recover a server from incorrect provider-side routing, unsupported virtual hardware, or unavailable recovery controls.

## Supported systems

- AMD64 only
- Debian 12 and 13
- Ubuntu 22.04, 24.04, and 26.04 LTS
- Firmware modes validated for the exact RouterOS release (7.21.5: legacy BIOS)
- One unambiguous local boot disk
- One Ethernet uplink with a single routing policy
- IPv4 DHCP or static addressing
- IPv6 SLAAC, DHCPv6, static addressing, or combinations of those modes
- Same-subnet and provider-routed/off-link gateways
- Rescue-system direct writing, or a RAM-backed pre-root writer from normal Linux

The preflight rejects RAID, multipath, ambiguous rescue disks, multiple uplinks/default routes, policy routing, VLANs, bonds, bridges, PPP, and other layouts that v1 cannot translate credibly.

V1 also blocks a Linux host that is currently booted with UEFI unless that exact long-term CHR image has passed native UEFI boot testing. RouterOS v7 supports UEFI on x86 in general, but the official CHR 7.21.5 raw image has only legacy MBR partitions and fell through to the OVMF shell in testing. Treating those as equivalent would be unsafe.

## Run preflight first

Download the release manually or use the bootstrap:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/parhamfa/install-mikrotik-chr-script/main/installer.sh)" -- --preflight
```

Preflight does not modify the server. It reports the resolved target disk, installation path, current addresses and routes, DNS, MTU, DHCP availability, current RouterOS long-term release, and any blockers.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/parhamfa/install-mikrotik-chr-script/main/installer.sh)"
```

The wizard will:

1. Inspect the host, root-disk ancestry, boot method, active routes, addresses, resolver state, network configuration files, leases, and DHCP availability.
2. Let you review and edit the proposed IPv4, IPv6, DNS, gateway, MAC, and MTU plan.
3. Download the latest RouterOS 7 long-term CHR image and its official SHA-256 checksum from MikroTik.
4. Parse the image partition table and inject only an idempotent `/rw/autorun.scr` network plan.
5. Require explicit recovery, unverified-network, untested-release, disk-erasure, and reboot acknowledgements when applicable.
6. Write from rescue Linux or a RAM-backed pre-root environment, then verify every written image byte before booting CHR.

There is no unattended mode and no reboot countdown.

## Safety model

- The target disk is derived from the filesystem backing `/`, then its ancestry and fingerprint are rechecked after review.
- The writer records the disk serial/WWN, size, kernel name, and major/minor identity, then checks them again immediately before writing.
- A normal running root disk is never overwritten from normal userspace; `mkinitramfs` rebuilds a RAM writer with the current kernel's full driver set.
- The CHR filesystem offset is read from its MBR; it is not hard-coded.
- DHCP probing sends only a DHCPDISCOVER packet and never installs an address or route on Linux.
- The first-boot script identifies the RouterOS uplink using the existing virtual NIC MAC.
- An unknown RouterOS version must pass structural checks and requires a typed acknowledgement. An incompatible layout is blocked.
- A failed read-back checksum halts the writer instead of rebooting.

## Building

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/chr-install-linux-amd64 ./cmd/chr-install
```

The full CHR/QEMU test is intentionally opt-in because it downloads MikroTik's official image and starts a virtual machine:

```bash
sudo env CHR_QEMU_INTEGRATION=1 go test -tags=integration -run TestQEMUBoot ./internal/integration -v
```

The release workflow also runs privileged network-namespace scenarios and boots the pre-root writer against a disposable serialized disk. Its CHR matrix logs in through the untouched serial console and verifies the MAC-selected interface, address binding, routes, DNS, MTU, DHCP cleanup, and gateway reachability. Those tests are required before assets are published; a post-release smoke job then exercises the legacy raw `installer.sh` URL and its checksum bootstrap.

## Project history

This is an in-place rewrite of `parhamfa/install-mikrotik-chr-script`. The repository history and contributor attribution remain intact. The last DHCP-only shell implementation will be retained under the `legacy-shell-final` tag when v1 reaches its release gate.

The repository will be renamed to `parhamfa/chr-install` only after the `v1.0.0` assets and old bootstrap URL pass the release smoke tests. The old repository name must never be reused because doing so would break GitHub's redirects.

## License

The v1 implementation is available under the [MIT License](LICENSE).
