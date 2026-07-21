## Summary

Describe the capability or defect and why the change belongs in `chr-install`.

## Safety impact

- Detection evidence added or changed:
- New fail-closed conditions:
- Disk-writing, image-layout, RouterOS script, or reboot-path impact:

## Validation

- [ ] `gofmt -w cmd internal`
- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `bash -n installer.sh`
- [ ] Static Linux AMD64 build
- [ ] Full QEMU workflow, if this affects networking, image injection, disk writing, initramfs, or boot
- [ ] New fixtures/tests cover both acceptance and refusal paths

## Scope

- [ ] This change does not add passwords, users, firewall policy, service restrictions, licensing, or unrelated RouterOS configuration.
- [ ] Logs, fixtures, and screenshots contain no unintended credentials or infrastructure identifiers.
