// diskprobe is a test-only initramfs helper used by the SCSI writer workflow.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/parhamfa/chr-install/internal/disk"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: diskprobe KERNEL_NAME")
		os.Exit(2)
	}
	fingerprint := disk.FingerprintFromSysfs("/", os.Args[1])
	encoded, err := json.Marshal(fingerprint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode fingerprint: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CHR-DISK-FINGERPRINT=%s\n", encoded)
	unix.Sync()
	if err := unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		fmt.Fprintf(os.Stderr, "power off probe VM: %v\n", err)
		os.Exit(1)
	}
}
