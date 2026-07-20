//go:build !linux

package network

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
)

func ProbeDHCP(_ context.Context, _ string, _ net.HardwareAddr, _ time.Duration) (model.DHCPProbe, error) {
	return model.DHCPProbe{}, fmt.Errorf("DHCP probing is only available on Linux")
}
