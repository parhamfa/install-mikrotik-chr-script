//go:build linux

package network

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildAndParseDHCPPacket(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	transaction := [4]byte{1, 2, 3, 4}
	packet := buildDHCPDiscover(mac, transaction)
	if len(packet) < 300 || packet[42] != 1 || string(packet[46:50]) != string(transaction[:]) {
		t.Fatalf("invalid DHCPDISCOVER packet")
	}
	binary.BigEndian.PutUint16(packet[34:36], dhcpServerPort)
	binary.BigEndian.PutUint16(packet[36:38], dhcpClientPort)
	dhcp := packet[42:]
	dhcp[0] = 2
	copy(dhcp[16:20], net.ParseIP("192.0.2.25").To4())
	for offset := 240; offset+2 < len(dhcp); {
		code := dhcp[offset]
		if code == 53 {
			dhcp[offset+2] = 2
			break
		}
		if code == 0 {
			offset++
			continue
		}
		if code == 255 {
			break
		}
		offset += 2 + int(dhcp[offset+1])
	}
	offer, ok := parseDHCPOffer(packet, transaction)
	if !ok || !offer.Offered || offer.Address != "192.0.2.25" {
		t.Fatalf("unexpected parsed offer: %#v, ok=%v", offer, ok)
	}
}
