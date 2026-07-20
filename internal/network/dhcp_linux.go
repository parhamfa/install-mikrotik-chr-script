//go:build linux

package network

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/parhamfa/chr-install/internal/model"
	"golang.org/x/sys/unix"
)

const (
	etherTypeIPv4  = 0x0800
	dhcpClientPort = 68
	dhcpServerPort = 67
)

func ProbeDHCP(ctx context.Context, interfaceName string, mac net.HardwareAddr, timeout time.Duration) (model.DHCPProbe, error) {
	result := model.DHCPProbe{Attempted: true}
	if len(mac) != 6 {
		return result, fmt.Errorf("invalid Ethernet MAC")
	}
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return result, err
	}
	socket, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeIPv4)))
	if err != nil {
		return result, fmt.Errorf("open packet socket: %w", err)
	}
	defer unix.Close(socket)
	if err := unix.Bind(socket, &unix.SockaddrLinklayer{Protocol: htons(etherTypeIPv4), Ifindex: device.Index}); err != nil {
		return result, fmt.Errorf("bind packet socket: %w", err)
	}
	deadline := time.Now().Add(timeout)
	_ = unix.SetsockoptTimeval(socket, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 0, Usec: 250000})

	var transaction [4]byte
	if _, err := rand.Read(transaction[:]); err != nil {
		return result, err
	}
	packet := buildDHCPDiscover(mac, transaction)
	var destination [8]uint8
	for i := 0; i < 6; i++ {
		destination[i] = 0xff
	}
	if err := unix.Sendto(socket, packet, 0, &unix.SockaddrLinklayer{Protocol: htons(etherTypeIPv4), Ifindex: device.Index, Halen: 6, Addr: destination}); err != nil {
		return result, fmt.Errorf("send DHCPDISCOVER: %w", err)
	}

	buffer := make([]byte, 2048)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		count, _, err := unix.Recvfrom(socket, buffer, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return result, fmt.Errorf("receive DHCPOFFER: %w", err)
		}
		offer, ok := parseDHCPOffer(buffer[:count], transaction)
		if ok {
			return offer, nil
		}
	}
	result.Message = "no DHCPOFFER received"
	return result, nil
}

func buildDHCPDiscover(mac net.HardwareAddr, transaction [4]byte) []byte {
	dhcp := make([]byte, 240)
	dhcp[0], dhcp[1], dhcp[2] = 1, 1, 6
	copy(dhcp[4:8], transaction[:])
	binary.BigEndian.PutUint16(dhcp[10:12], 0x8000)
	copy(dhcp[28:34], mac)
	copy(dhcp[236:240], []byte{99, 130, 83, 99})
	dhcp = append(dhcp,
		53, 1, 1,
		61, 7, 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		55, 5, 1, 3, 6, 51, 54,
		255,
	)
	udpLength := 8 + len(dhcp)
	ipLength := 20 + udpLength
	packet := make([]byte, 14+ipLength)
	for i := 0; i < 6; i++ {
		packet[i] = 0xff
	}
	copy(packet[6:12], mac)
	binary.BigEndian.PutUint16(packet[12:14], etherTypeIPv4)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLength))
	ip[8], ip[9] = 64, 17
	copy(ip[16:20], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))
	udp := packet[34:42]
	binary.BigEndian.PutUint16(udp[0:2], dhcpClientPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpServerPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLength))
	copy(packet[42:], dhcp)
	return packet
}

func parseDHCPOffer(packet []byte, transaction [4]byte) (model.DHCPProbe, bool) {
	result := model.DHCPProbe{Attempted: true}
	if len(packet) < 14+20+8+240 || binary.BigEndian.Uint16(packet[12:14]) != etherTypeIPv4 {
		return result, false
	}
	ipHeaderLength := int(packet[14]&0x0f) * 4
	if ipHeaderLength < 20 || len(packet) < 14+ipHeaderLength+8+240 {
		return result, false
	}
	udp := packet[14+ipHeaderLength:]
	if binary.BigEndian.Uint16(udp[0:2]) != dhcpServerPort || binary.BigEndian.Uint16(udp[2:4]) != dhcpClientPort {
		return result, false
	}
	dhcp := udp[8:]
	if dhcp[0] != 2 || string(dhcp[4:8]) != string(transaction[:]) || string(dhcp[236:240]) != string([]byte{99, 130, 83, 99}) {
		return result, false
	}
	options := parseDHCPOptions(dhcp[240:])
	if message := options[53]; len(message) != 1 || message[0] != 2 {
		return result, false
	}
	result.Offered = true
	result.Address = net.IP(dhcp[16:20]).String()
	if server := options[54]; len(server) == 4 {
		result.Server = net.IP(server).String()
	} else {
		result.Server = net.IP(packet[26:30]).String()
	}
	result.Message = "DHCPOFFER received"
	return result, true
}

func parseDHCPOptions(data []byte) map[byte][]byte {
	result := make(map[byte][]byte)
	for offset := 0; offset < len(data); {
		code := data[offset]
		offset++
		if code == 0 {
			continue
		}
		if code == 255 || offset >= len(data) {
			break
		}
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			break
		}
		result[code] = append([]byte(nil), data[offset:offset+length]...)
		offset += length
	}
	return result
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func htons(value uint16) uint16 {
	return value<<8&0xff00 | value>>8
}
