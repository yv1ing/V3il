package observer

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"sandbox-proxy/internal/telemetry"
)

const (
	observerExcludedPortsEnvName = "V3IL_OBSERVER_EXCLUDED_PORTS"
	packetStatisticsInterval     = 5 * time.Second
	ethernetProtocolAll          = 0x0003
	ethernetProtocolIPv4         = 0x0800
	ethernetProtocolIPv6         = 0x86dd
	ethernetProtocolVLAN         = 0x8100
	ethernetProtocolQinQ         = 0x88a8
	socketLevelPacket            = 263
	packetStatisticsOption       = 6
)

type packetObservation struct {
	Protocol        string
	SourceIP        string
	SourcePort      int
	DestinationIP   string
	DestinationPort int
	TCPFlags        byte
	PacketBytes     int
	InterfaceIndex  int
}

type packetSocketStatistics struct {
	Packets uint32
	Drops   uint32
}

func (o *Observer) runPacketObserver(ctx context.Context) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(hostToNetworkShort(ethernetProtocolAll)))
	if err != nil {
		o.recordFailure("network", "raw packet observer unavailable", err)
		return
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024); err != nil {
		o.recordFailure("network_buffer", "raw packet observer receive buffer could not be enlarged", err)
	} else {
		o.health.Set("network_buffer", "active", "raw packet receive buffer is configured")
	}
	o.health.Set("network", "active", "capturing IPv4 and IPv6 flow boundaries")
	o.recordState("network", "observer_started", "Raw packet flow observer started.", nil)
	go func() {
		<-ctx.Done()
		_ = syscall.Close(fd)
	}()
	go o.monitorPacketSocket(ctx, fd)

	excludedPorts := observerExcludedPorts()
	localAddresses := localIPSet()
	lastAddressRefresh := time.Now()
	buffer := make([]byte, 65535)
	for {
		n, source, receiveErr := syscall.Recvfrom(fd, buffer, 0)
		if receiveErr != nil {
			if ctx.Err() != nil || errors.Is(receiveErr, syscall.EBADF) {
				o.health.Set("network", "stopped", "observer context canceled")
				return
			}
			if errors.Is(receiveErr, syscall.EINTR) {
				continue
			}
			o.recordFailure("network", "packet receive failed", receiveErr)
			continue
		}
		o.recordRecovery("network", "capturing IPv4 and IPv6 flow boundaries")
		if time.Since(lastAddressRefresh) >= 30*time.Second {
			localAddresses = localIPSet()
			lastAddressRefresh = time.Now()
		}
		observation, ok := parsePacketObservation(buffer[:n])
		if !ok || excludedPorts[observation.SourcePort] || excludedPorts[observation.DestinationPort] {
			continue
		}
		if link, ok := source.(*syscall.SockaddrLinklayer); ok {
			observation.InterfaceIndex = link.Ifindex
		}
		direction := packetDirection(observation, localAddresses)
		if direction == "unknown" {
			continue
		}
		action, shouldRecord := packetAction(observation)
		if !shouldRecord {
			continue
		}
		o.recorder.Record(telemetry.Event{
			Category:        "network",
			Action:          action,
			Source:          "sensor",
			Direction:       direction,
			Outcome:         "unknown",
			SourceIP:        observation.SourceIP,
			SourcePort:      observation.SourcePort,
			DestinationIP:   observation.DestinationIP,
			DestinationPort: observation.DestinationPort,
			Protocol:        observation.Protocol,
			Attributes: map[string]any{
				"observer":        "af_packet",
				"packet_bytes":    observation.PacketBytes,
				"tcp_flags":       fmt.Sprintf("0x%02x", observation.TCPFlags),
				"interface_index": observation.InterfaceIndex,
			},
		})
	}
}

func (o *Observer) monitorPacketSocket(ctx context.Context, fd int) {
	ticker := time.NewTicker(packetStatisticsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !o.health.IsActive("network_buffer") {
				if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024); err != nil {
					o.recordFailure("network_buffer", "raw packet observer receive buffer could not be enlarged", err)
				} else {
					o.recordRecovery("network_buffer", "raw packet receive buffer is configured")
				}
			}
			statistics, err := readPacketSocketStatistics(fd)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, syscall.EBADF) {
					return
				}
				o.recordFailure("network_accounting", "packet drop accounting failed", err)
				continue
			}
			if statistics.Drops > 0 {
				o.recordFailure(
					"network_accounting",
					"raw packet observer reported an evidence coverage gap",
					fmt.Errorf("%d of %d packets dropped", statistics.Drops, statistics.Packets),
				)
				continue
			}
			o.recordRecovery("network_accounting", "kernel packet drop accounting active")
		}
	}
}

func readPacketSocketStatistics(fd int) (packetSocketStatistics, error) {
	statistics := packetSocketStatistics{}
	length := uint32(unsafe.Sizeof(statistics))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(socketLevelPacket),
		uintptr(packetStatisticsOption),
		uintptr(unsafe.Pointer(&statistics)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return packetSocketStatistics{}, errno
	}
	if length < uint32(unsafe.Sizeof(statistics)) {
		return packetSocketStatistics{}, errors.New("truncated packet socket statistics")
	}
	return statistics, nil
}

func parsePacketObservation(packet []byte) (packetObservation, bool) {
	if len(packet) < 14 {
		return packetObservation{}, false
	}
	offset := 14
	protocol := binary.BigEndian.Uint16(packet[12:14])
	for tags := 0; tags < 2 && (protocol == ethernetProtocolVLAN || protocol == ethernetProtocolQinQ); tags++ {
		if len(packet) < offset+4 {
			return packetObservation{}, false
		}
		protocol = binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		offset += 4
	}
	switch protocol {
	case ethernetProtocolIPv4:
		return parseIPv4Observation(packet, offset)
	case ethernetProtocolIPv6:
		return parseIPv6Observation(packet, offset)
	default:
		return packetObservation{}, false
	}
}

func parseIPv4Observation(packet []byte, offset int) (packetObservation, bool) {
	if len(packet) < offset+20 || packet[offset]>>4 != 4 {
		return packetObservation{}, false
	}
	headerLength := int(packet[offset]&0x0f) * 4
	if headerLength < 20 || len(packet) < offset+headerLength {
		return packetObservation{}, false
	}
	fragment := binary.BigEndian.Uint16(packet[offset+6 : offset+8])
	if fragment&0x1fff != 0 {
		return packetObservation{}, false
	}
	return parseTransportObservation(
		packet[offset+headerLength:],
		packet[offset+9],
		net.IP(packet[offset+12:offset+16]).String(),
		net.IP(packet[offset+16:offset+20]).String(),
		len(packet),
	)
}

func parseIPv6Observation(packet []byte, offset int) (packetObservation, bool) {
	if len(packet) < offset+40 || packet[offset]>>4 != 6 {
		return packetObservation{}, false
	}
	payload, protocol, ok := ipv6TransportPayload(packet, offset)
	if !ok {
		return packetObservation{}, false
	}
	return parseTransportObservation(
		payload,
		protocol,
		net.IP(packet[offset+8:offset+24]).String(),
		net.IP(packet[offset+24:offset+40]).String(),
		len(packet),
	)
}

func ipv6TransportPayload(packet []byte, offset int) ([]byte, byte, bool) {
	nextHeader := packet[offset+6]
	cursor := offset + 40
	for extensionCount := 0; extensionCount < 8; extensionCount++ {
		switch nextHeader {
		case 0, 43, 60:
			if len(packet) < cursor+2 {
				return nil, 0, false
			}
			headerLength := (int(packet[cursor+1]) + 1) * 8
			if headerLength < 8 || len(packet) < cursor+headerLength {
				return nil, 0, false
			}
			nextHeader = packet[cursor]
			cursor += headerLength
		case 44:
			if len(packet) < cursor+8 {
				return nil, 0, false
			}
			fragment := binary.BigEndian.Uint16(packet[cursor+2 : cursor+4])
			if fragment&0xfff8 != 0 {
				return nil, 0, false
			}
			nextHeader = packet[cursor]
			cursor += 8
		case 51:
			if len(packet) < cursor+2 {
				return nil, 0, false
			}
			headerLength := (int(packet[cursor+1]) + 2) * 4
			if headerLength < 8 || len(packet) < cursor+headerLength {
				return nil, 0, false
			}
			nextHeader = packet[cursor]
			cursor += headerLength
		case 50:
			return nil, 0, false
		default:
			if len(packet) < cursor {
				return nil, 0, false
			}
			return packet[cursor:], nextHeader, true
		}
	}
	return nil, 0, false
}

func parseTransportObservation(payload []byte, protocol byte, sourceIP string, destinationIP string, packetBytes int) (packetObservation, bool) {
	observation := packetObservation{
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		PacketBytes:   packetBytes,
	}
	switch protocol {
	case syscall.IPPROTO_TCP:
		if len(payload) < 14 {
			return packetObservation{}, false
		}
		observation.Protocol = "tcp"
		observation.SourcePort = int(binary.BigEndian.Uint16(payload[0:2]))
		observation.DestinationPort = int(binary.BigEndian.Uint16(payload[2:4]))
		observation.TCPFlags = payload[13]
	case syscall.IPPROTO_UDP:
		if len(payload) < 8 {
			return packetObservation{}, false
		}
		observation.Protocol = "udp"
		observation.SourcePort = int(binary.BigEndian.Uint16(payload[0:2]))
		observation.DestinationPort = int(binary.BigEndian.Uint16(payload[2:4]))
	case syscall.IPPROTO_ICMP:
		observation.Protocol = "icmp"
	case syscall.IPPROTO_ICMPV6:
		observation.Protocol = "icmpv6"
	default:
		return packetObservation{}, false
	}
	return observation, true
}

func packetAction(observation packetObservation) (string, bool) {
	if observation.Protocol != "tcp" {
		return "datagram_observed", true
	}
	if observation.TCPFlags&0x02 != 0 && observation.TCPFlags&0x10 == 0 {
		return "connection_attempted", true
	}
	if observation.TCPFlags&0x04 != 0 {
		return "connection_reset", true
	}
	if observation.TCPFlags&0x01 != 0 {
		return "connection_closed", true
	}
	return "", false
}

func packetDirection(observation packetObservation, localAddresses map[string]struct{}) string {
	_, sourceLocal := localAddresses[observation.SourceIP]
	_, destinationLocal := localAddresses[observation.DestinationIP]
	switch {
	case sourceLocal && destinationLocal:
		return "internal"
	case destinationLocal:
		return "inbound"
	case sourceLocal:
		return "outbound"
	default:
		return "unknown"
	}
}

func localIPSet() map[string]struct{} {
	result := map[string]struct{}{
		"127.0.0.1": {},
		"::1":       {},
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return result
	}
	for _, address := range addresses {
		value := address.String()
		if slash := strings.IndexByte(value, '/'); slash >= 0 {
			value = value[:slash]
		}
		if parsed := net.ParseIP(value); parsed != nil {
			result[parsed.String()] = struct{}{}
		}
	}
	return result
}

func observerExcludedPorts() map[int]bool {
	result := make(map[int]bool)
	for _, raw := range strings.Split(os.Getenv(observerExcludedPortsEnvName), ",") {
		port, err := strconv.Atoi(strings.TrimSpace(raw))
		if err == nil && port > 0 && port <= 65535 {
			result[port] = true
		}
	}
	return result
}

func hostToNetworkShort(value uint16) uint16 {
	return value<<8 | value>>8
}
