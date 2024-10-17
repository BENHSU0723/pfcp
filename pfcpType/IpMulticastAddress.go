package pfcpType

import (
	"fmt"
	"net"
)

// ref to Figure 8.2.137-1: IP Multicast Address
type IpMulticastAddress struct {
	Flag      uint8
	Ipv4Start net.IP
	Ipv6Start net.IP
	Ipv4End   net.IP
	Ipv6End   net.IP
}

// used for flag IE
const (
	IpMulticastAddressOnlyV6Start      = 0x01
	IpMulticastAddressOnlyV4Start      = 0x02
	IpMulticastAddressV6StartV6End     = 0x05
	IpMulticastAddressV4StartV4End     = 0x06
	IpMulticastAddressAnyMulticastAddr = 0x08
)

func (i *IpMulticastAddress) MarshalBinary() (data []byte, err error) {
	// Octet 5
	data = append([]byte(""), i.Flag)

	// Octet m to (m+3)
	if i.Flag == IpMulticastAddressOnlyV4Start || i.Flag == IpMulticastAddressV4StartV4End {
		if i.Ipv4Start.IsUnspecified() {
			return []byte(""), fmt.Errorf("IPv4 address shall be present if V4 is set")
		}
		data = append(data, i.Ipv4Start.To4()...)
	}

	// Octet p to (p+15)
	if i.Flag == IpMulticastAddressOnlyV6Start || i.Flag == IpMulticastAddressV6StartV6End {
		if i.Ipv6Start.IsUnspecified() {
			return []byte(""), fmt.Errorf("IPv6 address shall be present if V6 is set")
		}
		data = append(data, i.Ipv6Start.To16()...)
	}

	// Octet q to (q+3)
	if i.Flag == IpMulticastAddressV4StartV4End {
		if i.Ipv4End.IsUnspecified() {
			return []byte(""), fmt.Errorf("IPv4 address shall be present if V4 is set")
		}
		data = append(data, i.Ipv4End.To4()...)
	}

	// Octet r to (r+15)
	if i.Flag == IpMulticastAddressV6StartV6End {
		if i.Ipv6End.IsUnspecified() {
			return []byte(""), fmt.Errorf("IPv6 address shall be present if V6 is set")
		}
		data = append(data, i.Ipv6End.To16()...)
	}

	return data, nil
}

func (i *IpMulticastAddress) UnmarshalBinary(data []byte) error {
	length := uint16(len(data))

	var idx uint16 = 0
	// Octet 5
	if length < idx+1 {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}
	i.Flag = data[idx]
	idx += 1

	// Octet m to (m+3)
	if i.Flag == IpMulticastAddressOnlyV4Start || i.Flag == IpMulticastAddressV4StartV4End {
		if length < idx+net.IPv4len {
			return fmt.Errorf("Inadequate TLV length: %d", length)
		}
		i.Ipv4Start = net.IP(data[idx : idx+net.IPv4len])
		idx = idx + net.IPv4len
	}

	// Octet p to (p+15)
	if i.Flag == IpMulticastAddressOnlyV6Start || i.Flag == IpMulticastAddressV6StartV6End {
		if length < idx+net.IPv6len {
			return fmt.Errorf("Inadequate TLV length: %d", length)
		}
		i.Ipv6Start = net.IP(data[idx : idx+net.IPv6len])
		idx = idx + net.IPv6len
	}

	// Octet q to (q+3)
	if i.Flag == IpMulticastAddressV4StartV4End {
		if length < idx+net.IPv4len {
			return fmt.Errorf("Inadequate TLV length: %d", length)
		}
		i.Ipv4End = net.IP(data[idx : idx+net.IPv4len])
		idx = idx + net.IPv4len
	}

	// Octet r to (r+15)
	if i.Flag == IpMulticastAddressV6StartV6End {
		if length < idx+net.IPv6len {
			return fmt.Errorf("Inadequate TLV length: %d", length)
		}
		i.Ipv6End = net.IP(data[idx : idx+net.IPv6len])
		idx = idx + net.IPv6len
	}

	if length != idx {
		return fmt.Errorf("Inadequate TLV length: %d", length)
	}

	return nil
}
