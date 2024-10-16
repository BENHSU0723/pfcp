package pfcpType

import (
	"encoding/binary"
	"fmt"
)

// ref to Figure 8.2.137-1: IP Multicast Address
type IpMulticastAddress struct {
	Flag      uint8
	Ipv4Start uint32
	Ipv6Start [4]uint32
	Ipv4End   uint32
	Ipv6End   [4]uint32
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
	switch i.Flag {
	case IpMulticastAddressOnlyV4Start:
		data = make([]byte, 5)
		data[0] = i.Flag
		binary.BigEndian.PutUint32(data[1:], i.Ipv4Start)
		return data, nil
	default:
		return nil, fmt.Errorf("not support this kind of encoding type[%b]", i.Flag)
	}
}

func (i *IpMulticastAddress) UnmarshalBinary(data []byte) error {
	length := uint16(len(data))

	if length != 5 {
		return fmt.Errorf("not support others than IPv4 decodeing, received tpye[%b]", data[0])
	}

	i.Flag = data[0]
	i.Ipv4Start = binary.BigEndian.Uint32(data[1:])

	return nil
}
