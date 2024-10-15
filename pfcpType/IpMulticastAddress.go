package pfcpType

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
