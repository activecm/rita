package util

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type Subnet struct {
	*net.IPNet
}

// UnmarshalJSON unmarshals the JSON bytes into the IPNet struct
// overrides the default unmarshalling method to allow for custom parsing
func (s *Subnet) UnmarshalJSON(bytes []byte) error {
	var ipString string

	// unmarshal json into the ip string
	if err := json.Unmarshal(bytes, &ipString); err != nil {
		return err
	}

	subnet, err := ParseSubnet(ipString)
	if err != nil {
		return err
	}
	// set struct to unmarshalled value
	*s = subnet

	return nil
}

// ParseSubnet parses a CIDR string into a Subnet struct, which is formatted as IPv6
// It supports both IPv4 and IPv6 CIDRs, as well as IPv4 in IPv6 CIDRs
func ParseSubnet(str string) (Subnet, error) {
	var subnet Subnet
	isIPv4CIDRInIPv6 := false
	ipString := str
	originalLength := len(ipString)
	// trim off the IPv4 in IPv6 prefix since net.ParseCIDR can't parse them properly
	// IPv4 in IPv6 CIDRs will be parsed as a special case here
	// IPv4 in IPv6 (IP) addresses will fallthrough to the block further down
	ipString = strings.TrimPrefix(ipString, "::ffff:")
	if len(ipString) < originalLength {
		ipParts := strings.Split(ipString, "/")

		// parse as cidr if the ip string contained a slash
		if len(ipParts) == 2 {
			ip := net.ParseIP(ipParts[0])
			if ip == nil {
				return subnet, fmt.Errorf("unable to parse CIDR as subnet, invalid IP address: %s", ipParts[0])
			}
			// parse cidr mask as a number
			cidrMask, err := strconv.Atoi(ipParts[1])
			if err != nil {
				return subnet, fmt.Errorf("unable to parse CIDR as subnet, invalid mask: %s", ipParts[1])
			}
			// verify that mask is within the valid range for a IPv6 cidr mask
			if cidrMask < 96 || cidrMask > 128 {
				return subnet, fmt.Errorf("unable to parse CIDR as subnet, invalid numerical value for cidr mask: %d", cidrMask)
			}
			// mask the IP with the CIDR mask, or else it will appear like a /32 CIDR even if the mask is lower
			mask := net.CIDRMask(cidrMask, 128)
			ipNet := net.IPNet{IP: ip.To16().Mask(mask), Mask: mask}
			subnet = Subnet{&ipNet}
			isIPv4CIDRInIPv6 = true
		}

	}

	// otherwise, parse as a normal ip/cidr (including IPv4 in IPv6 IP addresses)
	if !isIPv4CIDRInIPv6 {

		// if string contains a slash, try to parse as a CIDR
		if strings.Contains(ipString, "/") {
			_, netAddr, err := net.ParseCIDR(ipString)
			if err != nil {
				return subnet, err
			}
			// convert IPv4 to IPv6
			if netAddr.IP.To4() != nil {
				netAddr.IP = netAddr.IP.To16()
				ones, _ := netAddr.Mask.Size()
				netAddr.Mask = net.CIDRMask(ones+96, 128)
			}

			// set the IPNet struct as a CIDR
			subnet = Subnet{netAddr}
		} else {

			// try to parse the ip string as an IP
			ip := net.ParseIP(ipString)

			// if still an error, return the error
			if ip == nil {
				return subnet, fmt.Errorf("unable to parse CIDR as subnet, invalid IP address: %s", ipString)
			}

			// set the IPNet struct as a single IP
			ipNet := net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
			subnet = Subnet{&ipNet}

		}
	}
	return subnet, nil
}

// NewSubnet creates a new Subnet struct from an IPNet pointer
func NewSubnet(ipNet *net.IPNet) Subnet {
	return Subnet{ipNet}
}

// NewSubnetList creates a list of Subnet structs from a list of strings
func NewSubnetList(subnets []string) ([]Subnet, error) {
	var subnetList []Subnet
	for _, subnet := range subnets {
		subnet, err := ParseSubnet(subnet)
		if err != nil {
			return nil, err
		}
		subnetList = append(subnetList, subnet)
	}
	return subnetList, nil
}

// NewTestSubnetList creates a list of Subnet structs from a list of strings, but asserts no error using testing library
func NewTestSubnetList(t *testing.T, subnets []string) []Subnet {
	subnetList, err := NewSubnetList(subnets)
	require.NoError(t, err)
	return subnetList
}

// MarshalJSON marshals the Subnet struct into JSON bytes
func (s *Subnet) MarshalJSON() ([]byte, error) {

	// convert the Subnet struct to a string
	ip, err := s.ToIPString()
	if err != nil {
		return nil, err
	}

	// add cidr notation if the mask is less than 128
	ones, _ := s.Mask.Size()
	if ones < 128 {
		ip += fmt.Sprintf("/%d", ones)
	}
	fmt.Println("ip", ip)
	return json.Marshal(ip)

}

// ToIPString converts the Subnet struct to a string representation of the IP, assuming /32 mask
func (s *Subnet) ToIPString() (string, error) {
	if s.IP == nil {
		return "", fmt.Errorf("ip is nil")
	}

	// convert the IP to a string
	ip := s.IP.String()

	// if the IP is an ipv4 address, convert it to ipv6
	if s.IP.To4() != nil {
		ip = "::ffff:" + ip
		// using ipv4 will break the {cidr} part of the isIPAddressInRange func
		// fmt.Printf("\t... this was an ipv4 address, so %s was converted to %s\n", s.IP.String(), ip)
	}
	return ip, nil
}

// ToString converts the Subnet struct to a proper string representation of the CIDR
func (s *Subnet) ToString() string {
	if s.IP == nil {
		return ""
	}

	// convert the IP to a string
	ip := s.IP.String()

	mask, _ := s.Mask.Size()

	// if the IP is an ipv4 address, convert it to ipv6
	if s.IP.To4() != nil {
		ip = s.IP.To4().Mask(net.CIDRMask(mask-96, 32)).String()
		ip = "::ffff:" + ip
	}

	return fmt.Sprintf("%s/%d", ip, mask)
}

// CompactSubnets removes duplicate Subnets from a given slice
func CompactSubnets(subnets []Subnet) []Subnet {
	var freshSubnets []Subnet
	dataMap := make(map[string]bool)
	for _, item := range subnets {
		if !dataMap[item.ToString()] {
			freshSubnets = append(freshSubnets, item)
			dataMap[item.ToString()] = true
		}
	}
	return freshSubnets
}

// IncludeMandatorySubnets ensures that a given slice of Subnets contains all elements of a mandatory list
func IncludeMandatorySubnets(data []Subnet, mandatory []Subnet) []Subnet {
	// create map to store elements of the given list
	dataMap := make(map[string]bool)
	for _, item := range data {
		dataMap[item.ToString()] = true
	}

	// check if all elements in the mandatory list exist in the given list
	for _, item := range mandatory {
		if !dataMap[item.ToString()] {
			data = append(data, item) // append missing element
		}
	}

	return data

}

// Scan implements the sql.Scanner interface for the Subnet struct;
// allows for scanning a Subnet struct from a database query
func (s *Subnet) Scan(src any) error {
	if t, ok := src.(string); ok {
		ipNet, err := ParseSubnet(t)
		if err != nil {
			return err
		}
		*s = ipNet
		return nil
	}
	return fmt.Errorf("cannot scan %T into Subnet", src)
}
