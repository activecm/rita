package util

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type IPNet struct {
	*net.IPNet
}

// UnmarshalJSON unmarshals the JSON bytes into the IPNet struct
// overrides the default unmarshalling method to allow for custom parsing
func (s *IPNet) UnmarshalJSON(bytes []byte) error {
	var ipString string
	var safelistIP IPNet

	// unmarshal json into the ip string
	if err := json.Unmarshal(bytes, &ipString); err != nil {
		return err
	}

	isIPv4CIDRInIPv6 := false

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
				return fmt.Errorf("invalid ip")
			}
			// parse cidr mask as a number
			cidrMask, err := strconv.Atoi(ipParts[1])
			if err != nil {
				return fmt.Errorf("invalid mask")
			}
			// verify that mask is within the valid range for a IPv6 cidr mask
			if cidrMask < 96 || cidrMask > 128 {
				return fmt.Errorf("invalid numerical value for cidr mask")
			}
			ipNet := net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(cidrMask, 128)}
			safelistIP = IPNet{&ipNet}
			isIPv4CIDRInIPv6 = true
		}

	}

	// otherwise, parse as a normal ip/cidr (including IPv4 in IPv6 IP addresses)
	if !isIPv4CIDRInIPv6 {

		// if string contains a slash, try to parse as a CIDR
		if strings.Contains(ipString, "/") {
			_, netAddr, err := net.ParseCIDR(ipString)
			if err != nil {
				return err
			}
			// convert IPv4 to IPv6
			if netAddr.IP.To4() != nil {
				netAddr.IP = netAddr.IP.To16()
				ones, _ := netAddr.Mask.Size()
				netAddr.Mask = net.CIDRMask(ones+96, 128)
			}

			// set the IPNet struct as a CIDR
			safelistIP = IPNet{netAddr}
		} else {

			// try to parse the ip string as an IP
			ip := net.ParseIP(ipString)

			// if still an error, return the error
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", ipString)
			}

			// set the IPNet struct as a single IP
			ipNet := net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)}
			safelistIP = IPNet{&ipNet}

		}
	}
	// set struct to unmarshalled value
	*s = safelistIP

	return nil
}

// MarshalJSON marshals the IPNet struct into JSON bytes
func (s *IPNet) MarshalJSON() ([]byte, error) {

	// convert the IPNet struct to a string
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

func (s *IPNet) ToIPString() (string, error) {
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
