package util

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type SubnetSuite struct {
	suite.Suite
}

func TestSubnets(t *testing.T) {
	suite.Run(t, new(SubnetSuite))
}

func (s *SubnetSuite) TestNewSubnetList() {
	t := s.T()

	tests := []struct {
		name          string
		input         []string
		expected      []Subnet
		expectedError error
	}{
		{
			name: "Valid IPv4 CIDRs",
			input: []string{
				"10.0.0.0/8", "10.1.1.1/8", "172.193.1.1/12", "10.99.45.67/16", "10.1.0.0", "192.168.45.99/24", "10.1.1.0/24", "192.168.45.199/25", "192.168.1.1/32",
			},

			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{172, 192, 0, 0}.To16(), Mask: net.CIDRMask(108, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{10, 99, 0, 0}.To16(), Mask: net.CIDRMask(112, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{10, 1, 0, 0}.To16(), Mask: net.CIDRMask(128, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 45, 0}.To16(), Mask: net.CIDRMask(120, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{10, 1, 1, 0}.To16(), Mask: net.CIDRMask(120, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 45, 128}.To16(), Mask: net.CIDRMask(25+96, 128)}),
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 1}.To16(), Mask: net.CIDRMask(128, 128)}),
			},
		},
		{
			name: "Valid IPv6 CIDRs",
			input: []string{
				"2000::/8", "2001:db8::/16", "3001:abcd:1234::/32", "4002:db8:5678::/48", "5003:abcd:5678:abcd::/64", "6004:1234:5678:abcd::/80",
				"7005:abcd:6789:abcd:1234::/96", "8006:1234:5678:abcd:5678::/112", "9007:abcd:1234:5678:abcd::/127",
			},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.ParseIP("2000::"), Mask: net.CIDRMask(8, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("2001::"), Mask: net.CIDRMask(16, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("3001:abcd::"), Mask: net.CIDRMask(32, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("4002:db8:5678::"), Mask: net.CIDRMask(48, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("5003:abcd:5678:abcd::"), Mask: net.CIDRMask(64, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("6004:1234:5678:abcd::"), Mask: net.CIDRMask(80, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("7005:abcd:6789:abcd:1234::"), Mask: net.CIDRMask(96, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("8006:1234:5678:abcd:5678::"), Mask: net.CIDRMask(112, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("9007:abcd:1234:5678:abcd::"), Mask: net.CIDRMask(127, 128)}),
			},
		},
		{
			name:  "Mixed IPv4 and IPv6 CIDRs",
			input: []string{"192.168.1.1/24", "2001:db8::/64"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 0}.To16(), Mask: net.CIDRMask(120, 128)}),
				NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
			},
		},
		{
			name:  "Single IPv4 Address",
			input: []string{"10.10.10.1"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{10, 10, 10, 1}.To16(), Mask: net.CIDRMask(128, 128)}),
			},
		},
		{
			name:  "Single IPv6 Address",
			input: []string{"2001:db8::1"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(128, 128)}),
			},
		},
		{
			name:  "IPv4 in IPv6 Notation",
			input: []string{"::ffff:10.99.99.99/104"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}),
			},
		},
		{
			name:          "Invalid CIDR",
			input:         []string{"192.168.1.0/33", "2001:db8::/64"},
			expectedError: fmt.Errorf("invalid CIDR address: 192.168.1.0/33"),
		},
		{
			name:          "Invalid IP",
			input:         []string{"invalidIP"},
			expectedError: fmt.Errorf("unable to parse CIDR as subnet, invalid IP address"),
		},
		{
			name:     "Empty List",
			input:    []string{},
			expected: []Subnet{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NewSubnetList(test.input)

			if test.expectedError != nil {
				require.Error(t, err, "expected an error but got none")
				require.ErrorContains(t, err, test.expectedError.Error(), "error message must contain expected error")
			} else {
				require.NoError(t, err, "should not have produced an error")
			}
			require.Equal(t, test.expected, result, "parsed subnets should match expected value")
		})
	}
}

func (s *SubnetSuite) TestSubnet_UnmarshalJSON() {
	t := s.T()
	tests := []struct {
		name          string
		input         string
		expected      Subnet
		expectedError error
	}{
		{
			name:     "IPv4 Subnet with /24 CIDR",
			input:    `"::ffff:192.168.1.0/120"`,
			expected: NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(120, 128)}),
		},
		{
			name:     "IPv6 Subnet with /64 CIDR",
			input:    `"2001:db8::/64"`,
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::").To16(), Mask: net.CIDRMask(64, 128)}),
		},
		{
			name:     "IPv4 Address without CIDR",
			input:    `"::ffff:10.1.1.1"`,
			expected: NewSubnet(&net.IPNet{IP: net.IPv4(10, 1, 1, 1).To16(), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv6 Address without CIDR",
			input:    `"::1"`,
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::1").To16(), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:          "Invalid Input",
			input:         `{"invalid": "input"}`,
			expectedError: fmt.Errorf("cannot unmarshal object into Go value of type string"),
		},
		{
			name:          "Invalid IP",
			input:         `"invalidIP"`,
			expectedError: errParseCIDRInvalidIP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var subnet Subnet
			// unmarshal json into subnet
			err := subnet.UnmarshalJSON([]byte(test.input))
			if test.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError.Error())
				require.Nil(t, subnet.IPNet)
			} else {
				require.NoError(t, err)

				// verify that the unmarshalled value matches the expected subnet
				require.Equal(t, test.expected, subnet)

				// marshal back to json to verify that the marshalled value matches the original input
				marshalled, err := subnet.MarshalJSON()
				require.NoError(t, err)
				require.JSONEq(t, test.input, string(marshalled))

				// parse back from the newly marshalled value verify match to both the original and expected values
				var parsedSubnet Subnet
				err = parsedSubnet.UnmarshalJSON(marshalled)
				require.NoError(t, err)
				require.Equal(t, subnet, parsedSubnet)
				require.Equal(t, test.expected, parsedSubnet)
			}
		})
	}
}

func (s *SubnetSuite) TestSubnet_MarshalJSON() {
	t := s.T()
	tests := []struct {
		name          string
		subnet        Subnet
		expected      string
		expectedError error
	}{
		{
			name:     "IPv4 Subnet with /24 CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(120, 128)}),
			expected: `"::ffff:192.168.1.0/120"`,
		},
		{
			name:     "IPv6 Subnet with /64 CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::").To16(), Mask: net.CIDRMask(64, 128)}),
			expected: `"2001:db8::/64"`,
		},
		{
			name:     "IPv4 Address without CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(10, 1, 1, 1).To16(), Mask: net.CIDRMask(128, 128)}),
			expected: `"::ffff:10.1.1.1"`,
		},
		{
			name:     "IPv6 Address without CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("::1").To16(), Mask: net.CIDRMask(128, 128)}),
			expected: `"::1"`,
		},
		{
			name:          "IP is nil",
			subnet:        NewSubnet(&net.IPNet{IP: nil, Mask: net.CIDRMask(0, 0)}),
			expectedError: ErrIPIsNIl,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// marshal subnet to json
			result, err := test.subnet.MarshalJSON()
			if test.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError.Error())
				require.Nil(t, result)
			} else {
				require.NoError(t, err)

				// verify that the marshalled value matches the expected value
				require.JSONEq(t, test.expected, string(result))

				// pass to parse subnet
				trimmedResult := strings.Trim(string(result), `"`)
				parsedSubnet, err := ParseSubnet(trimmedResult)
				require.NoError(t, err)

				// verify that the parsed subnet is the same as the original
				require.Equal(t, test.subnet, parsedSubnet)

				// marshal the newly parsed subnet and compare to the original marshalled result and expected value
				marshalledSubnet, err := parsedSubnet.MarshalJSON()
				require.NoError(t, err)
				require.JSONEq(t, string(marshalledSubnet), test.expected)
				require.JSONEq(t, string(marshalledSubnet), string(result))
			}
		})
	}
}

func (s *SubnetSuite) TestSubnet_ToIPString() {
	t := s.T()
	tests := []struct {
		name          string
		subnet        Subnet
		expected      string
		expectedError error
	}{
		{
			name:     "IPv4 Subnet in IPv6 Notation",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(120, 128)}),
			expected: "::ffff:192.168.1.0",
		},
		{
			name:     "IPv4 Subnet in IPv4 Notation",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)}),
			expected: "::ffff:192.168.1.0",
		},
		{
			name:     "IPv4 Subnet in IPv6 Notation but IPv4 Mask",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 32)}),
			expected: "::ffff:192.168.1.0",
		},
		{
			name:     "IPv6 Subnet with /64 CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
			expected: "2001:db8::",
		},
		{
			name:     "IPv4 Address without CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(10, 1, 1, 1), Mask: net.CIDRMask(128, 128)}),
			expected: "::ffff:10.1.1.1",
		},
		{
			name:     "IPv6 Address without CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}),
			expected: "::1",
		},
		{
			name:     "IPv6 Address with /48 CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8:abcd::"), Mask: net.CIDRMask(48, 128)}),
			expected: "2001:db8:abcd::",
		},
		{
			name:          "Nil IP",
			subnet:        NewSubnet(&net.IPNet{IP: nil, Mask: net.CIDRMask(0, 0)}),
			expectedError: ErrIPIsNIl,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.subnet.ToIPString()
			if test.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, result)
			}
		})
	}
}

func (s *SubnetSuite) TestSubnet_ToString() {
	t := s.T()
	tests := []struct {
		name     string
		subnet   Subnet
		expected string
	}{
		{
			name:     "IPv4 Subnet in IPv6 Notation",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(120, 128)}),
			expected: "::ffff:192.168.1.0/120",
		},
		{
			name:     "IPv4 Subnet in IPv4 Notation",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0), Mask: net.CIDRMask(24, 32)}),
			expected: "::ffff:192.168.1.0/120",
		},

		{
			name:     "IPv4 Subnet in IPv6 Notation but IPv4 Mask",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 32)}),
			expected: "::ffff:192.168.1.0/120",
		},
		{
			name:     "IPv6 Subnet with /64 CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
			expected: "2001:db8::/64",
		},
		{
			name:     "IPv4 Address",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(10, 1, 1, 1), Mask: net.CIDRMask(128, 128)}),
			expected: "::ffff:10.1.1.1/128",
		},
		{
			name:     "IPv6 Address",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}),
			expected: "::1/128",
		},
		{
			name:     "IPv6 Address with /48 CIDR",
			subnet:   NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8:abcd::"), Mask: net.CIDRMask(48, 128)}),
			expected: "2001:db8:abcd::/48",
		},
		{
			name:     "IPv4 CIDR /8 Mask",
			subnet:   NewSubnet(&net.IPNet{IP: net.IPv4(192, 0, 0, 0).To16(), Mask: net.CIDRMask(104, 128)}),
			expected: "::ffff:192.0.0.0/104",
		},
		{
			name:     "Empty Subnet",
			subnet:   NewSubnet(&net.IPNet{IP: nil, Mask: net.CIDRMask(0, 0)}),
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.subnet.ToString()
			require.Equal(t, test.expected, result)
		})
	}
}

func (s *SubnetSuite) TestSubnet_Scan() {
	t := s.T()
	tests := []struct {
		name          string
		src           any
		expected      Subnet
		expectedError error
	}{
		{
			name:     "Valid IPv4 Subnet String",
			src:      "192.168.1.0/24",
			expected: NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(120, 128)}),
		},
		{
			name:     "Valid IPv6 Subnet String",
			src:      "2001:db8::/64",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
		},
		{
			name:     "Valid IPv4 Address without CIDR",
			src:      "10.1.1.1",
			expected: NewSubnet(&net.IPNet{IP: net.IPv4(10, 1, 1, 1).To16(), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "Valid IPv6 Address without CIDR",
			src:      "::1",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:          "Invalid CIDR String",
			src:           "192.168.1.0/33",
			expected:      Subnet{},
			expectedError: fmt.Errorf("invalid CIDR address:"),
		},
		{
			name:          "Non-string Input - Int",
			src:           123,
			expected:      Subnet{},
			expectedError: fmt.Errorf("cannot scan int into Subnet"),
		},
		{
			name:          "Empty String",
			src:           "",
			expected:      Subnet{},
			expectedError: fmt.Errorf("unable to parse CIDR as subnet, empty string"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var subnet Subnet
			err := subnet.Scan(test.src)
			if test.expectedError != nil {
				require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, test.expected, subnet)
			}
		})
	}
}

func (s *SubnetSuite) TestSubnet_ToIPv6Notation() {
	t := s.T()
	tests := []struct {
		name     string
		subnet   Subnet
		expected Subnet
	}{
		{
			name:     "IPv4 Address",
			subnet:   Subnet{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 1), Mask: net.CIDRMask(32, 32)}},
			expected: Subnet{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 1).To16(), Mask: net.CIDRMask(128, 128)}},
		},
		{
			name:     "IPv4 CIDR",
			subnet:   Subnet{IPNet: &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)}},
			expected: Subnet{IPNet: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To16(), Mask: net.CIDRMask(104, 128)}},
		},
		{
			name:     "IPv4 CIDR with IPv6 Mask",
			subnet:   Subnet{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 1), Mask: net.CIDRMask(120, 128)}},
			expected: Subnet{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 1).To16(), Mask: net.CIDRMask(120, 128)}},
		},
		{
			name:     "IPv4 CIDR in IPv6 Notation but IPv4 Mask",
			subnet:   Subnet{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 1).To16(), Mask: net.CIDRMask(24, 32)}},
			expected: Subnet{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 1).To16(), Mask: net.CIDRMask(120, 128)}},
		},
		{
			name:     "IPv6 Address",
			subnet:   Subnet{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}},
			expected: Subnet{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}},
		},
		{
			name:     "IPv6 with IPv4 Mask",
			subnet:   Subnet{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(24, 32)}},
			expected: Subnet{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(120, 128)}},
		},
		{
			name:     "Empty Input",
			subnet:   Subnet{IPNet: &net.IPNet{IP: nil, Mask: net.CIDRMask(0, 0)}},
			expected: Subnet{IPNet: &net.IPNet{IP: nil, Mask: net.CIDRMask(0, 0)}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// execute the conversion
			test.subnet.ToIPv6Notation()

			// check if the IP and Mask match the expected result
			require.Equal(t, test.expected.IPNet.IP, test.subnet.IPNet.IP)
			require.Equal(t, test.expected.IPNet.Mask, test.subnet.IPNet.Mask)
			require.Equal(t, test.expected, test.subnet)
		})
	}
}

func (s *SubnetSuite) TestParseSubnet() {
	t := s.T()

	tests := []struct {
		name          string
		input         string
		expected      Subnet
		expectedError error
	}{
		{
			name:     "IPv4 Address",
			input:    "192.168.1.1",
			expected: NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 1}.To16(), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv4 CIDR with 32 Bit Mask",
			input:    "192.168.1.1/32",
			expected: NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 1}.To16(), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv4 CIDR with 24 Bit Mask",
			input:    "10.1.1.1/24",
			expected: NewSubnet(&net.IPNet{IP: net.IP{10, 1, 1, 0}.To16(), Mask: net.CIDRMask(120, 128)}),
		},
		{
			name:     "IPv4 CIDR with 16 Bit Mask",
			input:    "10.99.45.67/16",
			expected: NewSubnet(&net.IPNet{IP: net.IP{10, 99, 0, 0}.To16(), Mask: net.CIDRMask(112, 128)}),
		},
		{
			name:     "IPv4 CIDR with 8 Bit Mask",
			input:    "192.168.100.99/8",
			expected: NewSubnet(&net.IPNet{IP: net.IP{192, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}),
		},
		{
			name:     "IPv4 Zero",
			input:    net.IPv4zero.String(),
			expected: NewSubnet(&net.IPNet{IP: net.IP{0, 0, 0, 0}.To16(), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv4-Mapped IPv6 Address",
			input:    "::ffff:192.168.1.1",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::ffff:192.168.1.1"), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv4-Mapped IPv6 CIDR",
			input:    "::ffff:10.10.42.158/120",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::ffff:10.10.42.0"), Mask: net.CIDRMask(120, 128)}),
		},
		{
			name:     "IPv6 Address",
			input:    "::1",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv6 CIDR with 128 Bit Mask",
			input:    "2001:db8::1/128",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:     "IPv6 CIDR with 64 Bit Mask",
			input:    "2001:db8:abcd:1234:5678:9abc:def0:1234/64",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8:abcd:1234::"), Mask: net.CIDRMask(64, 128)}),
		},
		{
			name:     "IPv6 CIDR with 48 Bit Mask",
			input:    "2001:db8:abcd:5678:9abc:def0:1234:5678/48",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8:abcd::"), Mask: net.CIDRMask(48, 128)}),
		},
		{
			name:     "IPv6 CIDR with 32 Bit Mask",
			input:    "2001:db8:1234:5678:9abc:def0:1234:5678/32",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)}),
		},
		{
			name:     "IPv6 CIDR with 96 Bit Mask",
			input:    "2001:db8:abcd:1234:5678:9abc:def0:5678/96",
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8:abcd:1234:5678:9abc::"), Mask: net.CIDRMask(96, 128)}),
		},
		{
			name:     "IPv6 Zero",
			input:    net.IPv6zero.String(),
			expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::"), Mask: net.CIDRMask(128, 128)}),
		},
		{
			name:          "Invalid CIDR",
			input:         "192.168.1.0/33",
			expectedError: &net.ParseError{Type: "CIDR address", Text: ""},
		},
		{
			name:          "Invalid IPv4-Mapped IPv6 CIDR - Invalid IP",
			input:         "::ffff:---/b",
			expectedError: errParseCIDRInvalidIP,
		},
		{
			name:          "Invalid IPv4-Mapped IPv6 CIDR - Invalid Mask",
			input:         "::ffff:192.168.1.0/b",
			expectedError: errParseCIDRInvalidMask,
		},
		{
			name:          "Invalid IPv4-Mapped IPv6 CIDR - Invalid Numerical Mask",
			input:         "::ffff:192.168.1.0/33",
			expectedError: errParseCIDRInvalidNumMask,
		},
		{
			name:          "Invalid IP",
			input:         "invalidIP",
			expectedError: errParseCIDRInvalidIP,
		},
		{
			name:          "Empty Input",
			input:         "",
			expectedError: errParseCIDREmptyString,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ParseSubnet(test.input)

			if test.expectedError != nil {
				require.Error(t, err, "expected an error but got none")
				require.ErrorContains(t, err, test.expectedError.Error(), "error message must contain expected error")
			} else {
				require.NoError(t, err, "did not expect an error but got one")
				require.Equal(t, test.expected, result, "parsed subnet should match expected value")
			}
		})
	}
}

func (s *SubnetSuite) TestCompactSubnets() {
	t := s.T()
	tests := []struct {
		name     string
		subnets  []Subnet
		expected []Subnet
	}{
		{
			name: "Has Duplicates",
			subnets: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To16(), Mask: net.CIDRMask(8, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To16(), Mask: net.CIDRMask(8, 128)}),
			},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To16(), Mask: net.CIDRMask(8, 128)}),
			},
		},
		{
			name: "No Duplicates",
			subnets: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To16(), Mask: net.CIDRMask(8, 128)}),
			},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To16(), Mask: net.CIDRMask(8, 128)}),
			},
		},
		{
			name: "All Duplicates",
			subnets: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
			},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IPv4(192, 168, 1, 0).To16(), Mask: net.CIDRMask(24, 128)}),
			},
		},
		{
			name:     "Empty list",
			subnets:  []Subnet{},
			expected: []Subnet{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompactSubnets(tt.subnets)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

func (s *SubnetSuite) TestIncludeMandatorySubnets() {
	t := s.T()
	tests := []struct {
		name      string
		data      []Subnet
		mandatory []Subnet
		expected  []Subnet
	}{
		{
			name:      "All elements present",
			data:      NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
			mandatory: NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64"}),
			expected:  NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
		},
		{
			name:      "Some elements missing",
			data:      NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64"}),
			mandatory: NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
			expected:  NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
		},
		{
			name:      "No elements present",
			data:      []Subnet{},
			mandatory: NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
			expected:  NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
		},
		{
			name:      "Empty mandatory list",
			data:      NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
			mandatory: []Subnet{},
			expected:  NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}),
		},
		{
			name:      "No elements in both lists",
			data:      []Subnet{},
			mandatory: []Subnet{},
			expected:  []Subnet{},
		},
		{
			name:      "Duplicate elements in mandatory list",
			data:      NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64"}),
			mandatory: NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "ffee::1/64", "10.55.100.100/24", "::ffff:10.55.100.100/120"}),
			expected:  NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24", "10.55.100.100/24"}), // duplicate ipv4-mapped ipv6 address should be a duplicate of the original ipv4 address
		},
		{
			name:      "Duplicate elements in mandatory list, compacted",
			data:      NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64"}),
			mandatory: CompactSubnets(NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "ffee::1/64", "10.55.100.100/24", "::ffff:10.55.100.100/120"})),
			expected:  NewTestSubnetList(t, []string{"192.168.0.11/12", "ffee::1/64", "10.55.100.100/24"}), // duplicate ipv4-mapped ipv6 address should have been compacted
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IncludeMandatorySubnets(test.data, test.mandatory)
			require.ElementsMatch(t, test.expected, result, "resulting list should match expected value, expected: %v, got: %v", test.expected, result)
		})
	}
}
