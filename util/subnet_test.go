package util

import (
	"fmt"
	"net"
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
		// TODO: since formatting doesn't match the ParseSubnets results, we should
		// update either parsesubnets or parsesubnet to match
		// {
		// 	name:  "Valid IPv4 CIDRs",
		// 	input: []string{"192.168.1.0/24", "10.0.0.0/8"},
		// 	expected: []Subnet{
		// 		NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)}),
		// 		NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)}),
		// 	},
		// },
		// {
		// 	name:  "Valid IPv6 CIDRs",
		// 	input: []string{"2001:db8::/64", "2001:0db8:85a3::/48"},
		// 	expected: []Subnet{
		// 		NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
		// 		NewSubnet(&net.IPNet{IP: net.ParseIP("2001:0db8:85a3::"), Mask: net.CIDRMask(48, 128)}),
		// 	},
		// },
		// {
		// 	name:  "Mixed IPv4 and IPv6 CIDRs",
		// 	input: []string{"192.168.1.0/24", "2001:db8::/64"},
		// 	expected: []Subnet{
		// 		NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)}),
		// 		NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
		// 	},
		// },
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

func (s *SubnetSuite) TestParseSubnets() {
	t := s.T()

	tests := []struct {
		name      string
		subnets   []string
		expected  []Subnet
		expectErr bool
	}{
		{
			name:    "Valid CIDR",
			subnets: []string{"192.168.1.0/24", "10.0.0.0/8"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)}),
				NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)}),
			},
		},
		{
			name:    "Single IP",
			subnets: []string{"192.168.1.1"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 1}, Mask: net.CIDRMask(32, 32)}),
			},
		},
		{
			name:    "Multiple IPs",
			subnets: []string{"192.168.1.1", "10.0.0.1"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 1}, Mask: net.CIDRMask(32, 32)}),
				NewSubnet(&net.IPNet{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(32, 32)}),
			},
		},
		{
			name:    "IPv6 Address",
			subnets: []string{"2001:db8::1"},
			expected: []Subnet{
				NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(128, 128)}),
			},
		},
		{
			name:      "Invalid CIDR",
			subnets:   []string{"192.168.1.0/33"},
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "Invalid IP",
			subnets:   []string{"invalidIP"},
			expected:  nil,
			expectErr: true,
		},
		{
			name:      "Mixed Valid and Invalid",
			subnets:   []string{"192.168.1.0/24", "invalidIP"},
			expected:  nil,
			expectErr: true,
		},
		{
			name:     "Empty input",
			subnets:  []string{},
			expected: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// parse the subnets
			result, err := ParseSubnets(test.subnets)

			// check expected error and results
			if test.expectErr {
				require.Error(t, err, "parsing subnets should produce an error")
			} else {
				require.NoError(t, err, "parsing subnets should not produce an error")
				require.Equal(t, test.expected, result, "parsed subnets should match expected value")
			}
		})
	}
}

func (s *SubnetSuite) TestParseSubnet() {
	t := s.T()

	tests := []struct {
		name      string
		input     string
		expected  Subnet
		expectErr bool
	}{
		// TODO: since formatting doesn't match the ParseSubnets results, we should
		// update either parsesubnets or parsesubnet to match
		// {
		// 	name:     "Valid IPv4 Address",
		// 	input:    "192.168.1.1",
		// 	expected: NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 1}, Mask: net.CIDRMask(128, 128)}),
		// },
		// {
		// 	name:     "Valid IPv4 in IPv6 Notation",
		// 	input:    "::ffff:192.168.1.1",
		// 	expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::ffff:192.168.1.1"), Mask: net.CIDRMask(128, 128)}),
		// },
		// {
		// 	name:     "Valid IPv4 CIDR",
		// 	input:    "192.168.1.0/24",
		// 	expected: NewSubnet(&net.IPNet{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)}),
		// },
		// {
		// 	name:     "Valid IPv4 CIDR in IPv6 Notation",
		// 	input:    "::ffff:192.168.1.0/120",
		// 	expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::ffff:192.168.1.0"), Mask: net.CIDRMask(120, 128)}),
		// },
		// {
		// 	name:     "Valid IPv6 Address",
		// 	input:    "::1/128",
		// 	expected: NewSubnet(&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)}),
		// },
		// {
		// 	name:     "Valid IPv6 CIDR",
		// 	input:    "2001:db8::/64",
		// 	expected: NewSubnet(&net.IPNet{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(64, 128)}),
		// },

		{
			name:      "Invalid CIDR",
			input:     "192.168.1.0/33",
			expected:  Subnet{},
			expectErr: true,
		},
		{
			name:      "Invalid IP",
			input:     "invalidIP",
			expected:  Subnet{},
			expectErr: true,
		},
		{
			name:      "Empty Input",
			input:     "",
			expected:  Subnet{},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ParseSubnet(test.input)

			if test.expectErr {
				require.Error(t, err, "expected an error but got none")
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
