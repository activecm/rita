package util

import (
	"crypto/md5" // #nosec G501
	"database/sql/driver"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/go-github/github"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
)

func TestNewFixedStringHash(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		expected  FixedString
		expectErr bool
	}{
		{
			name: "Single string",
			args: []string{"hello"},
			expected: FixedString{
				// #nosec G401 : this md5 is used for hashing, not for security
				Data: md5.Sum([]byte("hello")),
			},
			expectErr: false,
		},
		{
			name: "Multiple strings",
			args: []string{"hello", "world"},
			expected: FixedString{
				Data: md5.Sum([]byte("helloworld")), // #nosec G401
			},
			expectErr: false,
		},

		{
			name: "Combination of strings",
			args: []string{"foo", "bar", "baz"},
			expected: FixedString{
				Data: md5.Sum([]byte("foobarbaz")), // #nosec G401
			},
			expectErr: false,
		},
		{
			name: "Whitespace strings",
			args: []string{" ", " "},
			expected: FixedString{
				Data: md5.Sum([]byte("  ")), // #nosec G401
			},
			expectErr: false,
		},
		{
			name: "Empty string",
			args: []string{""},
			expected: FixedString{
				Data: md5.Sum([]byte("")), // #nosec G401
			},
			expectErr: true,
		},
		{
			name: "Multiple empty strings",
			args: []string{"", ""},
			expected: FixedString{
				Data: md5.Sum([]byte("")), // #nosec G401
			},
			expectErr: true,
		},
		{
			name:      "No arguments",
			args:      []string{},
			expected:  FixedString{},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NewFixedStringHash(test.args...)
			if test.expectErr {
				require.Error(t, err, "error was expected")
			} else {
				require.NoError(t, err, "generating hash should not produce an error")
				require.Equal(t, test.expected, result, "hash should match expected value")
			}
		})
	}
}

func TestNewFixedStringFromHex(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expected      FixedString
		expectedError error
	}{
		{
			name:  "Valid Hex String",
			input: "00112233445566778899aabbccddeeff",
			expected: FixedString{
				Data: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			},
			expectedError: nil,
		},
		{
			name:  "Valid Hex String Shorter than 16 bytes",
			input: "0011223344556677",
			expected: FixedString{
				Data: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			expectedError: nil,
		},
		{
			name:  "Valid Hex String Longer than 16 bytes",
			input: "00112233445566778899aabbccddeeffaabbccddeeff",
			expected: FixedString{
				Data: [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			},
			expectedError: nil,
		},
		{
			name:          "Invalid Hex String",
			input:         "invalidhexstring",
			expected:      FixedString{},
			expectedError: fmt.Errorf("error decoding hex string: "),
		},
		{
			name:          "Empty Hex String",
			input:         "",
			expected:      FixedString{},
			expectedError: fmt.Errorf("hex string is empty"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NewFixedStringFromHex(test.input)

			if test.expectedError != nil {
				require.Error(t, err, "error should not be nil")
				require.ErrorContains(t, err, test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(t, err, "converting hex to fixed string should not produce an error")
				require.Equal(t, test.expected, result, "the result should match the expected value")
			}
		})
	}
}

func TestFixedString_Hex(t *testing.T) {
	tests := []struct {
		name     string
		input    FixedString
		expected string
	}{
		{
			name:     "All Zeros",
			input:    FixedString{Data: [16]byte{}},
			expected: "00000000000000000000000000000000",
		},
		{
			name:     "Mixed Data",
			input:    FixedString{Data: [16]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}},
			expected: "000102030405060708090A0B0C0D0E0F",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.input.Hex()
			require.Equal(t, test.expected, result)
		})
	}
}

func TestFixedString_MarshalBinary(t *testing.T) {
	tests := []struct {
		name     string
		input    FixedString
		expected []byte
	}{
		{
			name:     "All Zeros",
			input:    FixedString{Data: [16]byte{}},
			expected: make([]byte, 16),
		},
		{
			name:     "Mixed Data",
			input:    FixedString{Data: [16]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}},
			expected: []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.input.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestFixedString_UnmarshalBinary(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected FixedString
	}{
		{
			name:     "All Zeros",
			input:    make([]byte, 16),
			expected: FixedString{Data: [16]byte{}},
		},
		{
			name:     "Mixed Data",
			input:    []byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF},
			expected: FixedString{Data: [16]byte{0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result FixedString
			err := result.UnmarshalBinary(test.input)
			require.NoError(t, err)
			require.Equal(t, test.expected, result)
		})
	}
}

func TestFixedString_Value(t *testing.T) {
	tests := []struct {
		name     string
		input    FixedString
		expected driver.Value
	}{
		{
			name:     "Default Value",
			input:    FixedString{},
			expected: "",
		},
		{
			name:     "With Value",
			input:    FixedString{val: "example"},
			expected: "example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := test.input.Value()
			require.NoError(t, err)
			require.Equal(t, test.expected, *result.(*string))
		})
	}
}

func TestValidFQDN(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{
			name:     "Valid FQDN",
			value:    "example.com",
			expected: true,
		},
		{
			name:     "Valid FQDN with Multiple Subdomains",
			value:    "sub.example.com",
			expected: true,
		},
		{
			name:     "Valid FQDN with Hyphen",
			value:    "sub-domain.example.com",
			expected: true,
		},
		{
			name:     "Single Label",
			value:    "example",
			expected: false,
		},
		{
			name:     "Trailing Dot",
			value:    "example.com.",
			expected: false,
		},
		{
			name:     "Invalid Underscore",
			value:    "sub_domain.example.com",
			expected: false,
		},
		{
			name:     "Invalid Spaces",
			value:    "example .com",
			expected: false,
		},
		{
			name:     "Invalid Special Characters",
			value:    "exa$mple.com",
			expected: false,
		},
		{
			name:     "TLD Too Short",
			value:    "example.c",
			expected: false,
		},
		{
			name:     "Empty String",
			value:    "",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ValidFQDN(test.value)
			require.Equal(t, test.expected, result, "the result should match the expected value")
		})
	}
}

func TestContainsIP(t *testing.T) {
	tests := []struct {
		name      string
		subnets   []*net.IPNet
		ip        net.IP
		contained bool
	}{
		{
			name: "IP in subnet",
			subnets: []*net.IPNet{
				{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)},
			},
			ip:        net.IP{192, 168, 1, 1},
			contained: true,
		},
		{
			name: "IP not in subnet",
			subnets: []*net.IPNet{
				{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)},
			},
			ip:        net.IP{10, 0, 0, 1},
			contained: false,
		},
		{
			name: "IP in multiple subnets",
			subnets: []*net.IPNet{
				{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)},
				{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
			},
			ip:        net.IP{10, 0, 0, 1},
			contained: true,
		},
		{
			name: "IPv6 address in subnet",
			subnets: []*net.IPNet{
				{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
			},
			ip:        net.ParseIP("2001:db8::1"),
			contained: true,
		},
		{
			name: "IPv6 address not in subnet",
			subnets: []*net.IPNet{
				{IP: net.ParseIP("2001:db8::"), Mask: net.CIDRMask(32, 128)},
			},
			ip:        net.ParseIP("2001:db9::1"),
			contained: false,
		},
		{
			name:      "Empty subnets list",
			subnets:   []*net.IPNet{},
			ip:        net.IP{192, 168, 1, 1},
			contained: false,
		},
		{
			name: "IP in overlapping subnets",
			subnets: []*net.IPNet{
				{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
				{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)},
			},
			ip:        net.IP{192, 168, 1, 1},
			contained: true,
		},
		{
			name: "IP in smaller overlapping subnet",
			subnets: []*net.IPNet{
				{IP: net.IP{192, 168, 0, 0}, Mask: net.CIDRMask(16, 32)},
				{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(28, 32)},
			},
			ip:        net.IP{192, 168, 1, 1},
			contained: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ContainsIP(test.subnets, test.ip)
			require.Equal(t, test.contained, result, "contained should match expected value")
		})
	}
}

func TestParseSubnets(t *testing.T) {
	tests := []struct {
		name      string
		subnets   []string
		expected  []*net.IPNet
		expectErr bool
	}{
		{
			name:    "Valid CIDR",
			subnets: []string{"192.168.1.0/24", "10.0.0.0/8"},
			expected: []*net.IPNet{
				{IP: net.IP{192, 168, 1, 0}, Mask: net.CIDRMask(24, 32)},
				{IP: net.IP{10, 0, 0, 0}, Mask: net.CIDRMask(8, 32)},
			},
			expectErr: false,
		},
		{
			name:    "Single IP",
			subnets: []string{"192.168.1.1"},
			expected: []*net.IPNet{
				{IP: net.IP{192, 168, 1, 1}, Mask: net.CIDRMask(32, 32)},
			},
			expectErr: false,
		},
		{
			name:    "Multiple IPs",
			subnets: []string{"192.168.1.1", "10.0.0.1"},
			expected: []*net.IPNet{
				{IP: net.IP{192, 168, 1, 1}, Mask: net.CIDRMask(32, 32)},
				{IP: net.IP{10, 0, 0, 1}, Mask: net.CIDRMask(32, 32)},
			},
			expectErr: false,
		},
		{
			name:    "IPv6 Address",
			subnets: []string{"2001:db8::1"},
			expected: []*net.IPNet{
				{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(128, 128)},
			},
			expectErr: false,
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
			name:      "Empty input",
			subnets:   []string{},
			expected:  nil,
			expectErr: false,
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

func TestIPIsPubliclyRoutable(t *testing.T) {
	tests := []struct {
		name     string
		ip       net.IP
		routable bool
	}{
		{
			name:     "Private IPv4 Address 1",
			ip:       net.IP{10, 0, 0, 1},
			routable: false,
		},
		{
			name:     "Private IPv4 Address 2",
			ip:       net.IP{172, 16, 0, 1},
			routable: false,
		},
		{
			name:     "Private IPv4 Address 3",
			ip:       net.IP{192, 168, 1, 1},
			routable: false,
		},
		{
			name:     "Private IPv6 address",
			ip:       net.ParseIP("fc00::1"),
			routable: false,
		},
		{
			name:     "Public IPv4 Address 1",
			ip:       net.IP{8, 8, 8, 8},
			routable: true,
		},
		{
			name:     "Public IPv4 Address 2",
			ip:       net.IP{172, 217, 22, 14},
			routable: true,
		},
		{
			name:     "Public IPv4 Address 3",
			ip:       net.IP{192, 0, 2, 0},
			routable: true,
		},
		{
			name:     "Public IPv6 address",
			ip:       net.ParseIP("2001:4860:4860::8888"),
			routable: true,
		},
		{
			name:     "Loopback IPv4 address",
			ip:       net.IP{127, 0, 0, 1},
			routable: false,
		},
		{
			name:     "Link-local IPv4 Address",
			ip:       net.IP{169, 254, 0, 1},
			routable: false,
		},

		{
			name:     "Loopback IPv6 address",
			ip:       net.ParseIP("::1"),
			routable: false,
		},
		{
			name:     "Link-local IPv6 address",
			ip:       net.ParseIP("fe80::1"),
			routable: false,
		},
		{
			name:     "Multicast IPv6 address",
			ip:       net.ParseIP("ff02::1"),
			routable: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IPIsPubliclyRoutable(test.ip)
			require.Equal(t, test.routable, result, "routable should match expected value")
		})
	}
}

func TestParseNetworkID(t *testing.T) {

	tests := []struct {
		name              string
		ip                net.IP
		agentUUID         string
		expectedNetworkID uuid.UUID
	}{
		{ // agent uuids get overridden if ip is public
			name:              "Public IPv4 - Valid Agent UUID",
			ip:                net.IP{8, 8, 8, 8},
			agentUUID:         "02b1300b-dc4f-46dd-967e-698ccde5a920",
			expectedNetworkID: PublicNetworkUUID,
		},
		{
			name:              "Public IPv4 - Invalid Agent UUID",
			ip:                net.IP{8, 8, 8, 8},
			agentUUID:         "bingbong",
			expectedNetworkID: PublicNetworkUUID,
		},
		{
			name:              "Public IPv6 - Valid Agent UUID",
			ip:                net.ParseIP("2001:4860:4860::8888"),
			agentUUID:         "eb3a01e7-ac8a-461c-9582-b1d8727d240c",
			expectedNetworkID: PublicNetworkUUID,
		},
		{
			name:              "Public IPv6 - Invalid Agent UUID",
			ip:                net.ParseIP("2001:4860:4860::8888"),
			agentUUID:         "bingbong",
			expectedNetworkID: PublicNetworkUUID,
		},
		{
			name:      "Private IPv4 - Valid Agent UUID",
			ip:        net.IP{192, 168, 1, 1},
			agentUUID: "a9f1052c-fea4-4209-8362-7f33d2630bf2",
		},
		{
			name:              "Private IPv4 with Invalid Agent UUID",
			ip:                net.IP{192, 168, 1, 1},
			agentUUID:         "invalid-bing-bong",
			expectedNetworkID: UnknownPrivateNetworkUUID,
		},
		{
			name:      "Private IPv6 - Valid Agent UUID",
			ip:        net.ParseIP("fc00::1"),
			agentUUID: "2b648d28-26a1-460f-b417-651192562258",
		},
		{
			name:              "Private IPv6 - Invalid Agent UUID",
			ip:                net.ParseIP("fc00::1"),
			agentUUID:         "invalid-bing-bong",
			expectedNetworkID: UnknownPrivateNetworkUUID,
		},
		{
			name:              "Private IP with Empty Agent UUID",
			ip:                net.IP{192, 168, 1, 1},
			agentUUID:         "",
			expectedNetworkID: UnknownPrivateNetworkUUID,
		},
		{
			name:              "Loopback IP",
			ip:                net.IP{127, 0, 0, 1},
			agentUUID:         "some-agent-id",
			expectedNetworkID: UnknownPrivateNetworkUUID,
		},
		{
			name:              "Link-local IP",
			ip:                net.IP{169, 254, 0, 1},
			agentUUID:         "some-agent-id",
			expectedNetworkID: UnknownPrivateNetworkUUID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ParseNetworkID(test.ip, test.agentUUID)

			// if expected is not nil, check if the result matches the expected value
			// otherwise, parse the expected value and vet against the result
			if test.expectedNetworkID != uuid.Nil {
				require.Equal(t, test.expectedNetworkID, result, "network uuid should match expected value")
			} else {
				uuid, err := uuid.Parse(test.agentUUID)
				require.NoError(t, err)
				require.Equal(t, uuid, result, "network uuid should match expected value")
			}
		})
	}
}

func TestContainsDomain(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		domains   []string
		contained bool
	}{
		{
			name:      "Exact Match",
			domains:   []string{"bingbong", "test.com"},
			host:      "bingbong",
			contained: true,
		},
		{
			name:      "No Match",
			domains:   []string{"bingbong", "test.com"},
			host:      "notindomain.com",
			contained: false,
		},
		{
			name:      "Wildcard Match",
			domains:   []string{"*.bingbong", "test.com"},
			host:      "sub.bingbong",
			contained: true,
		},
		{
			name:      "Wildcard Top Domain",
			domains:   []string{"*.bingbong", "test.com"},
			host:      "bingbong",
			contained: true,
		},
		{
			name:      "Wildcard Root",
			domains:   []string{"*.com"},
			host:      "bingbong.com",
			contained: true,
		},
		{
			name:      "Wildcard, No Match",
			domains:   []string{"*.bingbong", "test.com"},
			host:      "sub.test.com",
			contained: false,
		},
		{
			name:      "Multiple Wildcards, Match",
			domains:   []string{"*.bingbong", "*.test.com"},
			host:      "sub.test.com",
			contained: true,
		},
		{
			name:      "Multiple Wildcards, No Match",
			domains:   []string{"*.bingbong", "*.test.com"},
			host:      "sub.another.com",
			contained: false,
		},
		{
			name:      "Wildcard Match with Subdomain",
			domains:   []string{"*.bingbong", "test.com"},
			host:      "super.sub.bingbong",
			contained: true,
		},
		{
			name:      "Empty Domains List",
			domains:   []string{},
			host:      "bingbong",
			contained: false,
		},
		{
			name:      "Empty Host",
			domains:   []string{"bingbong", "test.com"},
			host:      "",
			contained: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contained := ContainsDomain(test.domains, test.host)
			require.Equal(t, test.contained, contained, "contained should match expected value")
		})
	}
}

func TestEnsureSliceContainsAll(t *testing.T) {
	tests := []struct {
		name      string
		data      []string
		mandatory []string
		expected  []string
	}{
		{
			name:      "All elements present",
			data:      []string{"a", "b", "c"},
			mandatory: []string{"a", "b"},
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "Some elements missing",
			data:      []string{"a", "b"},
			mandatory: []string{"a", "b", "c"},
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "No elements present",
			data:      []string{},
			mandatory: []string{"a", "b", "c"},
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "Empty mandatory list",
			data:      []string{"a", "b", "c"},
			mandatory: []string{},
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "No elements in both lists",
			data:      []string{},
			mandatory: []string{},
			expected:  []string{},
		},
		{
			name:      "Duplicate elements in mandatory list",
			data:      []string{"a", "b"},
			mandatory: []string{"b", "c", "c"},
			expected:  []string{"a", "b", "c", "c"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := EnsureSliceContainsAll(test.data, test.mandatory)
			require.ElementsMatch(t, test.expected, result, "resulting list should match expected value")
		})
	}
}

func TestSortUInt32s(t *testing.T) {
	tests := []struct {
		name     string
		data     []uint32
		expected []uint32
	}{
		{
			name:     "Already sorted",
			data:     []uint32{1, 2, 3, 4, 5},
			expected: []uint32{1, 2, 3, 4, 5},
		},
		{
			name:     "Reverse order",
			data:     []uint32{5, 4, 3, 2, 1},
			expected: []uint32{1, 2, 3, 4, 5},
		},
		{
			name:     "Unsorted",
			data:     []uint32{3, 1, 4, 5, 2},
			expected: []uint32{1, 2, 3, 4, 5},
		},
		{
			name:     "With duplicates",
			data:     []uint32{3, 1, 4, 1, 5, 2, 3},
			expected: []uint32{1, 1, 2, 3, 3, 4, 5},
		},
		{
			name:     "Single element",
			data:     []uint32{1},
			expected: []uint32{1},
		},
		{
			name:     "Empty slice",
			data:     []uint32{},
			expected: []uint32{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SortUInt32s(test.data)
			require.Equal(t, test.expected, test.data, "the sorted data should match the expected value")
		})
	}
}

func TestUInt32sAreSorted(t *testing.T) {
	tests := []struct {
		name     string
		data     []uint32
		expected bool
	}{
		{
			name:     "Sorted data",
			data:     []uint32{1, 2, 3, 4, 5},
			expected: true,
		},
		{
			name:     "Unsorted data",
			data:     []uint32{5, 3, 4, 1, 2},
			expected: false,
		},
		{
			name:     "Empty data",
			data:     []uint32{},
			expected: true,
		},
		{
			name:     "Single element",
			data:     []uint32{42},
			expected: true,
		},
		{
			name:     "All elements equal",
			data:     []uint32{7, 7, 7, 7},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := UInt32sAreSorted(test.data)
			require.Equal(t, test.expected, result, "the result should match the expected value")
		})
	}
}

func TestValidateTimestamp(t *testing.T) {
	tests := []struct {
		name         string
		timestamp    time.Time
		expectedTime time.Time
		replaced     bool
	}{
		{
			name:         "Valid timestamp",
			timestamp:    time.Date(2024, time.June, 3, 23, 24, 10, 0, time.Local),
			expectedTime: time.Date(2024, time.June, 3, 23, 24, 10, 0, time.Local),
			replaced:     false,
		},
		{
			name:         "Log Floating-Pont Timestamp",
			timestamp:    time.Unix(1517336108, int64((0.231879)*1e9)), // 1517336108.231879
			expectedTime: time.Unix(1517336108, 231879000),
			replaced:     false,
		},
		{
			name:         "Unset Timestamp",
			timestamp:    time.Time{},
			expectedTime: time.Unix(0, 1),
			replaced:     true,
		},
		{
			name:         "MaxInt64 timestamp",
			timestamp:    time.Unix(math.MaxInt64, 0),
			expectedTime: time.Unix(0, 1),
			replaced:     true,
		},
		{
			name:         "Negative timestamp",
			timestamp:    time.Unix(-1, 0),
			expectedTime: time.Unix(0, 1),
			replaced:     true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ts, replaced := ValidateTimestamp(test.timestamp)
			require.Equal(t, test.expectedTime, ts, "timestamp should match expected value")
			require.Equal(t, test.replaced, replaced, "replaced should match expected value")
		})
	}
}

func TestParseRelativePath(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	fmt.Println("home: ", home)

	workingDir, err := os.Getwd()
	require.NoError(t, err)

	currentDir := path.Dir(path.Join(workingDir))

	tests := []struct {
		name      string
		path      string
		expected  string
		expectErr error
	}{
		{
			name:      "Home directory",
			path:      "~/data",
			expected:  home + "/data",
			expectErr: nil,
		},
		{
			name:     "Current directory path",
			path:     "./",
			expected: workingDir,
			// 	expectedPath:  filepath.Join(currentDir, "./mydir"),
			expectErr: nil,
		},
		{
			name:      "Relative directory - 1 deep",
			path:      "./data",
			expected:  workingDir + "/data",
			expectErr: nil,
		},
		{
			name:      "Relative directory - 2 deep",
			path:      "../data",
			expected:  currentDir + "/data",
			expectErr: nil,
		},
		{
			name:      "Absolute path",
			path:      "/home/logs",
			expected:  "/home/logs",
			expectErr: nil,
		},
		{
			name:      "Empty path",
			expected:  "",
			expectErr: ErrInvalidPath,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ParseRelativePath(test.path)
			if test.expectErr != nil {
				require.EqualError(t, err, test.expectErr.Error(), "error should match expected value")
			} else {
				require.NoError(t, err, "parsing relative path should not produce an error")
				require.Equal(t, test.expected, result, "relative path should match expected value, got: %s, expected: %s", result, test.expected)
			}
		})
	}
}

func TestValidateDirectory(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(afs afero.Fs)
		dir           string
		expectedError error
	}{
		{
			name: "Directory is Valid",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/nonemptydir", 0755))
				require.NoError(t, afero.WriteFile(afs, "/nonemptydir/file.txt", []byte("content"), 0644))
			},
			dir:           "/nonemptydir",
			expectedError: nil,
		},
		{
			name:          "Directory Does Not Exist",
			setup:         func(_ afero.Fs) {},
			dir:           "/nonexistent",
			expectedError: ErrDirDoesNotExist,
		},
		{
			name: "Path is Not a Directory",
			setup: func(afs afero.Fs) {
				require.NoError(t, afero.WriteFile(afs, "/file.txt", []byte("content"), 0644))
			},
			dir:           "/file.txt",
			expectedError: ErrPathIsNotDir,
		},
		{
			name: "Directory is Empty",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/emptydir", 0755))
			},
			dir:           "/emptydir",
			expectedError: ErrDirIsEmpty,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			afs := afero.NewMemMapFs()
			test.setup(afs)

			err := ValidateDirectory(afs, test.dir)
			if test.expectedError != nil {
				require.Error(t, err, "error should not be nil")
				require.ErrorContains(t, err, test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(t, err, "validating directory should not produce an error")
			}
		})
	}
}

func TestValidateFile(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(afs afero.Fs)
		file          string
		expectedError error
	}{
		{
			name: "File is Valid",
			setup: func(afs afero.Fs) {
				require.NoError(t, afero.WriteFile(afs, "/file.txt", []byte("content"), 0644))
			},
			file:          "/file.txt",
			expectedError: nil,
		},
		{
			name: "File is Empty",
			setup: func(afs afero.Fs) {
				require.NoError(t, afero.WriteFile(afs, "/emptyfile.txt", []byte(""), 0644))
			},
			file:          "/emptyfile.txt",
			expectedError: ErrFileIsEmtpy,
		},
		{
			name:          "File Does Not Exist",
			setup:         func(_ afero.Fs) {},
			file:          "/nonexistent",
			expectedError: ErrFileDoesNotExist,
		},
		{
			name: "Path is a Directory",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/directory", 0755))
			},
			file:          "/directory",
			expectedError: ErrPathIsDir,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			afs := afero.NewMemMapFs()
			test.setup(afs)

			err := ValidateFile(afs, test.file)
			if test.expectedError != nil {
				require.Error(t, err, "error should not be nil")
				require.ErrorContains(t, err, test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(t, err, "validating file should not produce an error")
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(afs afero.Fs)
		path          string
		expected      [3]bool // exists, isDir, isEmpty
		expectedError error
	}{
		{
			name: "Path is Valid Non-Empty File",
			setup: func(afs afero.Fs) {
				require.NoError(t, afero.WriteFile(afs, "/file.txt", []byte("content"), 0644))
			},
			path:          "/file.txt",
			expected:      [3]bool{true, false, false},
			expectedError: nil,
		},
		{
			name: "Path is Valid Empty File",
			setup: func(afs afero.Fs) {
				require.NoError(t, afero.WriteFile(afs, "/file.txt", []byte(""), 0644))
			},
			path:          "/file.txt",
			expected:      [3]bool{true, false, true},
			expectedError: nil,
		},
		{
			name: "Path is Valid Non-Empty Directory",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/nonemptydir", 0755))
				require.NoError(t, afero.WriteFile(afs, "/nonemptydir/file.txt", []byte("content"), 0644))
			},
			path:          "/nonemptydir",
			expected:      [3]bool{true, true, false},
			expectedError: nil,
		},
		{
			name: "Path is Valid Empty Directory",
			setup: func(afs afero.Fs) {
				require.NoError(t, afs.Mkdir("/emptydir", 0755))
			},
			path:          "/emptydir",
			expected:      [3]bool{true, true, true},
			expectedError: nil,
		},
		{
			name:          "Non-Existent Path",
			setup:         func(_ afero.Fs) {},
			path:          "/nonexistent",
			expected:      [3]bool{false, false, false},
			expectedError: nil,
		},
		{
			name:          "Empty Path",
			setup:         func(_ afero.Fs) {},
			path:          "",
			expected:      [3]bool{false, false, false},
			expectedError: ErrInvalidPath,
		},
		{
			name:          "Nil filesystem",
			setup:         func(_ afero.Fs) {},
			path:          "/some/path",
			expected:      [3]bool{false, false, false},
			expectedError: fmt.Errorf("filesystem is nil"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var afs afero.Fs
			if test.name != "Nil filesystem" {
				afs = afero.NewMemMapFs()
			}
			test.setup(afs)

			exists, isDir, isEmpty, err := validatePath(afs, test.path)

			if test.expectedError != nil {
				// require.Error(t, err)
				require.ErrorContains(t, err, test.expectedError.Error(), "error should contain expected value")
			} else {
				require.NoError(t, err, "validating path should not produce an error")
				require.Equal(t, test.expected[0], exists, "exist flag should be %v", test.expected[0])
				require.Equal(t, test.expected[1], isDir, "isDir flag should be %v", test.expected[1])
				require.Equal(t, test.expected[2], isEmpty, "isEmpty flag should be %v", test.expected[2])
			}
		})
	}
}

func TestCheckForNewerVersion(t *testing.T) {
	tests := []struct {
		name           string
		latestVersion  string
		currentVersion string
		expectedNewer  bool
		expectedError  bool
	}{
		{
			name:           "Newer version available",
			latestVersion:  "v1.1.0",
			currentVersion: "v1.0.0",
			expectedNewer:  true,
			expectedError:  false,
		},
		{
			name:           "No newer version",
			latestVersion:  "v1.0.0",
			currentVersion: "v1.0.0",
			expectedNewer:  false,
			expectedError:  false,
		},
		{
			name:           "Invalid current version",
			latestVersion:  "v1.1.0",
			currentVersion: "invalid-version",
			expectedNewer:  false,
			expectedError:  true,
		},
		{
			name:           "Invalid latest version",
			latestVersion:  "invalid-version",
			currentVersion: "v1.0.0",
			expectedNewer:  false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"tag_name": "%s"}`, tt.latestVersion)
			}))
			defer ts.Close()

			// Override the GitHub client base URL
			client := github.NewClient(nil)
			newBaseURL, err := client.BaseURL.Parse(ts.URL + "/")
			require.NoError(t, err, "failed to parse base URL")
			client.BaseURL = newBaseURL

			// Check for newer version
			newer, version, err := CheckForNewerVersion(client, tt.currentVersion)

			// Check for expected error
			if tt.expectedError {
				require.Error(t, err, "error was expected")
			} else {
				require.NoError(t, err, "checking for newer version should not produce an error")

				// Check the expected values
				require.Equal(t, tt.expectedNewer, newer)
				require.Equal(t, tt.latestVersion, version)
			}
		})
	}
}

func TestGetLatestReleaseVersion(t *testing.T) {
	tests := []struct {
		name          string
		owner         string
		repo          string
		latestVersion string
		expected      string
		expectedError bool
	}{
		{
			name:          "Valid Latest Release",
			owner:         "activecm",
			repo:          "rita",
			latestVersion: "v2.0.0",
			expected:      "v2.0.0",
			expectedError: false,
		},
		{
			name:          "Error Fetching Latest Release",
			owner:         "activecm",
			repo:          "rita",
			expected:      "",
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a test server
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if test.expectedError {
					http.Error(w, "error", http.StatusInternalServerError)
				} else {
					fmt.Fprintf(w, `{"tag_name": "%s"}`, test.latestVersion)
				}
			}))
			defer ts.Close()

			// Override the GitHub client base URL
			client := github.NewClient(nil)
			newBaseURL, err := client.BaseURL.Parse(ts.URL + "/")
			require.NoError(t, err, "failed to parse base URL")
			client.BaseURL = newBaseURL

			result, err := GetLatestReleaseVersion(client, test.owner, test.repo)

			if test.expectedError {
				require.Error(t, err, "error should not be nil")
				require.ErrorContains(t, err, "error fetching latest release", "error should contain expected value")
			} else {
				require.NoError(t, err, "fetching latest release should not produce an error")
				require.Equal(t, test.expected, result, "the result should match the expected value")
			}

		})
	}
}
