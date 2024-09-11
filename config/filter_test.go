package config

import (
	"net"
	"testing"

	"github.com/activecm/rita/v5/util"
	"github.com/stretchr/testify/require"
)

func TestFilterConnPair(t *testing.T) {
	internalSubnetListEmpty := []util.IPNet{}

	internalSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{11, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{120, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	alwaysIncludedSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{35, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{170, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	neverIncludedSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{12, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{150, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	// load config
	cfg, err := GetDefaultConfig()
	require.NoError(t, err)

	// set config filter for external to internal to false
	cfg.Filtering.FilterExternalToInternal = false

	// AlwaysInclude list tests
	t.Run("AlwaysInclude list tests", func(t *testing.T) {
		cfg.Filtering.AlwaysIncludedSubnets = alwaysIncludedSubnetList
		checkCases := cfg.Filtering.FilterConnPair(net.IP{35, 0, 0, 0}, net.IP{190, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")

		cfg.Filtering.AlwaysIncludedSubnets = alwaysIncludedSubnetList
		checkCases = cfg.Filtering.FilterConnPair(net.IP{190, 0, 0, 0}, net.IP{35, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
	})

	// NeverInclude list tests
	t.Run("NeverInclude list tests", func(t *testing.T) {
		cfg.Filtering.NeverIncludedSubnets = neverIncludedSubnetList
		checkCases := cfg.Filtering.FilterConnPair(net.IP{12, 0, 0, 0}, net.IP{190, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")

		cfg.Filtering.NeverIncludedSubnets = neverIncludedSubnetList
		checkCases = cfg.Filtering.FilterConnPair(net.IP{190, 0, 0, 0}, net.IP{12, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")
	})

	// InternalSubnets tests
	t.Run("InternalSubnets tests", func(t *testing.T) {
		cfg.Filtering.InternalSubnets = internalSubnetList

		// Both are external
		checkCases := cfg.Filtering.FilterConnPair(net.IP{185, 0, 0, 0}, net.IP{16, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")

		// Both are internal
		checkCases = cfg.Filtering.FilterConnPair(net.IP{11, 0, 0, 0}, net.IP{120, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")

		// Source is external, destination is internal, FilterExternalToInternal set
		cfg.Filtering.FilterExternalToInternal = true
		checkCases = cfg.Filtering.FilterConnPair(net.IP{180, 0, 0, 0}, net.IP{11, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")

		checkCases = cfg.Filtering.FilterDNSPair(net.IP{11, 0, 0, 0}, net.IP{120, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")

		// Empty list
		cfg.Filtering.InternalSubnets = internalSubnetListEmpty
		checkCases = cfg.Filtering.FilterConnPair(net.IP{180, 0, 0, 0}, net.IP{80, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
	})
}

func TestFilterDNSPair(t *testing.T) {
	internalSubnetListEmpty := []util.IPNet{}

	internalSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{11, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{120, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	alwaysIncludedSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{35, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{170, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	neverIncludedSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{12, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{150, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	// load config
	cfg, err := GetDefaultConfig()
	require.NoError(t, err)

	// set config filter for external to internal to false
	cfg.Filtering.FilterExternalToInternal = false

	// AlwaysInclude list tests
	t.Run("AlwaysInclude list tests", func(t *testing.T) {
		cfg.Filtering.AlwaysIncludedSubnets = alwaysIncludedSubnetList
		checkCases := cfg.Filtering.FilterDNSPair(net.IP{35, 0, 0, 0}, net.IP{190, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
		cfg.Filtering.AlwaysIncludedSubnets = alwaysIncludedSubnetList
		checkCases = cfg.Filtering.FilterDNSPair(net.IP{190, 0, 0, 0}, net.IP{35, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
	})

	// NeverInclude list tests
	t.Run("NeverInclude list tests", func(t *testing.T) {
		cfg.Filtering.NeverIncludedSubnets = neverIncludedSubnetList
		checkCases := cfg.Filtering.FilterDNSPair(net.IP{12, 0, 0, 0}, net.IP{190, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")
		cfg.Filtering.NeverIncludedSubnets = neverIncludedSubnetList
		checkCases = cfg.Filtering.FilterDNSPair(net.IP{190, 0, 0, 0}, net.IP{12, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")
	})

	// InternalSubnets tests
	t.Run("InternalSubnets tests", func(t *testing.T) {
		cfg.Filtering.InternalSubnets = internalSubnetList

		// Both are external
		checkCases := cfg.Filtering.FilterDNSPair(net.IP{185, 0, 0, 0}, net.IP{16, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")

		// Source is external, destination is internal, FilterExternalToInternal set
		cfg.Filtering.FilterExternalToInternal = true
		checkCases = cfg.Filtering.FilterDNSPair(net.IP{180, 0, 0, 0}, net.IP{120, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")
		checkCases = cfg.Filtering.FilterDNSPair(net.IP{11, 0, 0, 0}, net.IP{120, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")

		// Empty list
		cfg.Filtering.InternalSubnets = internalSubnetListEmpty
		checkCases = cfg.Filtering.FilterDNSPair(net.IP{180, 0, 0, 0}, net.IP{80, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
	})
}

func TestFilterSingleIP(t *testing.T) {

	alwaysIncludedSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{35, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
		{IPNet: &net.IPNet{IP: net.IP{170, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
	}

	neverIncludedSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{12, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
		{IPNet: &net.IPNet{IP: net.IP{150, 0, 0, 0}.To16(), Mask: net.CIDRMask(104, 128)}},
	}

	// load config
	cfg, err := GetDefaultConfig()
	require.NoError(t, err)

	// AlwaysInclude list test
	t.Run("AlwaysInclude list test", func(t *testing.T) {
		cfg.Filtering.AlwaysIncludedSubnets = alwaysIncludedSubnetList
		checkCases := cfg.Filtering.FilterSingleIP(net.IP{35, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
	})

	// NeverInclude list test
	t.Run("NeverInclude list test", func(t *testing.T) {
		cfg.Filtering.NeverIncludedSubnets = neverIncludedSubnetList
		checkCases := cfg.Filtering.FilterSingleIP(net.IP{12, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")
	})
}

func TestFilterDomain(t *testing.T) {
	alwaysIncludedDomainList := []string{
		"trustmebro-university.com",
		"expressbuy.com",
	}

	neverIncludedDomainList := []string{
		"bing.com",
		"google.com",
	}

	// load config
	cfg, err := GetDefaultConfig()
	require.NoError(t, err)

	// AlwaysInclude list test
	t.Run("AlwaysInclude list test", func(t *testing.T) {
		cfg.Filtering.AlwaysIncludedDomains = alwaysIncludedDomainList
		checkCases := cfg.Filtering.FilterDomain("trustmebro-university.com")
		require.False(t, checkCases, "filter state should match expected value")
	})

	// NeverInclude list test
	t.Run("NeverInclude list test", func(t *testing.T) {
		cfg.Filtering.NeverIncludedDomains = neverIncludedDomainList
		checkCases := cfg.Filtering.FilterDomain("bing.com")
		require.True(t, checkCases, "filter state should match expected value")
	})
}

func TestFilterNeverInclude(t *testing.T) {
	// load config
	cfg, err := GetDefaultConfig()
	require.NoError(t, err)

	t.Run("Value not in NeverInclude list", func(t *testing.T) {
		filtered := cfg.Filtering.FilterSingleIP(net.IP{65, 0, 0, 0})
		require.False(t, filtered, "filter state should match expected value")
	})

	t.Run("IPv4 broadcast", func(t *testing.T) {
		filtered := cfg.Filtering.FilterSingleIP(net.IPv4bcast)
		require.True(t, filtered, "filter state should match expected value")
	})

	t.Run("IPv4 all zeros address", func(t *testing.T) {
		filtered := cfg.Filtering.FilterSingleIP(net.IPv4zero)
		require.True(t, filtered, "filter state should match expected value")
	})

	t.Run("IPv6 unspecified address", func(t *testing.T) {
		filtered := cfg.Filtering.FilterSingleIP(net.IPv6unspecified)
		require.True(t, filtered, "filter state should match expected value")
	})
}

func TestCheckIfInternal(t *testing.T) {
	internalSubnetList := []util.IPNet{
		{IPNet: &net.IPNet{IP: net.IP{11, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
		{IPNet: &net.IPNet{IP: net.IP{120, 0, 0, 0}, Mask: net.IPMask{255, 0, 0, 0}}},
	}

	// load config
	cfg, err := GetDefaultConfig()
	require.NoError(t, err)

	// set internal subnets
	cfg.Filtering.InternalSubnets = internalSubnetList

	// internal ip
	t.Run("Valid Internal IP", func(t *testing.T) {
		checkCases := cfg.Filtering.CheckIfInternal(net.IP{11, 0, 0, 0})
		require.True(t, checkCases, "filter state should match expected value")
	})

	// external ip
	t.Run("Valid External IP", func(t *testing.T) {
		checkCases := cfg.Filtering.CheckIfInternal(net.IP{110, 0, 0, 0})
		require.False(t, checkCases, "filter state should match expected value")
	})

	// unspecified ip
	t.Run("Unspecified IPv6", func(t *testing.T) {
		checkCases := cfg.Filtering.CheckIfInternal(net.IPv6unspecified)
		require.False(t, checkCases, "filter state should match expected value")
	})

	// all zeros ip
	t.Run("All Zeros IPv4", func(t *testing.T) {
		checkCases := cfg.Filtering.CheckIfInternal(net.IPv4zero)
		require.False(t, checkCases, "filter state should match expected value")
	})

	// broadcast ip
	t.Run("Broadcast IP", func(t *testing.T) {
		checkCases := cfg.Filtering.CheckIfInternal(net.IPv4bcast)
		require.False(t, checkCases, "filter state should match expected value")
	})

}
