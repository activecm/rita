package config

import (
	"github.com/activecm/rita/v5/util"

	"net"
)

// Filter provides methods for excluding IP addresses, domains, and determining proxy servers during the import step
// based on the user configuration
type Filter struct {
	InternalSubnetsJSON []string `json:"internal_subnets"`
	InternalSubnets     []*net.IPNet

	AlwaysIncludedSubnetsJSON []string `json:"always_included_subnets"`
	AlwaysIncludedSubnets     []*net.IPNet

	NeverIncludedSubnetsJSON []string `json:"never_included_subnets"`
	NeverIncludedSubnets     []*net.IPNet

	AlwaysIncludedDomains []string `json:"always_included_domains"`
	NeverIncludedDomains  []string `json:"never_included_domains"`

	FilterExternalToInternal bool `json:"filter_external_to_internal"`
}

func GetMandatoryNeverIncludeSubnets() []string {
	// s2 := make([]string, len(mandatoryNeverIncludeSubnets))

	// _ = copy(s2, mandatoryNeverIncludeSubnets) // s2 is now an independent copy of s
	// return s2
	return []string{
		"0.0.0.0/32",         // current host
		"127.0.0.0/8",        // loopback
		"169.254.0.0/16",     // link local
		"224.0.0.0/4",        // multicast
		"255.255.255.255/32", // limited broadcast
		"::1/128",            // loopback
		"::",                 // unspecified IPv6
		"fe80::/10",          // link local
		"ff00::/8",           // multicast
		"ff02::2",            // local multicast
	}
}

func (cfg *Config) ParseFilter() error {
	// parse internal subnets
	internalSubnetList, err := util.ParseSubnets(cfg.Filter.InternalSubnetsJSON)
	if err != nil {
		return err
	}
	cfg.Filter.InternalSubnets = internalSubnetList

	// parse always included subnets
	alwaysIncludedSubnetList, err := util.ParseSubnets(cfg.Filter.AlwaysIncludedSubnetsJSON)
	if err != nil {
		return err
	}
	cfg.Filter.AlwaysIncludedSubnets = alwaysIncludedSubnetList

	// validate that all mandatory never include subnets are present
	cfg.Filter.NeverIncludedSubnetsJSON = util.EnsureSliceContainsAll(cfg.Filter.NeverIncludedSubnetsJSON, GetMandatoryNeverIncludeSubnets())

	// parse never included subnets
	neverIncludedSubnetList, err := util.ParseSubnets(cfg.Filter.NeverIncludedSubnetsJSON)
	if err != nil {
		return err
	}
	cfg.Filter.NeverIncludedSubnets = neverIncludedSubnetList

	return nil
}

// FilterSNIPair returns true if a SNI connection pair is filtered/excluded.
func (fs *Filter) FilterSNIPair(srcIP net.IP) bool {
	// check if src is internal
	isSrcInternal := util.ContainsIP(fs.InternalSubnets, srcIP)

	// filter out connections that have external source IPs
	return !isSrcInternal
}

// FilterConnPairForHTTP returns true if a connection pair is filtered
// based on criteria that should apply regardless of whether or not there is a proxy connection for it
func (fs *Filter) FilterConnPairForHTTP(srcIP net.IP, dstIP net.IP) bool {

	// check if on always included list
	isSrcIncluded := util.ContainsIP(fs.AlwaysIncludedSubnets, srcIP)
	isDstIncluded := util.ContainsIP(fs.AlwaysIncludedSubnets, dstIP)

	// check if on never included list
	isSrcExcluded := util.ContainsIP(fs.NeverIncludedSubnets, srcIP)
	isDstExcluded := util.ContainsIP(fs.NeverIncludedSubnets, dstIP)

	// if either IP is on the AlwaysInclude list, filter does not apply
	if isSrcIncluded || isDstIncluded {
		return false
	}

	// if either IP is on the NeverInclude list, filter applies
	if isSrcExcluded || isDstExcluded {
		return true
	}

	// check if src and dst are internal
	isSrcInternal := util.ContainsIP(fs.InternalSubnets, srcIP)
	isDstInternal := util.ContainsIP(fs.InternalSubnets, dstIP)

	// if both addresses are external, filter applies
	if (!isSrcInternal) && (!isDstInternal) {
		return true
	}

	return false
}

// filterConnPair returns true if a connection pair is filtered/excluded.
// This is determined by the following rules, in order:
//  1. Not filtered if either IP is on the AlwaysInclude list
//  2. Filtered if either IP is on the NeverInclude list
//  3. Not filtered if InternalSubnets is empty
//  4. Filtered if both IPs are internal or both are external
//  5. Filtered if the source IP is external and the destination IP is internal and FilterExternalToInternal has been set in the configuration file
//  6. Not filtered in all other cases
func (fs *Filter) FilterConnPair(srcIP net.IP, dstIP net.IP) bool {

	// check if on always included list
	isSrcIncluded := util.ContainsIP(fs.AlwaysIncludedSubnets, srcIP)
	isDstIncluded := util.ContainsIP(fs.AlwaysIncludedSubnets, dstIP)

	// check if on never included list
	isSrcExcluded := util.ContainsIP(fs.NeverIncludedSubnets, srcIP)
	isDstExcluded := util.ContainsIP(fs.NeverIncludedSubnets, dstIP)

	// if either IP is on the AlwaysInclude list, filter does not apply
	if isSrcIncluded || isDstIncluded {
		return false
	}

	// if either IP is on the NeverInclude list, filter applies
	if isSrcExcluded || isDstExcluded {
		return true
	}

	// if no internal subnets are defined, return false
	// note: this should not happen since we validate the config to ensure
	// that internal subnets is not empty
	if len(fs.InternalSubnets) == 0 {
		return false
	}

	// check if src and dst are internal
	isSrcInternal := util.ContainsIP(fs.InternalSubnets, srcIP)
	isDstInternal := util.ContainsIP(fs.InternalSubnets, dstIP)

	// if both addresses are internal, filter applies
	if isSrcInternal && isDstInternal {
		return true
	}

	// if both addresses are external, filter applies
	if (!isSrcInternal) && (!isDstInternal) {
		return true
	}

	// filter external to internal traffic if the user has specified to do so
	if fs.FilterExternalToInternal && (!isSrcInternal) && isDstInternal {
		return true
	}

	// default to not filter the connection pair
	return false
}

// filterDNSPair returns true if a DNS connection pair is filtered/excluded.
// DNS is treated specially since we need to capture internal -> internal DNS traffic
// in order to detect C2 over DNS with an internal resolver.
// This is determined by the following rules, in order:
//  1. Not filtered if either IP is on the AlwaysInclude list
//  2. Filtered if either IP is on the NeverInclude list
//  3. Not filtered if InternalSubnets is empty
//  4. Filtered if both IPs are external (this is different from filterConnPair which filters internal to internal connections)
//  5. Filtered if the source IP is external and the destination IP is internal and FilterExternalToInternal has been set in the configuration file
//  6. Not filtered in all other cases
func (fs *Filter) FilterDNSPair(srcIP net.IP, dstIP net.IP) bool {
	// check if on always included list
	isSrcIncluded := util.ContainsIP(fs.AlwaysIncludedSubnets, srcIP)
	isDstIncluded := util.ContainsIP(fs.AlwaysIncludedSubnets, dstIP)

	// check if on never included list
	isSrcExcluded := util.ContainsIP(fs.NeverIncludedSubnets, srcIP)
	isDstExcluded := util.ContainsIP(fs.NeverIncludedSubnets, dstIP)

	// if either IP is on the AlwaysInclude list, filter does not apply
	if isSrcIncluded || isDstIncluded {
		return false
	}

	// if either IP is on the NeverInclude list, filter applies
	if isSrcExcluded || isDstExcluded {
		return true
	}

	// if no internal subnets are defined, filter does not apply
	// this is was the default behavior before InternalSubnets was added
	if len(fs.InternalSubnets) == 0 {
		return false
	}

	// check if src and dst are internal
	isSrcInternal := util.ContainsIP(fs.InternalSubnets, srcIP)
	isDstInternal := util.ContainsIP(fs.InternalSubnets, dstIP)

	// if both addresses are external, filter applies
	if (!isSrcInternal) && (!isDstInternal) {
		return true
	}

	// filter external to internal traffic if the user has specified to do so
	if fs.FilterExternalToInternal && (!isSrcInternal) && isDstInternal {
		return true
	}

	// default to not filter the connection pair
	return false
}

// filterSingleIP returns true if an IP is filtered/excluded.
// This is determined by the following rules, in order:
//  1. Not filtered IP is on the AlwaysInclude list
//  2. Filtered IP is on the NeverInclude list
//  3. Not filtered in all other cases
func (fs *Filter) FilterSingleIP(ip net.IP) bool {

	// check if on always included list
	if util.ContainsIP(fs.AlwaysIncludedSubnets, ip) {
		return false
	}

	// check if on never included list
	if util.ContainsIP(fs.NeverIncludedSubnets, ip) {
		return true
	}

	// default to not filter the IP address
	return false
}

// FilterDomain returns true if a domain is filtered/excluded.
// This is determined by the following rules, in order:
//  1. Not filtered if domain is on the AlwaysInclude list
//  2. Filtered if domain is on the NeverInclude list
//  3. Not filtered in all other cases
func (fs *Filter) FilterDomain(domain string) bool {
	// check if on always included list
	isDomainIncluded := util.ContainsDomain(fs.AlwaysIncludedDomains, domain)

	// check if on never included list
	isDomainExcluded := util.ContainsDomain(fs.NeverIncludedDomains, domain)

	// if either IP is on the AlwaysInclude list, filter does not apply
	if isDomainIncluded {
		return false
	}

	// if either IP is on the NeverInclude list, filter applies
	if isDomainExcluded {
		return true
	}

	// default to not filter the connection pair
	return false
}

func (fs *Filter) CheckIfInternal(host net.IP) bool {
	return util.ContainsIP(fs.InternalSubnets, host)
}
