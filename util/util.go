package util

import (
	"context"
	"crypto/md5" //#nosec
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/github"
	"github.com/google/uuid"
	"github.com/spf13/afero"
)

var (
	privateIPBlocks           []*net.IPNet
	PublicNetworkUUID         = uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	PublicNetworkName         = "Public"
	UnknownPrivateNetworkUUID = uuid.MustParse("ffffffff-ffff-ffff-ffff-fffffffffffe")
	UnknownPrivateNetworkName = "Unknown Private"

	ErrInvalidPath = errors.New("path cannot be empty string")

	ErrFileDoesNotExist = errors.New("file does not exist")
	ErrFileIsEmtpy      = errors.New("file is empty")
	ErrPathIsDir        = errors.New("given path is a directory, not a file")

	ErrDirDoesNotExist = errors.New("directory does not exist")
	ErrDirIsEmpty      = errors.New("directory is empty")
	ErrPathIsNotDir    = errors.New("given path is not a directory")
)

type FixedString struct {
	val  string
	Data [16]byte
}

func init() {
	privateIPs, err := ParseSubnets(
		[]string{
			// "127.0.0.0/8",    // IPv4 Loopback; handled by ip.IsLoopback
			// "::1/128",        // IPv6 Loopback; handled by ip.IsLoopback
			// "169.254.0.0/16", // RFC3927 link-local; handled by ip.IsLinkLocalUnicast()
			// "fe80::/10",      // IPv6 link-local; handled by ip.IsLinkLocalUnicast()
			"10.0.0.0/8",     // RFC1918
			"172.16.0.0/12",  // RFC1918
			"192.168.0.0/16", // RFC1918
			"fc00::/7",       // IPv6 unique local addr
		})

	if err == nil {
		privateIPBlocks = privateIPs
	} else {
		panic(fmt.Sprintf("Error defining private IPs: %v", err.Error()))
	}
}

func NewFixedStringHash(args ...string) (FixedString, error) {
	if len(args) == 0 {
		return FixedString{}, errors.New("no arguments provided")
	}

	joined := strings.Join(args, "")
	if joined == "" {
		return FixedString{}, errors.New("joined string is empty")
	}

	//#nosec
	hash := md5.Sum([]byte(strings.Join(args, "")))

	fs := FixedString{
		Data: hash,
	}
	return fs, nil
}

func NewFixedStringFromHex(h string) (FixedString, error) {
	data, err := hex.DecodeString(h)
	if err != nil {
		return FixedString{}, err
	}
	var fixed [16]byte
	copy(fixed[:], data[:16])
	return FixedString{
		Data: fixed,
	}, nil
}

func ValidFQDN(value string) bool {
	// Regular expression for validating FQDN
	// This pattern requires at least two labels (separated by dots), with each label starting and ending with an alphanumeric character.
	// Labels in between can have hyphens. The last label (TLD) must be at least two characters long, with only letters.
	re := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return re.MatchString(value)
}

func (bin *FixedString) Hex() string {
	return strings.ToUpper(hex.EncodeToString(bin.Data[:]))
}

//  override functions called by database driver

// Returns expected type for writing to the database
func (bin FixedString) MarshalBinary() ([]byte, error) {
	return bin.Data[:], nil
}

// Returns expected type for reading from the database
func (bin *FixedString) UnmarshalBinary(b []byte) error {
	copy(bin.Data[:], b)
	return nil
}

// Returns value of FixedString as a pointer, used when sometimes writing to database
func (bin FixedString) Value() (driver.Value, error) {
	return &bin.val, nil
}

// ContainsIP checks if a collection of subnets contains an IP
func ContainsIP(subnets []*net.IPNet, ip net.IP) bool {
	// cache IPv4 conversion so it not performed every in every Contains call
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	for _, block := range subnets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseSubnets parses the provided subnets into net.IPNet format
func ParseSubnets(subnets []string) ([]*net.IPNet, error) {
	var parsedSubnets []*net.IPNet

	for _, entry := range subnets {
		// Try to parse out CIDR range
		_, block, err := net.ParseCIDR(entry)

		// If there was an error, check if entry was an IP
		if err != nil {
			ipAddr := net.ParseIP(entry)
			if ipAddr == nil {
				return parsedSubnets, fmt.Errorf("error parsing entry: %s", err.Error())
			}

			// Check if it's an IPv4 or IPv6 address and append the appropriate subnet mask
			var subnetMask string
			if ipAddr.To4() != nil {
				subnetMask = "/32"
			} else {
				subnetMask = "/128"
			}

			// Append the subnet mask and parse as a CIDR range
			_, block, err = net.ParseCIDR(entry + subnetMask)

			if err != nil {
				return parsedSubnets, fmt.Errorf("error parsing entry: %s", err.Error())
			}
		}

		// Add CIDR range to the list
		parsedSubnets = append(parsedSubnets, block)
	}
	return parsedSubnets, nil
}

// IPIsPubliclyRoutable checks if an IP address is publicly routable. See privateIPBlocks.
func IPIsPubliclyRoutable(ip net.IP) bool {
	// cache IPv4 conversion so it not performed every in every ip.IsXXX method
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	if ContainsIP(privateIPBlocks, ip) {
		return false
	}
	return true
}

// ParseNetworkID returns the network ID for a given IP address and agent ID
func ParseNetworkID(ip net.IP, agentID string) uuid.UUID {
	if IPIsPubliclyRoutable(ip) {
		return PublicNetworkUUID
	}

	if len(agentID) == 0 {
		return UnknownPrivateNetworkUUID
	}

	networkID, err := uuid.Parse(agentID)
	if err != nil {
		return UnknownPrivateNetworkUUID
	}
	return networkID
}

// ContainsDomain checks if a given host is in a list of domains
func ContainsDomain(domains []string, host string) bool {

	for _, entry := range domains {

		// check for wildcard
		if strings.Contains(entry, "*") {

			// trim asterisk from the wildcard domain
			wildcardDomain := strings.TrimPrefix(entry, "*")

			// This would match a.mydomain.com, b.mydomain.com etc.,
			if strings.HasSuffix(host, wildcardDomain) {
				return true
			}

			// check match of top domain of wildcard
			// if a user added *.mydomain.com, this will include mydomain.com
			// in the filtering
			wildcardDomain = strings.TrimPrefix(wildcardDomain, ".")

			if host == wildcardDomain {
				return true
			}

			// match on exact
		} else if host == entry {
			return true

		}

	}
	return false
}

// EnsureSliceContainsAll ensures that a given slice contains all elements of a mandatory list
func EnsureSliceContainsAll(data []string, mandatory []string) []string {
	// create map to store elements of the given list
	dataMap := make(map[string]bool)
	for _, item := range data {
		dataMap[item] = true
	}

	// check if all elements in the mandatory list exist in the given list
	for _, item := range mandatory {
		if !dataMap[item] {
			data = append(data, item) // append missing element
		}
	}

	return data

}

// UInt32sAreSorted returns true if a slice of uint32 is sorted in ascending order
func UInt32sAreSorted(data []uint32) bool {
	return sort.SliceIsSorted(data, func(i, j int) bool { return data[i] < data[j] })
}

// SortUInt32s sorts a slice of uint32 in ascending order
func SortUInt32s(data []uint32) {
	sort.Slice(data, func(i, j int) bool { return data[i] < data[j] })
}

func ValidateTimestamp(timestamp time.Time) (time.Time, bool) {
	if timestamp.UTC().Unix() > 0 && timestamp.UTC().Unix() < math.MaxInt64 {
		return timestamp, false
	}
	return time.Unix(0, 1), true
}

// GetRelativeFirstSeenTimestamp returns the timestamp to use for first seen calculation/display.
// This is a shortcut for a commonly used if statement
func GetRelativeFirstSeenTimestamp(useCurrentTime bool, maxTimestamp time.Time) time.Time {
	if !useCurrentTime {
		// use the max timestamp to score against
		return maxTimestamp
	}
	return time.Now()
}

// func ParseRelativePath(dir string) (string, error) {
// 	// if path is home, parse and set home dir
// 	if dir[:2] == "~/" {
// 		home, err := os.UserHomeDir()
// 		if err != nil {
// 			return "", err
// 		}
// 		return filepath.Join(home, dir[2:]), nil
// 	}
// 	// otherwise, get the path relative to the current working directory
// 	currentDir, err := os.Getwd()
// 	if err != nil {
// 		return "", err
// 	}
// 	return filepath.Join(currentDir, dir), nil
// }

func ParseRelativePath(dir string) (string, error) {
	// validate parameters
	if dir == "" {
		return "", ErrInvalidPath
	}

	switch {
	// if path is home, parse and set home dir
	case dir[:2] == "~/":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, dir[2:]), nil
	// if the path starts with a dot, get the path relative to the current working directory
	case strings.HasPrefix(dir, "."):
		currentDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(currentDir, dir), nil
	default:
		// otherwise, return the directory as is
		return dir, nil

	}

}

// ValidateDirectory returns whether a directory exists and is empty
func ValidateDirectory(afs afero.Fs, dir string) error {
	// validate path
	exists, isDir, isEmpty, err := validatePath(afs, dir)
	if err != nil {
		return err
	}

	// check if dirctory exists
	if !exists {
		return fmt.Errorf("%w: %s", ErrDirDoesNotExist, dir)
	}

	// check if path is a directory
	if !isDir {
		return fmt.Errorf("%w: %s", ErrPathIsNotDir, dir)
	}

	// check if file is empty
	if isEmpty {
		return fmt.Errorf("%w: %s", ErrDirIsEmpty, dir)
	}

	return nil
}

// Validate File
func ValidateFile(afs afero.Fs, file string) error {
	// validate path
	exists, isDir, isEmpty, err := validatePath(afs, file)
	if err != nil {
		return err
	}

	// check if file exists
	if !exists {
		return fmt.Errorf("%w: %s", ErrFileDoesNotExist, file)
	}

	// check if path is a directory
	if isDir {
		return fmt.Errorf("%w: %s", ErrPathIsDir, file)
	}

	// check if file is empty
	if isEmpty {
		return fmt.Errorf("%w: %s", ErrFileIsEmtpy, file)
	}

	return nil
}

func validatePath(afs afero.Fs, path string) (bool, bool, bool, error) {
	var exists, isDir, isEmpty bool

	// validate parameters
	if afs == nil {
		return exists, isDir, isEmpty, fmt.Errorf("filesystem is nil")
	}
	if path == "" {
		return exists, isDir, isEmpty, ErrInvalidPath
	}

	// check if path exists
	exists, err := afero.Exists(afs, path)
	if err != nil {
		return exists, isDir, isEmpty, err
	}

	if exists {
		// check if path is a directory
		isDir, err = afero.IsDir(afs, path)
		if err != nil {
			return exists, isDir, isEmpty, err
		}

		// check if directory is empty
		isEmpty, err = afero.IsEmpty(afs, path)
		if err != nil {
			return exists, isDir, isEmpty, err
		}
	}

	return exists, isDir, isEmpty, nil
}

// CheckForNewerVersion checks if a newer version of the project is available on the GitHub repository
func CheckForNewerVersion(client *github.Client, currentVersion string) (bool, string, error) {

	// Get the latest release
	latestRelease, _, err := client.Repositories.GetLatestRelease(context.Background(), "activecm", "rita")
	if err != nil {
		return false, "", fmt.Errorf("error fetching latest release: %w", err)
	}

	// Get the latest version from release tag name
	latestVersion := latestRelease.GetTagName()

	// Parse the current and latest versions
	currentSemver, err := semver.ParseTolerant(currentVersion)
	if err != nil {
		return false, "", fmt.Errorf("error parsing current version: %w", err)
	}

	latestSemver, err := semver.ParseTolerant(latestVersion)
	if err != nil {
		return false, "", fmt.Errorf("error parsing latest version: %w", err)
	}

	// Compare the versions
	if latestSemver.GT(currentSemver) {
		return true, latestVersion, nil
	}

	return false, latestVersion, nil
}
