package lab

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/activecm/rita/v5/util"
	"github.com/hjson/hjson-go/v4"
)

var (
	ErrInvalidSchemaVersion = errors.New("lab schema_version is required")
	ErrInvalidAsset         = errors.New("invalid lab asset")
	ErrInvalidAllowlist     = errors.New("invalid lab allowlist rule")
	ErrInvalidScoring       = errors.New("invalid lab scoring configuration")
	ErrInvalidWindow        = errors.New("invalid lab reporting window")
)

func ReadConfig(path string) (*LabConfig, string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}

	var cfg LabConfig
	if err := hjson.Unmarshal(contents, &cfg); err != nil {
		return nil, "", fmt.Errorf("parse lab config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, "", err
	}

	digest := sha256.Sum256(contents)
	return &cfg, fmt.Sprintf("%x", digest), nil
}

func (cfg *LabConfig) Validate() error {
	if strings.TrimSpace(cfg.SchemaVersion) == "" {
		return ErrInvalidSchemaVersion
	}
	window, err := time.ParseDuration(cfg.Reporting.DefaultWindow)
	if err != nil || window <= 0 {
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidWindow, err)
		}
		return ErrInvalidWindow
	}

	assetIDs := make(map[string]struct{}, len(cfg.Assets))
	cidrs := make(map[string]struct{}, len(cfg.Assets))
	for i := range cfg.Assets {
		asset := &cfg.Assets[i]
		if strings.TrimSpace(asset.AssetID) == "" || strings.TrimSpace(asset.AssetType) == "" || strings.TrimSpace(asset.Owner) == "" || strings.TrimSpace(asset.NetworkZone) == "" || asset.Importance < 0 || asset.Importance > 100 {
			return fmt.Errorf("%w at index %d", ErrInvalidAsset, i)
		}
		if _, ok := assetIDs[asset.AssetID]; ok {
			return fmt.Errorf("%w: duplicate asset_id %q", ErrInvalidAsset, asset.AssetID)
		}
		subnet, err := util.ParseSubnet(asset.CIDR)
		if err != nil {
			return fmt.Errorf("%w: asset %q CIDR: %w", ErrInvalidAsset, asset.AssetID, err)
		}
		canonicalCIDR := subnet.ToString()
		if _, ok := cidrs[canonicalCIDR]; ok {
			return fmt.Errorf("%w: duplicate CIDR %q", ErrInvalidAsset, asset.CIDR)
		}
		ones, _ := subnet.Mask.Size()
		asset.network = subnet.IPNet
		asset.prefix = ones
		assetIDs[asset.AssetID] = struct{}{}
		cidrs[canonicalCIDR] = struct{}{}
	}

	for i, rule := range cfg.Allowlists.Domains {
		if strings.TrimSpace(rule.Pattern) == "" || strings.TrimSpace(rule.Reason) == "" || rule.ScoreReduction < 0 || rule.ScoreReduction > 1 {
			return fmt.Errorf("%w at index %d", ErrInvalidAllowlist, i)
		}
	}

	s := cfg.Scoring
	weights := []float64{s.RITAEvidenceWeight, s.AssetImportanceWeight, s.ThreatIntelWeight, s.PersistenceWeight, s.RarityWeight}
	var total float64
	for _, weight := range weights {
		if weight < 0 || weight > 1 {
			return ErrInvalidScoring
		}
		total += weight
	}
	if math.Abs(total-1) > 0.000001 || s.PersistenceCountTarget == 0 || s.PersistenceDurationMins <= 0 {
		return ErrInvalidScoring
	}
	return nil
}
