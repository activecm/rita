package lab

import "net"

func MatchAsset(assets []Asset, ip net.IP) AssetMatch {
	if ip == nil {
		return AssetMatch{Asset: unclassifiedAsset()}
	}

	best := -1
	var match Asset
	for _, asset := range assets {
		if asset.network != nil && asset.network.Contains(ip.To16()) && asset.prefix > best {
			best = asset.prefix
			match = asset
		}
	}
	if best < 0 {
		return AssetMatch{Asset: unclassifiedAsset()}
	}
	return AssetMatch{Asset: match, Matched: true}
}

func unclassifiedAsset() Asset {
	return Asset{
		AssetID:     "unclassified",
		AssetType:   "unclassified",
		Owner:       "unclassified",
		NetworkZone: "unclassified",
	}
}
