
@set min_ts=0


SELECT IPv6NumToString(src) as src, IPv6NumToString(dst) as dst, fqdn,
    count,
    proxy_count,
    proxy_ips,
    total_bytes,
    total_bytes_formatted,
    subdomains,
    -- arrayDistinct(flatten(port_proto_service)) as port_proto_service,
    port_proto_service,
    beacon_score as beacon_score,
    beacon_threat_score,
    c2_over_dns_score,
    strobe_score,
    total_duration,
    long_conn_score,
    prevalence,
    prevalence_score,
    first_seen_historical,
    first_seen_score,
    threat_intel_score,
    threat_intel_data_size_score,
    missing_host_count,
    missing_host_header_score,
    c2_over_dns_direct_conn_score,
    total_modifier_score,
    toFloat32(base_score + total_modifier_score + prevalence_score + first_seen_score + missing_host_header_score + threat_intel_data_size_score + c2_over_dns_direct_conn_score) as final_score
    -- base_score
    -- total_modifier_score

    -- total_modifier_score

    FROM (
        SELECT hash, src, dst, fqdn,
            groupUniqArrayArray(proxy_ips) as proxy_ips,
            max(proxy_count) as proxy_count,
            max(open_count) as open_count,
            max(count) as count,
            sum(total_bytes) as total_bytes,
            formatReadableSize(total_bytes) as total_bytes_formatted,
            sum(subdomain_count) as subdomains,
            flatten(groupArray(port_proto_service)) as port_proto_service,
            toFloat32(sum(beacon_score)) as beacon_score,
            toFloat32(sum(beacon_threat_score)) as beacon_threat_score,
            toFloat32(sum(c2_over_dns_score)) as c2_over_dns_score,
            toFloat32(sum(strobe_score)) as strobe_score,
            sum(total_duration) as  total_duration,
            toFloat32(sum(long_conn_score)) as  long_conn_score,
            toFloat32(sum(prevalence)) as prevalence,
            toFloat32(sum(prevalence_score)) as prevalence_score,
            max(first_seen_historical) as first_seen_historical,
            toFloat32(sum(first_seen_score)) as first_seen_score,
            toFloat32(sum(threat_intel_score)) as threat_intel_score,
            toFloat32(sum(threat_intel_data_size_score)) as threat_intel_data_size_score,
            sum(missing_host_count) as missing_host_count,
            toFloat32(sum(missing_host_header_score)) as missing_host_header_score,
            toFloat32(sum(c2_over_dns_direct_conn_score)) as c2_over_dns_direct_conn_score,
            toFloat32(sum(modifier_score)) as total_modifier_score,
            greatest(beacon_threat_score, long_conn_score, strobe_score, c2_over_dns_score, threat_intel_score) as base_score

        FROM threat_mixtape t
        INNER JOIN (SELECT hash, argMax(import_id, last_seen) as import_id, max(last_seen) as max_last_seen FROM threat_mixtape GROUP BY hash) x
        ON t.hash = x.hash and t.last_seen = x.max_last_seen and t.import_id = x.import_id
        WHERE toStartOfHour(t.last_seen) >= toStartOfHour(fromUnixTimestamp(:min_ts))
        GROUP BY hash, src, dst, fqdn
    )
    ORDER BY final_score DESC, strobe_score DESC, beacon_score DESC