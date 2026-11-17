# RITA-Lab: asset-aware, explainable laboratory reporting

RITA-Lab is a **read-only reporting layer** built into this RITA checkout. It consumes the RITA ClickHouse results after `rita import` has completed. It does not modify RITA detection algorithms, RITA's original score semantics, or the `threat_mixtape` schema.

```text
Zeek conn.log / dns.log / http.log / ssl.log
  -> rita import
  -> ClickHouse + RITA native analysis
  -> rita lab report
  -> asset association, report-period allowlist, aggregation, priority explanation
  -> Markdown / CSV / HTML
```

## Safety and reproducibility boundary

The provided lab workflow replays repository-owned Zeek log fixtures only. It does not capture host interfaces, scan systems, contact external targets, or generate attack traffic. The optional Compose `pcap` profile processes a locally supplied PCAP offline and has no host-network attachment.

The default test inputs are listed in [`lab/fixtures/manifest.hjson`](../lab/fixtures/manifest.hjson). They are controlled RITA test fixtures, not a statement about universal detection coverage or performance.

## Configure RITA and RITA-Lab separately

RITA's primary HJSON controls **import-time filtering** and must contain the lab's internal ranges. The sample is [`lab/fixtures/config/rita-lab.hjson`](../lab/fixtures/config/rita-lab.hjson).

The separate laboratory profile, [`lab/fixtures/config/lab-profile.hjson`](../lab/fixtures/config/lab-profile.hjson), adds:

- assets (`cidr`, `asset_id`, `asset_type`, `owner`, `importance`, `network_zone`);
- report-period domain allowlist rules;
- secondary-priority weights;
- default aggregation window.

Asset matching uses the most-specific matching CIDR. An untagged source is retained as `unclassified` rather than discarded.

### Filtering is not an allowlist

RITA `filtering.never_included_domains` excludes records **during import**, so later reporting cannot retain their evidence. RITA-Lab's `allowlists.domains` is intentionally different: it retains the alert, annotates the matching pattern/reason, and applies a visible score reduction. This enables auditing the reason for a lower priority.

Patterns can be exact (`updates.example.test`) or wildcard (`*.updates.example.test`). Domain matching is lower-cased and ignores a trailing dot.

## Generate a report

First run a normal import, then choose an explicit report range:

```bash
rita import --config lab/fixtures/config/rita-lab.hjson \
  --database lab_traffic --logs test_data/dnscat2-ja3-strobe-agent --rebuild

rita lab report lab_traffic \
  --config lab/fixtures/config/rita-lab.hjson \
  --lab-config lab/fixtures/config/lab-profile.hjson \
  --from 2024-01-01T00:00:00Z --to 2024-01-02T00:00:00Z \
  --window 30m --formats markdown,csv,html \
  --output-dir ./rita-lab-output
```

Allowlisted alerts are included by default so the score reduction remains auditable. Add `--exclude-allowlisted` only when an intentionally reduced output view is required.

If `--from` and `--to` are omitted together, RITA-Lab uses the same recent-range helper as the RITA viewer (the helper caps the lower bound at 24 hours before the latest dataset timestamp). Reports are generated for the UTC half-open interval `[from, to)`. Existing output files are never replaced unless `--overwrite` is passed.

Use `rita lab evaluate` only for controlled log fixtures. Its `--rebuild` flag is explicit because it destroys and recreates the named database:

```bash
rita lab evaluate lab_traffic \
  --config lab/fixtures/config/rita-lab.hjson \
  --lab-config lab/fixtures/config/lab-profile.hjson \
  --logs test_data/dnscat2-ja3-strobe-agent \
  --rebuild --output-dir ./rita-lab-output --overwrite
```

## Aggregation and evidence

An alert key is:

```text
source_ip + destination_domain + detection_type + time_window
```

Detection types are `beacon`, `long_connection`, `strobe`, `dns_c2`, and `threat_intel_only`. A native RITA finding can contribute to multiple typed alerts. Missing FQDNs are transparently represented as `ip:<destination-ip>`; no domain is fabricated.

RITA's DNS domain-level result may have `::` as its source. RITA-Lab retains that native result as explicitly unattributed domain evidence; raw `dns.src` records are available as investigation context but are not used to copy the domain-global C2 score onto every querying host. A missing or partial raw match therefore cannot be mistaken for a host-level RITA finding.

The report additionally shows reproducible DNS investigation features for each source/domain/window:

- query count and unique encoded labels;
- average and maximum encoded-label length;
- Shannon entropy over encoded-label bytes, in bits per byte;
- queries per minute;
- NXDOMAIN count and ratio.

These features are clues for investigation, not independent proof of DNS tunneling.

## Secondary laboratory priority

Native RITA evidence remains separate from `lab_priority_score`. The default profile uses normalised `0..1` components:

```text
pre_allowlist_score =
    0.45 * rita_evidence
  + 0.20 * asset_importance
  + 0.15 * threat_intel
  + 0.10 * persistence
  + 0.10 * rarity

lab_priority_score = 100 * clamp(pre_allowlist_score - allowlist_reduction, 0, 1)
```

Each output alert includes the raw value, normalised value, configured weight, signed contribution, status, and explanation for every component. Unknown prevalence and unclassified assets are marked `not_available`; they do not receive an invented positive or negative contribution.

## Report content

All formats derive from the same report model:

- **Markdown**: metadata, summary, native evidence, assets, DNS evidence, allowlist decision, and score table;
- **CSV**: structured columns including JSON score breakdown, written with Go's `encoding/csv`;
- **HTML**: static `html/template` output, with all log/configuration values escaped.

Generated reports record their configuration SHA-256 and scoring version. Evaluation mode records only direct runtime facts (imported record count, aggregated alerts, report duration). It does **not** claim parsing success, accuracy, false-positive rate, recall, or query percentiles unless those metrics are obtained from a completed, labelled evaluation implementation.

## Docker Compose replay

Validate and run the isolated replay:

```bash
docker compose -f docker-compose.lab.yml config
docker compose -f docker-compose.lab.yml up --build --abort-on-container-exit
```

Reports are stored in the `lab-reports` Compose volume. The stack has an internal-only network and no published ports. To use the optional offline PCAP stage, set `LAB_PCAP_DIR` to a local directory containing `input.pcap` and invoke `--profile pcap`; inspect and approve the PCAP before running it.
