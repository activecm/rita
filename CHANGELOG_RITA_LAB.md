# RITA-Lab 改动总结

> 本文件总结本次在 RITA v5 checkout 中完成的全部 RITA-Lab 相关改动。RITA-Lab 是只读的报告与实验层，不改变 RITA 原生检测算法、原生评分语义或 `threat_mixtape` 表结构。

## 1. 目标与边界

- 在现有 RITA CLI 中内置 `rita lab`，而不是创建平行 CLI。
- 以仓库内已有 Zeek 日志 fixture 作为首版离线、可复现输入。
- 仅消费 RITA 导入和分析后的 ClickHouse 结果，生成资产感知、可解释的二次报告。
- 不抓取宿主机接口、不扫描公网、不联系外部目标、不生成攻击流量。
- 报告期 allowlist 只影响二次报告优先级，不映射到 RITA 的导入期 `never_included_domains`，从而保留可审计证据。

## 2. 核心领域模型

新增 `lab/model.go`，定义并区分：

- `LabConfig`、`Asset`、`Allowlists`、`AllowlistRule`；
- `ScoringConfig`、`ReportingConfig`、`DNSFeatureConfig`；
- `NativeEvidence`、`DNSEvent`、`DNSFeatures`；
- `AssetMatch`、`AllowlistMatch`；
- `AggregateAlert`、`ScoreContribution`、`Report`、`EvaluationResult`。

支持的检测类型：

- `beacon`
- `long_connection`
- `strobe`
- `dns_c2`
- `threat_intel_only`

缺少域名时使用 `ip:<destination>` 作为明确的 IP fallback；缺少来源时保留 `unattributed`，不伪造主机地址。

## 3. 独立实验室配置

新增 `lab/config.go` 和 fixture 配置：

- `lab/fixtures/config/rita-lab.hjson`：离线 RITA 导入配置、内部网段和关闭更新检查；
- `lab/fixtures/config/lab-profile.hjson`：资产、allowlist、评分权重、默认窗口和 DNS 特征开关。

配置读取和校验包括：

- HJSON 解析和配置 SHA-256；
- schema 版本和默认时间窗口；
- 资产 ID、CIDR、重复 CIDR、资产重要性；
- allowlist 模式、原因和分数扣减；
- 五项评分权重之和为 1；
- persistence 阈值有效性。

## 4. 资产与域名关联

新增：

- `lab/assets.go`：使用最长前缀匹配将源 IP 关联到最具体资产；未匹配资产保留为 `unclassified`；
- `lab/allowlist.go`：支持精确域名和 `*.` 通配符，统一小写并移除尾点；
- `lab/normalize.go`：统一域名、时间窗口、目标键和稳定告警 ID。

## 5. ClickHouse 原生证据查询

新增 `lab/query.go`：

- 从 `threat_mixtape` 读取报告范围内每个 hash 的最新基线快照；
- 快照严格关联 `hash`、`import_id`、`last_seen` 和 `analyzed_at`，避免历史结果或 modifier 行重复计入；
- modifier 单独读取并汇总到对应基线证据；
- native final score 对齐 RITA viewer 的原生组成，包括 prevalence、first-seen、missing-host-header、威胁情报数据量和 DNS direct-connection 分量；
- 查询再次施加 `[from,to)` 时间范围；
- DNS 候选域使用 ClickHouse `Array(String)` 参数，并安全转义参数值；
- DNS 域名查询统一处理大小写和尾点。

## 6. DNS C2 证据和安全归因

新增 `lab/dns.go` 和相关聚合逻辑：

- 查询数；
- 唯一编码标签数；
- 平均和最大编码标签长度；
- 以字节为单位计算 Shannon entropy（bits/byte）；
- 每分钟查询频率；
- NXDOMAIN 数量和比例；
- 首次和最后观测时间。

重要语义：RITA 的 DNS C2 结果可能是域级证据且来源为 `::`。RITA-Lab 将其保留为明确的未归因域级 alert；raw DNS 的 `dns.src` 只作为调查上下文，绝不把域级分数复制给该域的每个查询主机，避免错误提升普通查询主机的风险分数。

当没有 DNS 事件、编码标签或有效分母时，相关特征保持不可用，而不是被解释为低风险。

## 7. 时间窗口聚合

新增 `lab/aggregate.go`：

- 使用以下逻辑键聚合：

  ```text
  source_ip + destination_domain + detection_type + time_window
  ```

- 同一个 RITA 原生结果可以展开为多个明确检测类型；
- 保存原生证据、连接计数、DNS 查询计数、首末时间、威胁情报状态、资产和 allowlist 信息；
- 按实验室优先级、窗口、源、目标、检测类型和 ID 进行确定性排序；
- DNS 特征开关关闭时不执行 raw DNS 查询。

## 8. 二次优先级与解释

新增 `lab/scoring.go`。默认使用归一化到 `0..1` 的组件：

```text
pre_allowlist_score =
    0.45 * rita_evidence
  + 0.20 * asset_importance
  + 0.15 * threat_intel
  + 0.10 * persistence
  + 0.10 * rarity

lab_priority_score = 100 * clamp(pre_allowlist_score - allowlist_reduction, 0, 1)
```

每项都输出：

- 原始值；
- 归一化值；
- 配置权重；
- 有符号贡献；
- `applied` 或 `not_available` 状态；
- 可读原因。

未知 prevalence 和未分类资产不会被虚构成正向风险贡献。allowlist 的匹配规则、原因和扣减作为独立的可审计贡献保留。

## 9. 报告输出

新增 `lab/report.go`：

- Markdown：元数据、摘要、原生证据、资产、DNS 特征、allowlist 和评分分解；
- CSV：使用 Go `encoding/csv`，包含结构化字段、allowlist 原因和 JSON `score_breakdown_json`；
- HTML：使用 `html/template`，对域名、owner、allowlist reason 和日志值进行 HTML 转义；
- 所有格式共用同一 `Report` 模型和确定性排序；
- 记录配置 SHA-256 和评分版本；
- 评估指标仅记录实际执行得到的导入计数、聚合告警数和耗时，不虚构准确率、召回率或性能数据。

`lab/run.go` 还提供：

- 报告构建；
- 最低优先级筛选；
- allowlist 告警默认保留、可选择排除；
- Markdown/CSV/HTML 格式解析；
- 输出文件预检查；
- 临时文件写入后原子 rename，避免多格式输出中途失败留下半成品。

## 10. CLI

新增 `cmd/lab.go`，并在 `cmd/cmd.go` 注册 `LabCommand`。

### `rita lab report`

支持：

- `--config`
- `--lab-config`
- `--from` / `--to`
- `--window`
- `--formats`
- `--output-dir`
- `--minimum-score`
- `--exclude-allowlisted`
- `--overwrite`

### `rita lab evaluate`

支持：

- `--logs` 受控日志目录；
- `--rebuild` 显式重建数据库；
- 与 report 相同的范围、窗口、格式、输出和 allowlist 选项；
- 使用既有 `RunImportCmd`，不复制 RITA importer、analysis 或 modifier 流程；
- 执行前校验日志目录。

省略 `--from` 和 `--to` 时复用 RITA viewer 的近期范围辅助函数，该函数会将下界限制在最新数据时间戳前 24 小时，而非宣称覆盖整个历史数据集。

## 11. Fixture、Compose 和 Makefile

新增：

- `lab/fixtures/manifest.hjson`：登记已有 `dnscat2-ja3-strobe-agent`、`valid_tsv` 和 `dns_only` fixture；未执行的指标明确标记为 `not_measured`；
- `docker-compose.lab.yml`：ClickHouse、RITA-Lab runner 和可选离线 Zeek PCAP profile；使用 internal-only network、无端口发布和只读 fixture 挂载；
- `Makefile` 目标：
  - `test-lab`
  - `compose-lab-config`
  - `lab-up`
  - `lab-down`

可选 PCAP profile 仅读取用户提供的本地 PCAP，不绑定宿主网络接口，也不对公网通信。

## 12. 测试与验证

新增测试覆盖：

- 资产最长前缀和未分类资产；
- allowlist 大小写、尾点和通配符；
- DNS 熵、标签长度、NXDOMAIN 和频率；
- 未归因 DNS C2 保留域级证据；
- 时间窗口和稳定告警 ID；
- allowlist 降分但保留告警；
- CSV 特殊字符转义；
- HTML 内容转义；
- 报告格式解析；
- CLI 注册和窗口校验。

在本环境中完成：

```text
go build ./...                         通过
go test ./lab                        通过
go test ./cmd -run '^TestLab'         通过
git diff --check                      通过
```

完整测试套件未能在当前环境完成，原因是：

- 没有 Docker daemon，依赖 Testcontainers 的集成测试无法启动 ClickHouse；
- Docker 命令本身也不可用，因此 Compose 未实际启动；
- 原项目的 GitHub 更新检查测试受到 GitHub API rate limit 影响。

Go 1.22.12 使用的是本地临时工具链 `/tmp/go`，不是系统级安装。

## 13. 变更文件清单

### 修改的既有文件

- `Makefile`
- `README.md`
- `cmd/cmd.go`
- `docs/Configuration.md`

### 新增文件

- `CHANGELOG_RITA_LAB.md`
- `cmd/lab.go`
- `cmd/lab_test.go`
- `docker-compose.lab.yml`
- `docs/RITALab.md`
- `lab/model.go`
- `lab/config.go`
- `lab/normalize.go`
- `lab/assets.go`
- `lab/allowlist.go`
- `lab/dns.go`
- `lab/aggregate.go`
- `lab/scoring.go`
- `lab/query.go`
- `lab/report.go`
- `lab/run.go`
- `lab/evaluate.go`
- `lab/lab_test.go`
- `lab/report_test.go`
- `lab/fixtures/config/rita-lab.hjson`
- `lab/fixtures/config/lab-profile.hjson`
- `lab/fixtures/manifest.hjson`

## 14. 安全声明

本次实现遵守实验室边界：**不要对公网进行扫描或攻击测试。** 所有默认实验路径均为仓库内受控日志回放或用户明确提供的本地离线 PCAP 处理。
