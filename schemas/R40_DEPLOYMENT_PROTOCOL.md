# R40 — 统一模型的端到端 CI/CD 部署实验 协议

**协议版本** `r40-deployment-protocol-1` ·
**与 `h2-real-protocol-6` 并列, 不取代它, 也不重开它的任何结论** ·
**输入** `schemas/R40_INPUT_DEPOSIT.json` 所列七个冻结文件 ·
**工作流** `tools/h2_real_pipeline/.github/workflows/deployment.yml` ·
**shard 脚本** `tools/h2_real_pipeline/scripts/online_query.py` ·
**门** `Test_r40_deployment.py` · **冻结记录** `schemas/R40_DEPLOYMENT_FREEZE.json`

<!-- terminology:start -->
> **术语与措辞**
>
> **R37 = 真实 GitHub Actions 验证**(已封板, 普查 run `32143022565`, 2026-08-18)。
> **R40 = 部署实验**(本文件)。**R40 不是 R37 改名**, 也不是 R37 重跑 ——
> 它问的是**另一个问题**, 有**另一个终点**。
>
> **本协议写在结果之前, 但不称 "pre-registered"** —— 写它之前已经做过可行性实测
> (重建耗时、峰值内存、链路字节同一性), 那些测量的存在意味着这个词用在这里不准确。
> 称 **"在正式结果运行前冻结的分析协议"**。
>
> **不得出现的说法**: 「统一模型比单一来源更快 / 缩短了修复时间」——
> 本实验不测量任何人的修复速度, 见 §2 与 §8。
<!-- terminology:end -->

---

## 1. 这个实验是什么 —— 一句白话

**把完整的统一模型放到一台干净的 CI 机器上重新造出来, 装进流水线里当场使用, 看它能不能用、
用出来的答案对不对。**

论文要写「完整统一模型被部署并在 CI/CD 中在线运行」。在 R40 之前, 这句话**说不出口**:
R37 的 Unified 臂读的是一份**事先在本地算好、随仓库带上去的清单**
(`H2_UNIFIED_RECOMMENDATIONS.json`), 模型本身**从未上过 runner**。
R40 让模型上 runner, 并让每一条建议都是**在 runner 上算出来的**。

---

## 2. 注册的主要终点(**只有这两条**)

| # | 终点 | 判定 |
|---|---|---|
| **E1** | **可运行性** —— 模型能在干净 runner 上从哈希校验过的冻结输入重建、加载、被查询 | 11 个 `.jsonl.gz` 段与封板模型**逐字节相同**, 且 `dataset_metadata.json` 的 `section_sha256` / `inputs` / `counts` 三块相同 |
| **E2** | **决策保真** —— 线上算出的推荐与冻结派生**逐字节相同** | `h2_query_ledger.json` / `h2_scores.json` / `h2_cicd_decisions.json` / `H2_UNIFIED_RECOMMENDATIONS.json` 四者的 `--check` 全部通过 |

**不是终点、不作结论报告的**:安装成功率、扫描结果、重扫后的暴露状态、
任何 arm 之间的比较、任何 readiness 判断。**这些照做、照归档, 但见 §5。**

> **为什么 `dataset_metadata.json` 不整份比对**:它含 `generated_at_utc`,
> 每次重建必然不同。**实测确认这是唯一不同的键。** 拿整份比会因为一个时间戳而失败,
> 而「把时间戳删掉让它通过」就是为了让检查通过去改被检查的东西。故**按块比对, 并写明哪一块除外**。

---

## 3. 「在线运行」的定义(**逐字进论文**)

> 模型**在 CI runner 执行期间**, 从**哈希校验过的冻结输入**重新构建、载入内存并被查询;
> 流水线每一条修复建议都由**该次载入的模型**在**该次运行中**算出。

**它证明**:可部署性; 在干净机器上的构建可复现性; 决策链不依赖任何本地状态。

**它不证明**:时效性; 也不证明「若改为查询**当下**的 NVD/GHSA/OSV 会得到同样答案」。

**输入必须保持冻结, 不得临时抓取最新数据** —— 否则研究总体就变了,
得到的也不再是同一项研究的结果。

---

## 4. 什么在哪里跑

### 4.1 `build-model`(一次)

1. 按 `R40_INPUT_DEPOSIT.json` 下载七个文件, **逐个校验 sha256, 不符即中止**;
2. `python build_unified_v3.py --input-dir <下载目录> --out-dir output/unified_model_v3`
   —— **冻结代码原样运行, 不带任何 `--mapping` 覆盖**;
3. 段级字节比对(E1);
4. 上传模型(**40 MB**)与七个输入的校验记录为 artifact。

### 4.2 `census`(32 shard, 扇出)

**每个 shard 自己跑完整条链, 而不是接收算好的结果。**

1. 取回模型 artifact, 放在 `output/unified_model_v3/`;
2. **加载模型**并**原样**依次运行
   `build_h2_query_ledger.py` → `score_h2.py` → `derive_h2_cicd.py` →
   `build_h2_unified_recommendations.py`, **每一步 `--check`**(E2);
3. `online_query.py` 为本 shard 的每个环境写一条**在线查询记录**:
   `entity_id` · 命中的 `record_ref` · `fix_pointer` / `range_pointer` ·
   `declares_ranges` / `ranges_containing_installed` · 每源声明的 branch fix ·
   适用版本分支 · **选择理由**;
4. 之后才执行 `run_environment.py`:安装 → 扫描 → 修复 → 重扫;
5. 归档(§7)。

> **为什么每个 shard 都重跑整条链, 而不是由 build job 算一次发下去。**
>
> 决策里的冲突检验是**包级、跨语料**的:某臂对某个包"能不能有一个版本同时清掉它声明过的
> 全部修复"要看**整个语料**里该包的所有查询。**只拿到自己那批环境的 shard 算不出这个** ——
> 硬算就会因为看不全而**悄悄少掉判据**。
>
> 但 shard 手里有**完整模型**, 而整条链**实测只要约 42 秒**(账本 5.3 / 打分 24.7 /
> 决策 11.7 / 清单 0.1), 相对每 shard 安装数十个 npm 包可以忽略。
> **所以让它跑全量, 既字面满足"运行时加载并查询", 又不必新写任何决策代码。**
>
> **这一点是硬要求, 不是实现偏好**: R37b-P0 记着, 流水线曾经在运行时**自己重算** Unified 臂,
> 绕过了可解析 / 可安装 / 可追溯 / 唯一性 / 冲突检验全部判据 ——
> **27 个环境**模型本无有效推荐而那个合并硬给出了版本, **另 6 个**给到有效集之外。
> **R40 不得引入任何新的决策实现。** 门 `Test_r40_deployment.py` 对此设有故障检验。

### 4.3 冻结清单的新地位

`schemas/H2_UNIFIED_RECOMMENDATIONS.json` 在 R40 中**只作预期输出对照(oracle)**,
**不再作为 Unified 臂的输入**。shard 用的是它**自己刚算出来的**那一份。

---

## 5. 与已封板普查的不可比性(**在跑之前声明**)

**R40 的安装 / 扫描 / 重扫结果, 与 R37 普查不可比。** 理由是机制性的, 不是态度问题:

1. `pinned_tools.json` 钉住了 **osv-scanner 二进制**, **钉不住它的漏洞数据库** ——
   osv-scanner v2 也不报告数据库时间戳, 扫描时刻是唯一记录;
2. `npm install` 向**当下的** registry 解析, 而普查跑于 **2026-08-18**;
3. 因此两次运行之间的差异**会来自 registry 与扫描库的移动**, 而不是来自模型。

**所以**:

- R40 **不重开** `h2_supported`。它在 `h2_results.json` 中仍为 `false`, 哈希不得变动;
- R40 的 readiness 类结果**不得**与 R37 的并排呈现为同一量的两次测量;
- 若日后有人要做那个比较, 需要**另一个**在共同快照下冻结的设计, 不是 R40。

---

## 6. 不得触碰的封板层

| 对象 | 约束 |
|---|---|
| `h2_results.json` / `h2_cicd_decisions.json` / `h2_real_run.json` | 哈希不得变动 |
| `H2_REAL_PIPELINE_FREEZE.json` | **不得复用、不得修改** —— 它钉的是普查的输入(含 `unified_manifest` 哈希)。R40 另起 `R40_DEPLOYMENT_FREEZE.json` |
| `tools/h2_real_pipeline/.github/workflows/census.yml` | 不得修改 —— 那是普查真正跑过的那一份 |
| `run_environment.py` 的判定逻辑 | 不得修改 |
| 冻结代码 `build_unified_v3.py` / `identity_extract.py` / `build_identity_v2.py` / `collect_h1.py` | 只**运行**, 不修改 |
| `output/unified_model_v*/` | 本地不得覆盖(runner 上是空目录, 不存在覆盖) |
| `temporal_v3_results.json` / `cwe_tree_v3_results.json` | 已封板, 哈希不得变动 |

---

## 7. 归档要求

每个 shard 必须交回, 缺一即判该 shard 失败:

- 模型的 11 段 sha256 与 `dataset_metadata` 三块;
- 七个输入的下载校验记录(期望值、实得值);
- `online_query` 记录(§4.2 第 3 步的全部字段);
- 四步 `--check` 的结果;
- 扫描器**原始 stdout**(`raw_sha256` 必须能被复核, 沿用 R37 做法);
- 工具版本、runner 镜像、run id / attempt / sha / ref。

> **artifact 会在 90 天后过期。** 论文依赖的任何东西必须在过期前拷出并归档 ——
> 这是保留期, 不是永久发表。R37 已经在这上面吃过一次亏。

---

## 8. 事先声明的局限

1. **指针可解析性不在线上重建。** `npm_range_h2.py --self-test` 要把每个发出的指针
   对回它声称指向的原始窗口记录, 需要三个 `*_window_raw.jsonl.gz` 共 **669.5 MB**,
   **不在沉积清单内**。R40 **继承**离线套件对这一点的结论, 不在线上重新确立;
2. **E1 的"逐字节相同"不含 `generated_at_utc`**(§2 注);
3. **32 个 shard 的链路结果彼此独立但不互相校验** —— 它们各自与**同一份**冻结产物比对,
   所以是 32 次对同一 oracle 的确认, 不是 32 次互校;
4. **本实验不测量任何人的修复速度**, 也不支持任何"更快"的表述;
5. **模型是被重建的, 不是被下载的成品**。若日后改为分发成品模型, E1 的含义随之改变,
   届时必须改协议版本, 而不是沿用本文件。

---

## 9. 公开仓库怎么装配

R37 的 kit 把 `tools/h2_real_pipeline/` **整个拷到公开仓库根目录**;R40 还需要论文仓库根部的
链路脚本与 `schemas/`。**权威清单是机器可读的**:
`R40_DEPLOYMENT_FREEZE.json` 的 `kit_layout_thesis_to_public_repo`
(论文路径 → 公开仓库路径), 共 **31 个文件**。

```bash
# 在公开仓库里
cp -a <thesis>/tools/h2_real_pipeline/. .          # scripts/ tests/ .github/ pinned_tools.json
mkdir -p schemas
python - <<'PY'   # 按 kit_layout 逐个拷, 不手抄
import json, shutil, pathlib
kit = json.load(open('<thesis>/schemas/R40_DEPLOYMENT_FREEZE.json'))
for src, dst in kit['kit_layout_thesis_to_public_repo'].items():
    p = pathlib.Path(dst); p.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(f'<thesis>/{src}', p)
PY
```

> **不要手抄这份清单。** 它写到 31 个文件的过程中错过两次:
> `semver_h2.py` 与 `schemas/H2_RANGE_REQUESTS.json` 是**经由 `npm_range_h2` 间接**到达的,
> 而 `Test_h2_cicd.py` 是被 `derive_h2_cicd.py` 读去做自哈希的。
> **缺一个文件, 要到 runner 上跑了二十分钟才发现。**

**不进公开仓库的**(见 `not_in_kit`):`census.yml`(封板普查跑的那一份)、
`output/unified_model_v1/`(只被 `v1_comparison()` 读, 不在重建路径上)、
三个 `*_window_raw.jsonl.gz`、`H2_R36_PREDICTION_SIDECAR.json`。

---

## 10. 输入的沉积与核验(**前置条件已满足**)

**DOI**: `10.5281/zenodo.22234503` · 记录页 <https://doi.org/10.5281/zenodo.22234503> ·
open access, CC-BY-4.0 · **七个文件全部在内, 无多余文件**。

**下载模板**(`url_template`, 带 `{name}` 占位):
`https://zenodo.org/api/records/22234503/files/{name}/content`

> **为什么是模板而不是"基址 + 文件名"**:Zenodo 的 API 形式把文件名放在**中间**
> (`.../files/{name}/content`)。三种形式我都实际取过并与钉住的 sha256 比对过,
> 三种都对;但**假设"能直接拼接"的写法会在换一个宿主时到 runner 上才炸**, 故存成模板。

**核验(`verify_r40_deposit.py`, 可重跑)**:
`--full` 把七个文件**全部下载并逐字节哈希**, 与**上传发生之前**就已提交的 sha256 比对。
结果写进 `R40_INPUT_DEPOSIT.json` 的 `deposit.verification`。
**门 `deposit_located_and_verified` 要求它必须是 `mode: full` 且通过** ——
把可达性探测记成"已核验"会被当场判错。

> **联网的边界**:项目规则是**构建与派生不得联网**。取一份本地已冻结文件的外部副本
> **两者都不是** —— 没有任何新观测进入研究, 每个字节都拿去和一个既有哈希比对,
> 不符即失败, 永不产生新值。

**仍需人工的一步**:按 §9 装配公开仓库并触发工作流(需要 push 与 GitHub 账号)。
