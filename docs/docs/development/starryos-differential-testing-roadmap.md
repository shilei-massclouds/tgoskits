---
sidebar_position: 6
sidebar_label: "差分测试改进路线图"
---

# StarryOS 差分测试场景与变异改进路线图

本文规划 StarryOS Linux 差分测试的长期演进，重点提高测试场景的广度、
变异的有效性，以及 coverage 反馈对 corpus 演进的实际帮助。当前起点是
`scripts/pipe-oracle/` 和 `test-suit/starryos/qemu/pipe-linux-oracle/`；后续可以
扩展到 `eventfd`、Unix domain socket 和 VFS 等其他 Linux 兼容接口。

本文只描述后续方向和阶段门槛，不表示所有阶段都应同时启动。近期优先完成
收益高、改动边界小的阶段 0 至阶段 3.1，并在取得度量结果后再决定后续投入。

## 1. 范围与决策

差分测试继续使用以下主流程：

```text
场景操作序列
  -> host Linux 执行并录制预期 trace
  -> 同一个执行程序和操作序列在 StarryOS 中运行
  -> 比较返回值、errno 和操作输出
  -> 提取 StarryOS LLVM coverage
  -> 选择、保存、变异或最小化场景
```

Linux 执行结果仍是唯一测试基准。场景生成器可以维护 fd 类型、资源生产者和
消费者、线程或对象生命周期等结构状态，但不能再实现一份 Linux 返回值、
readiness 或错误选择模型。

### 1.1 目标

1. 让大部分变异都实际改变执行的操作或参数，而不是只改变无语义效果的输入。
2. 系统覆盖有效、错误、边界和生命周期场景，而不只生成随机的正常调用。
3. 将新 coverage 精确归因到具体场景，并让有价值的 corpus 跨 campaign 保存。
4. 对 mismatch 和新 coverage 场景进行自动最小化，生成短小、稳定的回归输入。
5. 复用 syzkaller 的 syscall 程序作为候选场景来源，但继续使用本项目的差分执行
   和比较流程。
6. 在出现第二个真实场景适配器后提取公共框架，逐步扩展到 pipe 之外的接口。

### 1.2 非目标

- 不设计或实现 KCOV。
- 不接入完整的 `syz-manager`、`syz-executor` 或 syzkaller VM 生命周期。
- 不复制 Linux pipe、socket、VFS 或其他子系统的结果语义模型。
- 不用自然调度顺序或绝对时间直接比较并发行为。
- 不在近期将重型 fuzz campaign 加入默认 PR 或 CI 路径。
- 不立即承诺稳定的公共 corpus、trace 或场景插件协议。

## 2. 当前基础与主要缺口

固定 `pipe.ops` 已覆盖零长度 I/O、数据顺序、`PIPE_BUF` 小写入原子性、大写入
部分成功、页槽碎片、端点复制与关闭、EOF、`EPIPE` 和容量取整。这些人工场景
用于保护已知语义边界，不能被随机生成器替代。

当前 coverage fuzz 已具备 host record、StarryOS compare、failure artifact、
replay 和 LLVM region 反馈，但场景演进仍有以下限制：

- `generator.py` 只将 fuzz 输入的前 8 字节解释为随机种子；其余字节的多数变异
  不会改变最终 `pipe.ops`。
- corpus 以原始 bytes 为单位，而 coverage 实际对应生成后的操作序列；不同输入
  可能产生重复或等价场景。
- 成功 corpus 只存在于当前进程，campaign 重启后从内置 seed 重新开始。
- productive batch 已能逐 entry 重放并保存完整 coverage 映射；后续缺口是阶段
  2.3 的 operation/scenario 最小化，而不是继续按整批粗粒度准入。
- 随机参数没有优先覆盖 `0`、`PAGE_SIZE`、`PIPE_BUF`、capacity 等语义边界。
- generator 尚不能产生固定 corpus 已有的所有操作，也很少主动产生非法资源、
  错误 fd 类型和异常 flags。
- coverage 目标硬编码为 `pipe.rs`，不适合后续跨文件或跨子系统场景。

这些缺口决定了近期应先改善输入表示、变异和 corpus 闭环，而不是立即增加大量
新 syscall 或抽象一个通用框架。

## 3. 效果衡量

阶段 0 先记录基线，不预先设置脱离数据的百分比目标。后续阶段至少持续观察：

| 指标 | 含义 |
|---|---|
| 语义变异有效率 | mutation 前后的 canonical 操作序列不同的比例 |
| 唯一场景比例 | 生成场景按 canonical digest 去重后的比例 |
| 操作覆盖 | 每种 operation 是否可由 generator 到达 |
| 参数桶覆盖 | 长度、flags、events、fd 状态等关键类别是否出现 |
| 状态转换覆盖 | 创建、复制、关闭、对端消失等资源转换是否出现 |
| region 收益 | 每次 QEMU 或每分钟获得的新目标 region 数量 |
| coverage 归因率 | 新 region 能定位到具体 corpus entry 的比例 |
| 最小化收益 | 场景操作数、参数复杂度和 artifact 大小的缩减 |
| 稳定性 | 相同场景重复 host record 后 normalized trace 一致的比例 |
| replay 成功率 | 保存的 mismatch 在当前约束下能够再次触发的比例 |

代码 coverage 只表示执行到达，不证明语义正确。新增 operation 必须同时有执行
结果比较和确定性回归证据，不能只以 region 数增长作为完成条件。

## 4. 阶段 0：建立生成器与变异基线

**定位：近期，投入小，一个独立 PR。**

**阶段状态：已完成。**

增加不改变 campaign 行为的离线分析入口，输出稳定 JSON 和便于阅读的摘要。阶段
0 只观察生成器与变异器的离线行为，不启动 QEMU、不执行测试场景，也不读取或
修改真实 campaign corpus。

### 4.1 统计口径

- 一个生成样本是一个 raw input 及其生成的完整 `pipe.ops` 文本；canonical 文本
  必须是执行入口实际使用的 `ops_to_text(expand_input(input))` 结果，包括版本、
  场景名和结尾换行。
- canonical digest 是上述文本 UTF-8 字节的 SHA-256；不能使用 raw input digest、
  Python 对象 hash 或重新构造的摘要格式代替。
- raw 变异变化表示 mutation 前后 bytes 不同；规范场景变化表示 canonical digest
  不同。两者分别计数，并单列“raw 改变但规范场景不变”的无效变异。
- 唯一场景数按完整 canonical digest 去重；重复率为
  `(样本数 - 唯一场景数) / 样本数`。最高频场景同时报告 digest、出现次数和完整
  canonical 文本，便于人工复核热点。
- operation 和参数桶统计所有生成场景中的操作。长度、pipe size、poll mask 以及
  每个 operation 执行前的 reader/writer 数量分别统计，资源数量在每个 scenario
  开始时重置。
- 生成样本和 mutation 分别使用当前 campaign `_Rng` 流和独立确定性随机流，两个
  来源独立报告；每种 mutation 的尝试、raw 变化和规范场景变化之和必须分别等于
  对应总数。

batch 耗时、新增 region 和真实 corpus entry 的来源、后代及 coverage 贡献依赖
实际执行和持久化身份，移至阶段 2 的 corpus 持久化与精确归因中记录。

### 4.2 实施进度

| 步骤 | 状态 | 完成日期 | 验证证据 |
|---|---|---|---|
| 1. 定义规范场景摘要和统计口径 | 已完成 | 2026-07-31 | 明确以实际 `pipe.ops` 文本及其 SHA-256 为 canonical，并定义变异、去重、参数和资源桶口径。 |
| 2. 实现 canonical 文本及 digest 辅助函数 | 已完成 | 2026-07-31 | `canonicalize_input` 复用 `expand_input`/`ops_to_text`，直接验证文本和 UTF-8 SHA-256 与现有序列化结果一致。 |
| 3. 实现离线分析器及稳定 JSON 输出 | 已完成 | 2026-07-31 | 两类独立随机流的小规模 JSON 连续运行逐字节一致，分类总和校验通过；临时工作目录保持为空。 |
| 4. 完成测试、运行基线验证并记录结果 | 已完成 | 2026-07-31 | 14 个 pipe-oracle 单元测试通过；默认规模 JSON 连续两次 SHA-256 均为 `7fc3f25595c3bc8a8fe1cc7bb836895b4dd140d9416abfd216c18637ea75fc89`，临时目录无新增文件。 |

实施后续阶段前，先将阶段细化成同样可验收的步骤表。步骤只使用 `未开始`、
`进行中`、`已完成` 三种状态：开始实施时更新为 `进行中`，代码和对应验证完成后
在同一笔提交中更新为 `已完成`，并记录完成日期和简短、可复核的验证证据。阶段
内全部步骤完成后才能把阶段总状态改为 `已完成`。进度记录不引用易失效的工作树
状态，也不提交生成的完整基线快照。

### 4.3 交付物

- generator/mutation 离线分析脚本及其单元测试；
- 可重复的文本和 JSON 基线报告格式；
- 可在后续阶段复用的 canonical scenario digest 计算方法。

### 4.4 验收标准

- 相同参数连续运行的 JSON 输出逐字节一致；
- 能识别“raw input 改变但场景未改变”的 mutation；
- 两类随机来源独立报告，所有分类统计满足总和约束；
- 统计过程不启动 QEMU、不写文件，也不改变 corpus 或 failure artifact；
- 命令入口、完整 pipe-oracle 单元测试和默认规模分析通过验证。

## 5. 阶段 1：结构化场景与有效变异

**定位：近期，投入小到中，预期收益最高，拆成两个或三个 PR。**

**阶段状态：已完成。**

### 5.1 实施进度

| 步骤 | 状态 | 完成日期 | 验证证据 |
|---|---|---|---|
| 1. 行为保持型 IR 与 codec | 已完成 | 2026-07-31 | 11 种 operation、typed codec error、manual corpus round trip 和 legacy full-text/digest golden 通过；新 IR-backed legacy generator 配合阶段 0 analyzer/旧 raw mutator的默认 JSON SHA-256 仍为 `7fc3f25595c3bc8a8fe1cc7bb836895b4dd140d9416abfd216c18637ea75fc89`。 |
| 2. 结构化 corpus、正式 RNG 与 mutation | 已完成 | 2026-07-31 | 五个 legacy seed 等价迁移；canonical digest 有序 corpus 和独立进程 batch/mutation 确定性通过；8 类 mutation、dependency repair、entry limit、donor splice、schema 2 analyzer 通过，executable canonical no-op 为零。 |
| 3. 边界字典与错误资源场景 | 已完成 | 2026-07-31 | 0/1、4 KiB/8 KiB 邻域、最大值和未知 mask bit 可达；空闲/关闭 slot、错误端点、重复 close、双端查询和 null I/O 可达；malformed 在 host/QEMU 前过滤，错误资源 corpus 的 host record/compare 自洽。26 个单元测试和 `git diff --check` 通过；短 campaign 进入 QEMU compare 并保存一个真实 poll mask differential artifact。 |

### 5.2 引入内部场景 IR

将 generator 内部表示改为显式的 `Scenario`、`Operation` 和 logical resource。
`pipe.ops` 继续作为可审查、可重放的执行格式；内部 IR 暂不作为公共 API。

IR 至少表达：

- operation 类型和强类型参数；
- logical fd slot 及其当前资源类别；
- operation 的资源生产、消费和释放关系；
- scenario 边界与版本；
- canonical serialization 和 digest。

阶段 1 选择 canonical UTF-8 `pipe.ops` 作为唯一 corpus 编码，不再引入另一种二进制
格式。任意 raw bytes 到 version-1 LCG 的解码只用于迁移五个初始 seed 和 legacy
golden；正式 campaign 使用版本化 SHA-256 counter stream，并通过拒绝采样选择范围。
同一 generator 版本、seed 和 corpus 必须在独立进程中产生相同的选择和 mutation。

### 5.3 增加结构化 mutation

第一批 mutation 包括：

- 插入、删除或替换一个 operation；
- 交换相邻 operation；
- 复制、删除或拼接连续 operation 片段；
- 拼接两个 corpus entry；
- 修改 fd、长度、byte、flags 或 event mask；
- 将有效资源替换为关闭、空闲、错误类型或越界 slot；
- 在保持目标 mutation 意图的前提下修复必要资源依赖。

修复逻辑只保证场景可以被 harness 表达，不应把所有非法操作修复成成功路径。
错误 fd、错误端点和非法参数必须是显式可生成的场景类别。

mutation 结果分为 `executable` 和 `malformed`。前者进入 host/StarryOS batch，后者
记录稳定 codec/limit 类别后在 host 执行前过滤；host parser rejection 也不计为
differential failure。可执行 mutation 必须改变 canonical digest，不允许静默 no-op。

### 5.4 增加边界值字典

数值 mutation 优先从领域字典选择，同时保留一部分任意值：

```text
0, 1, 2
PAGE_SIZE - 1, PAGE_SIZE, PAGE_SIZE + 1
PIPE_BUF - 1, PIPE_BUF, PIPE_BUF + 1
capacity - 1, capacity, capacity + 1
最大合法值、越界值、未知 flag bit
```

依赖运行环境的值应在执行时解析或记录，不要把宿主机偶然状态静默固化为跨平台
语义。

### 5.5 阶段 1 新基线

默认配置（seed 42、每个来源 10,000 个生成样本和 20,000 次 mutation）的 schema 2
JSON 连续两次逐字节一致，SHA-256 均为
`7dbb413e07077da9fb4bc7c0cc976bcdfd258e3e1b2415e717734f7721503dc1`。

| 来源 | 唯一场景 | 重复样本 | executable mutation | malformed mutation | canonical change rate | executable no-op |
|---|---:|---:|---:|---:|---:|---:|
| `campaign_rng` | 9,991 | 9 | 19,629 | 371 | 98.145% | 0 |
| `legacy_lcg` | 9,996 | 4 | 20,000 | 0 | 100% | 0 |

`campaign_rng` 的 371 个 malformed 包含 280 个 out-of-range 和 91 个 resource
conflict。11 种 operation，以及 null I/O、空闲/关闭 slot、错误端点、重复 close
和读写两端查询类别均有非零样本。

计划指定的 `--seed 42 --batches 1 --batch-size 8` 短 campaign 生成 8 个
executable entry（23 个 scenario、0 个 malformed），host record 成功，并进入
StarryOS QEMU compare。compare 在 `poll 9 3260` 处发现 Linux 返回 `POLLHUP`、
StarryOS 返回 `EINVAL` 的真实差异，保存为
`batch0_mismatch_35f3571308ae`。阶段 1 不修改 StarryOS syscall 语义，也不将该
差异改判为 malformed；该差异已由后续独立 ABI 修复处理，artifact 继续作为原始
差异证据保留。

### 5.6 验收结果

- 相同 seed、corpus 和 generator 版本产生字节一致的操作序列；
- codec round trip 保持 canonical 场景不变；
- 除显式 no-op 外，每个 mutation 都改变 canonical digest；
- mutation 后的场景要么通过 harness 解析，要么以预期的 malformed 类别被拒绝；
- generator 测试能证明所有 operation 和关键参数桶可达；
- 不新增任何预测 Linux 返回值或 errno 的逻辑。

## 6. 阶段 2：Corpus 持久化、归因与最小化

**定位：近期至中期，投入中，两个或三个 PR。**

**阶段状态：已完成。**

### 6.1 持久化和去重

**子阶段状态：已完成。**

| 步骤 | 状态 | 完成日期 | 验证证据或继续位置 |
|---|---|---|---|
| 1. 确定持久目录、schema、兼容和原子保存策略 | 已完成 | 2026-07-31 | 采用 canonical SHA-256 entry 目录、schema v1、generator 版本拒绝、ELF digest 隔离 coverage state、临时目录原子 rename、metadata 原子 replace 和 workspace campaign 锁。 |
| 2. 添加重启恢复回归并确认旧实现失败 | 已完成 | 2026-07-31 | 新增独立 `test_corpus.py`；旧实现因不存在磁盘 corpus 模块而以 `ModuleNotFoundError: No module named 'corpus'` 确定性失败。 |
| 3. 实现独立 corpus 持久层和严格加载 | 已完成 | 2026-07-31 | `corpus.py` 已实现 canonical 去重、entry metadata、原子保存、损坏/不兼容 fail closed、ELF coverage state 和进程锁；11 个独立 corpus 测试通过。 |
| 4. 接入 campaign provenance、run metadata 和持久 coverage 基线 | 已完成 | 2026-07-31 | `MutationCandidate` 已贯穿 generated/mutation、parent、donor 和 mutation 类型；`fuzz.py` 启动合并磁盘 corpus，原子记录 run metadata，并按 Starry ELF digest 恢复/保存 coverage baseline。40 个 Python 测试通过，固定 seed 的 batch digest golden 保持不变。 |
| 5. 补全测试、文档和两次真实 campaign 验收 | 已完成 | 2026-07-31 | README 和设计文档已同步；40 个 Python 测试、`py_compile` 和 `git diff --check` 通过。第一次 seed 42 campaign 完成 host record、StarryOS QEMU compare 和 coverage 提取，持久化 8 个 canonical entry 及 382 个新增 pipe region；第二次重启报告 `built-in=5 disk=8 deduplicated-total=13`，完成 compare/coverage 并继续准入 2 个新 entry。两次构建得到不同 Starry ELF digest，各自保存独立的 382-region baseline；严格重载确认磁盘共有 10 个唯一 digest，且无半写目录。 |

阶段 2.1 保留的 schema v1 entry 继续严格可读；阶段 2.2 只在旧 entry 再次成为
确定贡献者时将其原子惰性升级为 schema v2。阶段 2.3 在最终证明后才将最小 entry
写为 schema v3，并保留 v1/v2 历史目录。

按 canonical 操作序列而不是 raw input 保存成功 corpus。每个 entry 记录：

- scenario digest 和 generator 版本；
- 生成来源、父 entry 和 mutation 类型；
- 首次获得的 region；
- 最近验证的 commit、架构和运行环境摘要；
- 稳定性和 replay 状态。

campaign 启动时加载兼容版本的 corpus。版本不兼容时必须显式迁移、重新验证或
拒绝，不能静默按新语义解释旧输入。

持久化 metadata 同时记录实际 batch 耗时、输入数、来源和后代关系；这些数据以
稳定 corpus entry 身份为锚点，避免阶段 0 离线估计与真实 campaign 行为混淆。

### 6.2 精确 coverage 归因

**子阶段状态：已完成。**

| 步骤 | 状态 | 完成日期 | 验证证据或继续位置 |
|---|---|---|---|
| 1. 固定重放、ELF 和兼容策略 | 已完成 | 2026-07-31 | 默认使用精确归因；productive batch 对每个唯一 entry 重放，并最终重放代表集，最多增加 `N + 1` 次 QEMU。每次重放重新生成 Linux trace；连续归因只接受同一 Starry ELF。 |
| 2. 定义 attribution job/run schema v2 和 corpus schema v2 | 已完成 | 2026-07-31 | job 保存完整输入、ELF、初始/逐项/代表集 replay 证据、状态、映射和 ELF transition；run 保存 job ID、全部映射、代表集和额外 QEMU 数；corpus 严格读取 v1/v2，并仅在旧 entry 再次贡献时原子惰性升级。 |
| 3. 实现中断恢复、失败保全和固定 ELF 转换流程 | 已完成 | 2026-07-31 | campaign 在新 batch 前恢复 job；证据先于 metadata 持久化并可在重启时对账。跨 campaign ELF 改变时先对完整原 batch 重放并重置归因；连续重放中 ELF 改变或归因不稳定时移动完整 job 到 failure，不更新 baseline。 |
| 4. 实现确定性代表集和原子最终提交 | 已完成 | 2026-07-31 | 保存所有 `entry -> target regions` 映射；按最大新增覆盖、digest 破同分，再确定性删除冗余项；只有代表集最终重放覆盖全部 target 后才准入代表 entry 并提交 baseline。 |
| 5. 完成回归、文档和真实 campaign 验收 | 已完成 | 2026-07-31 | 59 个 Python 回归、2 个 axbuild kallsyms 固定测试、`cargo xtask clippy --package axbuild`、`py_compile` 和 `git diff --check` 通过。真实 seed 4246、`batch-size=1` campaign 完成初始 batch、逐 entry 和代表集三次 QEMU；后两次正好满足 `N + 1 = 2`。三份 fresh trace/profraw evidence 均覆盖 346 个 target region，Starry ELF SHA-256 均为 `de330f7778459ac401f5891dab69f130812b2064a9845657db5687051f5b7c3d`；job/run/corpus v2 和 ELF-scoped baseline 完成原子提交。验收期间发现 `gen_ksym` 会单独改变 `.kallsyms` 排序；重放现固定 job ELF 的 kallsyms，并在替换前校验全部运行时及 coverage section、替换后校验完整 ELF 逐字节一致。阶段 2.3 不在本步骤范围。 |

常规路径继续使用 batch 降低 QEMU 次数。只有 batch 获得新 region 时，才对子集
进行精确重放：

1. 原子保存该 batch 的唯一候选、ELF-scoped baseline、target region 和初始证据；
2. 为每个 entry 重新执行 host record，并用 fresh profraw 启动一次 StarryOS QEMU；
3. 保存所有 entry 对 target region 的交集，包括空集合；
4. 确定性选择去冗余、inclusion-minimal 的代表覆盖；
5. 为完整代表集重新生成 Linux trace 并执行一次最终 QEMU 证明；
6. 只将新代表 entry 加入持久 corpus，同时更新已有的非代表贡献者。

成功路径在初始 batch 之外最多增加 `N + 1` 次 QEMU。这里的“去冗余”只删除能由
其他 entry 覆盖替代的完整 entry，不删除 scenario、operation 或参数，因此不属于
阶段 2.3 的最小化。

归因不能使用不同构建产生的 coverage 与原 batch 混合。一次连续归因中 Starry
ELF digest 改变会立即失败；为消除 `gen_ksym` 对相同符号表产生的 `.kallsyms` 排序
抖动，entry 和代表集 replay 固定使用 job 保存 ELF 的 kallsyms。axbuild 在替换前
比较非零地址运行时 section 与 `__llvm_covfun`/`__llvm_covmap`，替换后要求完整 ELF
逐字节等于保存版本，真实代码或 coverage metadata 改变仍会失败。若中断恢复时
active ELF 已改变，则先对完整保存 batch 重新执行 host record/QEMU，在新 ELF
baseline 上计算 target，记录 transition 并从逐 entry 归因重新开始。用于比较的
每个 profraw 都由对应 replay 产生，QEMU 启动前先删除固定 profraw 路径，禁止复用
陈旧文件。

job metadata、每个 replay evidence 和最终 run record 都使用 schema v2 严格校验。
campaign 启动时优先恢复未完成 job；若进程终止在 evidence 保存和 metadata 更新
之间，下次启动从 evidence 对账而不重复已完成 QEMU。归因缺失 region、最终代表集
不能复现、host/guest/coverage 失败或 ELF 不稳定时，完整 job 原子移动到
`failures/attribution-<job-id>/`，campaign 停止，corpus 和 coverage baseline 均不
接收未经最终证明的结果。

归因结果记录每个 batch 的新增 region，以及每个真实 corpus entry 对这些 region
的具体贡献、代表集和额外 QEMU 次数，作为后续评估单位 QEMU 时间收益的基础。

#### 6.2 验收标准

- productive batch 的每个 target region 至少映射到一个具体 entry；
- 相同映射始终选择相同代表集，最终代表集重放覆盖所有 target region；
- 成功路径在初始 batch 外不超过 `N + 1` 次 QEMU，且每次使用新的 Linux trace
  和当前 run 的 profraw；
- 中断 job 在新 batch 和 RNG 消耗前恢复，已保存 evidence 不会重复执行；
- v1/v2 corpus 严格兼容读取，旧 contributor 的 v2 升级和所有 job 状态转换均为
  原子操作；
- 归因不稳定时保留完整证据、停止 campaign，且 baseline 不变；
- 连续 QEMU 的 Starry ELF digest 稳定；跨 campaign digest 改变严格执行完整 batch
  rebase 流程。

### 6.3 场景最小化

**子阶段状态：已完成。**

| 步骤 | 状态 | 完成日期 | 验证证据或继续位置 |
|---|---|---|---|
| 1. 类型化 guest 结果、difference mask 和 failure schema v2 | 已完成 | 2026-07-31 | runner 区分 passed、semantic mismatch、oracle/panic/lockdep/timeout/infrastructure；monitor socket 回归证明基础设施故障不再误报 mismatch。C harness 输出稳定 difference mask；failure v2 固定 Starry ELF 和 fingerprint，v1 只在旧 log 可严格推导并重放确认时惰性导入。 |
| 2. 实现确定性结构化 reducer 和谓词 | 已完成 | 2026-07-31 | reducer 保留 operation origin，按 tail/scenario block/operation block/reverse single/dup-resource/参数顺序缩减；所有候选 canonical、资源合法、complexity 严格下降并去重。coverage 使用确定性责任集，mismatch 要求 origin/fingerprint 不漂移。 |
| 3. 实现持久 job、预算和最终证明 | 已完成 | 2026-07-31 | minimization schema v1 严格保存 validating/reducing/final-proof/completed/stale/unstable、reducer cursor、固定 ELF、best checkpoint、拒绝摘要和重型证据。候选共享预算默认 64；原始验证一次，最终连续证明两次；checkpoint/metadata 间崩溃可恢复。 |
| 4. 接入 corpus v3、failure v2、run v3 和 campaign 启动顺序 | 已完成 | 2026-07-31 | 最小 entry 先激活再 supersede，历史 entry 保留且 mutation 只加载 active；coverage baseline 不由 minimizer 修改。启动先恢复 attribution/minimization、再加载 active corpus、最后初始化 RNG；`--no-minimize` 可回滚。 |
| 5. 完成全部回归、文档和真实 QEMU 小预算验收 | 已完成 | 2026-07-31 | 85 个 Python/host-harness 回归、`py_compile`、workspace rustfmt 和 `git diff --check` 通过。真实 coverage job 使用固定 ELF `de330f…` 完成 1 次验证、4 次候选和2次证明，输入由 637 缩至 503 字节；两次 fresh profraw 分别覆盖全部 346 个责任 region，原 entry 保留为 superseded、最小 entry active。现有 schema-v1 poll mismatch 成功惰性导出 operation 16 的稳定 fingerprint，但当前 ELF 上 397 个 operation 已全部通过，故按设计在原始验证后标记 unstable、候选 QEMU 为 0，原 artifact digest 不变；该历史 ABI 差异已经修复，本地已无可做正向真实缩减的旧 ELF。正向 mismatch 缩减由确定性端到端回归验证（1 次验证、1 次候选、2 次证明并保留原/最小 failure）；两个旧基础设施 artifact 均在 QEMU 前被严格拒绝。 |

对 mismatch 和获得新 region 的场景分别使用对应谓词最小化：

- 删除整个 scenario；
- 删除 operation 或连续片段；
- 压缩 dup 链、重定向兼容资源引用并进行 dense slot 重命名；
- 将参数逐步缩到边界值；
- 删除关键 mismatch operation 之后的尾部操作。

mismatch 最小化必须保持相同差异类别和关键操作；coverage 最小化必须保持指定
region 集合，不能仅要求“仍有任意 coverage”。

实现使用固定、结构感知的分层 delta debugging，不调用随机 mutation，也不隐式
合成初始化操作。每个 job 默认最多运行 64 次候选 QEMU；无效或重复候选不计预算。
原输入验证一次，最终当前最佳连续证明两次。预算耗尽但证明成功时以
`budget-limited` 完成，因此目标是预算内确定性缩减，不承诺全局最小。

coverage target region 按代表 digest 顺序分配给首个覆盖者，并与 entry 历史
`attributed_regions` 取并集形成责任集。多个代表按 digest 轮转、共享预算；最终
代表集必须连续两次覆盖全部责任集并集，之后最小 entry 才激活，原 entry 才标记
superseded。mismatch fingerprint 包含原 operation identity、kind、差异字段、两侧
结果类别和失败侧 errno；不同 fingerprint、关键 operation 漂移或通过均是普通拒绝。

job 在新 batch 和 RNG 消耗前恢复。恢复时 Starry ELF 改变则保存为 `stale` 并停止，
不自动 rebase；panic、基础设施故障、coverage 缩减中出现新 mismatch 或最终证明
不稳定会保存完整异常证据并标记 `unstable`。普通拒绝只保存摘要和 evidence digest，
重型 profraw 仅保留原始验证、当前最佳、异常现场和两次最终证明。

### 验收标准

- campaign 重启后能够继续使用已保存 corpus；
- raw 输入不同但 canonical 场景相同的 entry 只保存一次；
- 每个新 region 能追溯到至少一个具体场景；
- 阶段 2.3 完成后，最小化前后的 predicate 有自动化测试；
- 中断保存不会留下被下次 campaign 当作有效 entry 的半写目录。

## 7. 阶段 3：扩展确定性 Pipe 场景

**定位：近期至中期。按语义族拆分，每个语义族独立回归、实现和验证。**

### 7.1 低成本边界补齐

优先让 generator 覆盖 harness 已有能力和同步错误路径：

- `read-null`、`write-null`；
- 已关闭 fd、重复 `close`、空闲 slot 和越界 slot；
- 对 read end 执行 write、对 write end 执行 read；
- 在读写两端查询 `FIONREAD` 和 pipe capacity；
- 任意及未知 poll event mask；
- 零长度、空 buffer、非法 pointer 与正长度的组合；
- `0`、`1`、`PAGE_SIZE` 和 `PIPE_BUF` 邻域值。

这部分不引入线程、阻塞等待或新的执行框架，应作为阶段 1 和阶段 2 后的首批场景
扩展。

### 7.2 fd、flags 与向量 I/O

#### 阶段 3.2a：pipe fd 与 flags 差分场景

**状态：已完成（2026-07-31）。**

本子阶段将 `pipe.ops` 升至 version 2，在保持 version 1 canonical digest 和回放
兼容的前提下增加：

- `pipe2` 的 `0`、`O_NONBLOCK`、`O_CLOEXEC` 和非法 flags；
- `F_GETFL`、`F_SETFL` 动态切换 `O_NONBLOCK`；
- `F_GETFD` 和 `FD_CLOEXEC`；
- `dup2`、`dup3`、同 fd 和目标 fd 覆盖。

IR 显式区分共享 open-file-description status flags 和逐 fd `FD_CLOEXEC`。正长度
I/O 仅在 codec 能静态证明 `O_NONBLOCK` 已启用时接受；零长度、无效 fd 和纯 fd/flag
错误路径保持同步执行。trace version 2 追加 operation kind，成功的 `dup2`/`dup3`
返回值统一归一化为 `0`。coverage 使用 `pipe-fd-v2` target set，固定覆盖
`file/pipe.rs`、`syscall/fs/pipe.rs` 和 `syscall/fs/fd_ops.rs`；旧持久 job 继续绑定
`pipe-v1`，不会污染新 baseline。

本子阶段不包括 `readv`/`writev`、multi-fd poll、`select`/`epoll`、exec 生命周期或
自然阻塞语义。

验收时 103 个 Python/host-harness 回归、`py_compile`、workspace rustfmt 和
`git diff --check` 通过；x86_64 QEMU 对 checked-in version-2 corpus 的 115 个
operation 全部通过并成功导出 coverage。小预算真实 campaign 完成两个精确归因与
最小化 job：在两个固定 Starry ELF 上分别新增 693 和 674 个 `pipe-fd-v2` region，
均以 1 次原始验证、4 次候选和 2 次最终证明完成；canonical entry 分别由 631 缩至
476 bytes、由 1171 缩至 843 bytes。旧 schema job 保持 `pipe-v1`，磁盘中断后的
schema-v3 job 从原子 checkpoint 恢复，未重复生成输入。未发现 StarryOS 语义差分，
生产 Rust 逻辑无需修改。

#### 阶段 3.2b-1：Pipe 向量 I/O 差分

**状态：已完成（2026-08-01）。**

`pipe.ops` version 3 增加有界 `readv`/`writev`，覆盖空向量、零长度段、跨段布局、
短读/部分写、无效 iovec/base、负数和超限 `iovcnt`、坏 fd 及错误优先级。trace
version 3 追加 kind 18/19；`readv` 将全部有效目标段（包括固定哨兵的未写区域）扁平
写入 trace。generator v4、mutation 和 reducer 均理解向量 count、segment、base、
length 和 byte，正长度路径继续要求静态 `O_NONBLOCK`。

coverage 使用 `pipe-vector-v3`，在 3.2a 的三个文件上追加 `syscall/fs/io.rs` 与
`mm/io.rs`。新持久格式为 coverage-state v3、attribution v4、minimization v3、run
v5；旧格式分别严格恢复到 `pipe-v1` 或 `pipe-fd-v2`，corpus schema v3 与 failure
schema v2 保持不变。

直接 raw-syscall 回归证明 Starry 原先在 `sys_writev` 中先导入 iovec，且 read/write
访问模式也晚于 iovec 校验。生产修复为 `FileLike` 增加读写能力查询，由普通文件、
目录、pipe 和 memfd 实现；`sys_readv`/`sys_writev` 在导入用户 iovec 前统一检查 fd
及能力，没有 pipe 特判。预修复 x86_64 QEMU 为 70 pass / 4 fail，修复后为
74 pass / 0 fail。

完整 oracle 随后发现第二个校验时机差分：空 nonblocking pipe 的 `readv` 使用未映射
但仍位于 Linux user limit 内的 segment base 时，Linux 在实际访问目标内存前返回
`EAGAIN`，Starry 却在导入 iovec 时返回 `EFAULT`。新增 raw-syscall 回归在修复前为
75 pass / 1 fail；`IoVectorBuf` 改为导入时只做 Linux `access_ok` 风格的地址上限检查、
把映射错误延迟到实际段访问后，回归为 76 pass / 0 fail。

最终验收中，114 个 Python/host-harness 回归、23 项 `starry-kernel` clippy、
`py_compile`、workspace rustfmt、`git diff --check` 和 host C record/compare 全部通过；
checked-in version-3 corpus 的 142 个 x86_64 QEMU operation 全部通过并导出 coverage。
真实 `seed=2`、`batch-size=2` campaign 同时执行 `readv`/`writev`，2 个输入均可执行，
新增 1000 个 `pipe-vector-v3` region：`file/pipe.rs` 345、`syscall/fs/pipe.rs` 33、
`syscall/fs/fd_ops.rs` 342、`syscall/fs/io.rs` 171、`mm/io.rs` 109。精确归因使用 3 次
额外 QEMU，将 993/956 个 region 映射到 2 个代表。最小化使用 1 次验证、4 次候选和
2 次最终证明；两个输入分别保持 1308 bytes 和由 672 缩至 629 bytes，最终以
`budget-limited` 完成并保留全部责任 region。

#### 阶段 3.2b-2：multi-fd poll

**状态：已完成（2026-08-01）。**

`pipe.ops` version 4 增加 `poll-many COUNT [FD_MODE FD_ARG EVENTS]...`，数组长度限制
为 `0..4`。fd 可引用逻辑 slot，也可使用固定 literal `-2`、`-1`、`2147483647`；
timeout 固定为零。它覆盖空数组、多个不同 fd、同一 slot 重复、dup alias、所有负 fd、
无效正 fd、invalid/ready 混合顺序、不同 mask 以及 closed-peer `HUP/ERR`，不复用旧
单 fd 结果结构。

trace version 4 追加 kind 20，精确保存 syscall `result`/`errno`，并按数组顺序把每个
`revents` 以两字节 little-endian 写入 `data`。调用前全部填充固定哨兵，ignored/unready
条目必须由内核清零。generator v5、mutation 和 reducer 均理解 entry 增删、重复、
顺序、fd mode/argument 与 event mask；reducer 保持复杂度严格下降，不合成资源初始化。

新 coverage target 为 `pipe-poll-v4`，在 `pipe-vector-v3` 五个文件上追加
`syscall/io_mpx/poll.rs` 与 `syscall/io_mpx/mod.rs`。持久格式升级为 coverage-state v4、
attribution v5、minimization v4、run v6；旧 schema 严格绑定到 `pipe-v1`、
`pipe-fd-v2` 或 `pipe-vector-v3`，corpus schema v3 与 failure schema v2 不变。

直接 raw-syscall 回归证明 Starry 原先只忽略 `fd == -1`，并在遇到无效正 fd 后提前
返回，遗漏同一数组中有效条目的 readiness。预修复新模块为 8 pass / 8 fail；共享
`do_poll` 修复为清零并忽略所有负 fd、累计 invalid entry、即时扫描所有有效 entry 后
返回，重复 fd 逐项计数，不增加 pipe 特判。修复后的 `poll`/`ppoll` 镜像回归为
16 pass / 0 fail，完整 select/poll family 的 45 个模块全部通过。`ppoll` 仅验证共享
生产路径，不加入 differential corpus。

最终 checked-in version-4 corpus 的 162 个 host/Starry operation 全部通过并导出
coverage。真实 `seed=0`、`batch-size=2` campaign 生成 11 个 `poll-many`，两个输入均
可执行，新增 1205 个 region：`file/pipe.rs` 353、`syscall/fs/pipe.rs` 33、
`syscall/fs/fd_ops.rs` 342、`syscall/fs/io.rs` 169、`mm/io.rs` 121、
`syscall/io_mpx/poll.rs` 179、`syscall/io_mpx/mod.rs` 8。精确归因使用 3 次额外 QEMU，
将 1187/1078 个 region 映射到两个代表；最小化使用 1 次验证、4 次候选和 2 次最终
证明，责任 region 要求两个输入保持 1653/555 bytes，最终以 `budget-limited` 完成。

实现前的旧 Python codec 与保存的 version-3 C harness 均严格拒绝 version-4 corpus。
实现后 120 个 Python/host-harness 回归、`py_compile`、23 项 `starry-kernel` clippy、
workspace rustfmt 与 `git diff --check` 全部通过。

本阶段仍不包含坏 `pollfd *`、超限 `nfds`、非零/无限 timeout、信号 mask、线程关闭
竞态或阻塞语义；这些边界继续由直接 syscall 测试或后续并发阶段负责。

### 7.3 readiness 与零拷贝接口

在前述同步场景稳定后，再增加：

- timeout 为零的 `select`、`pselect`；
- `epoll_create1`、`epoll_ctl`、timeout 为零的 `epoll_wait`；
- `splice`、`tee`、`vmsplice`；
- FIFO pathname/open 语义；
- `fork`、`exec` 后的 fd 和 `CLOEXEC` 生命周期。

后两类涉及更多 VFS、进程和环境状态，coverage 目标也应扩展到真正拥有相关语义
的文件，不能继续只统计 `pipe.rs`。

### 每个语义族的合入门槛

1. 先增加一个在缺失行为上必然失败的确定性回归。
2. host `--record` 后 host `--compare` 必须自洽。
3. trace 损坏或 malformed corpus 必须 fail closed。
4. generator reachability 测试证明新 operation 和关键参数可到达。
5. StarryOS mismatch 必须修生产实现，不能通过放宽比较隐藏。
6. 文档登记规范化字段、环境依赖和明确非目标。

## 8. 阶段 4：导入 syzkaller 候选语料

**定位：中期，投入中；在结构化 IR 和持久 corpus 稳定后开始。**

实现受限的 `.syz` 文本 importer，不构建或运行 syzkaller executor。第一版只接受
场景适配器声明的 syscall allowlist，并将 syzkaller resource 引用转换为本项目的
logical resource。

导入流程：

```text
.syz program
  -> 解析 syscall、参数和 resource 引用
  -> 拒绝不支持或不确定的调用
  -> 转换为内部 Scenario IR
  -> 在 host Linux 上重复执行稳定性检查
  -> 使用现有 host record / StarryOS compare
  -> coverage 归因、最小化并进入持久 corpus
```

第一版 pipe allowlist 可包含 `pipe2`、`read`、`write`、`close`、`dup*`、
`fcntl`、相关 `ioctl`、`poll`、`select` 和 `epoll`。以下内容默认拒绝：

- syzkaller pseudo-syscall；
- namespace、cgroup、sandbox 或设备初始化；
- 未被 StarryOS 和当前 harness 支持的 syscall；
- 无法转换的 resource 关系；
- threaded、repeat 或依赖自然调度的程序；
- 依赖特定设备、后台服务或不可复现文件系统状态的输入。

`syz-prog2c` 可用于诊断或人工比较，但不作为长期导入格式；直接解析程序结构更
容易保留 resource 关系和输出比较边界。

### 交付物与验收标准

- 受限 `.syz` parser/importer 和明确的拒绝原因；
- 原始程序 digest、syzkaller revision 和转换日志记录在 provenance 中；
- 同一输入多次 host record 的 normalized trace 一致后才能进入 corpus；
- 至少一组导入的 pipe 程序能够完成 host/StarryOS 差分和 replay；
- importer 不依赖 KCOV、`syz-manager` 或 `syz-executor`。

syzkaller 的 syscall 描述和程序表示可用于生成、变异、验证和最小化 syscall
序列，适合作为候选输入来源。其 coverage 或 crash 结果不是本项目的 Linux 语义
预期，导入后仍必须重新执行 host record。

## 9. 阶段 5：第二个场景适配器与公共框架

**定位：中期至长期，投入中到大。**

不要只根据 pipe 预先设计通用插件接口。先实现第二个真实使用者，建议选择
`eventfd`：它同样具有 fd 生命周期、read/write、counter 和 poll 状态，但不依赖
pathname、网络环境或自然时间。

pipe 和 eventfd 都能够稳定执行后，再从两个实现中提取公共部分：

| 公共编排层 | 场景适配层 |
|---|---|
| campaign 与 batch 调度 | operation IR 与 codec |
| corpus 存储、选择和最小化 | resource 类型与 mutation |
| artifact、metadata 和 replay | host/guest harness |
| QEMU 注入和运行 | 输出字段与规范化规则 |
| profraw 合并和 region 归因 | coverage 源文件集合 |
| failure 分类和原子保存 | 稳定性与环境前置条件 |

公共层不应出现 `pipe.rs`、pipe operation 或 pipe artifact 的特殊分支。适配器也
不应接管 QEMU 生命周期或重新实现 artifact 原子保存。

### 后续场景顺序

1. `eventfd`：简单计数器和 readiness 状态机。
2. Unix domain `socketpair`：stream/datagram、shutdown、peek 和 ancillary data。
3. 基础 VFS：open/read/write/truncate/rename/unlink。
4. 更复杂的 socket、进程、信号和内存管理场景。

选择新场景时优先考虑 host 与 StarryOS 环境容易对齐、输出可以明确规范化、无需
外部服务且有真实兼容性风险的接口。

### 验收标准

- 第二个适配器先以完整纵向能力证明真实需求；
- 提取公共层后 pipe 和第二个适配器的 failure artifact 均可 replay；
- 每个适配器独立声明 coverage 文件集合和输出规范化规则；
- 新增第三个适配器不需要修改公共层中的场景专用分支。

## 10. 阶段 6：受控并发与阻塞语义

**定位：长期，投入大；按受控调度模型拆分。**

### 10.1 Stage 6.1：eventfd 受控阻塞与唤醒

**状态：已完成（2026-08-04）。**

Stage 6.1 新增单控制线程、单工作线程的 `blocking` 场景模型；它不是同步模型的
格式升级或替代。命令不带 `--model` 时仍选择 `simple-single` 和历史 adapter
`eventfd-v1`，显式 `--model blocking` 才选择独立 adapter
`eventfd-blocking-v1`。前者继续使用 `eventfd.ops` version 1，后者使用 version 2；
replay 根据 artifact 中的 adapter ID 严格分派，两个 campaign 根目录和持久状态
完全隔离。

version 2 固定 actor 0 为 controller、actor 1 为 worker，并增加 `start-read`、
`start-write`、`assert-pending` 和 `join`。每次只允许一个未完成 syscall，validator
静态证明 start 必然阻塞、controller trigger 指向同一 eventfd、`join` 前调用最终
可完成。worker 活跃期间禁止 close、dup、flag 修改、poll 和其他生命周期竞争。
固定 50 ms pending guard 与 5 s 完成期限不进入 canonical 输入或 trace；提前完成
属于语义 mismatch，触发后不完成属于 `schedule-timeout`，线程或时钟故障属于
`harness-error`。宿主候选只有连续三次录制得到逐字节一致 trace 才会被接受。

固定 corpus 覆盖 normal/semaphore eventfd 的空 counter 阻塞读、满 counter 阻塞
写、原 fd 与 alias 唤醒、共享 counter 和 `O_NONBLOCK`、一次释放空间不足、零写不
唤醒及随后正值写入。coverage target 在 eventfd syscall/file 路径之外纳入
`axtask::poll_io` 和 `axpoll::PollSet`。公共 campaign 层仍只处理 opaque canonical
bytes；actor 状态机暂留 eventfd adapter，等待第二个阻塞适配器验证公共边界。

验收结果如下：

| 项目 | 结果 |
|---|---|
| 固定宿主 trace | Linux 5.15.0-186-generic 连续 3 次逐字节一致，57 operations 的 host compare 通过 |
| StarryOS QEMU | blocking eventfd 57、simple eventfd 107、pipe 162 operations 全部匹配并导出 coverage |
| raw syscall 回归 | `syscall-test-eventfd2` 92/92 通过 |
| Python 回归 | common 11、eventfd 36、pipe 187 通过；pipe 另有 1 个环境条件 skip；`py_compile` 通过 |
| Rust 检查 | workspace rustfmt 与 `starry-kernel` 23/23 clippy 通过 |
| blocking campaign | seed 42、3 batches、16 candidates/batch、32 次 QEMU；第 1 批的 876 regions 精确归因到 2 个代表并持久化，含 6 个内置 seed 的总池为 8 entries |
| coverage 最小化 | 419→252 bytes（6 次候选）；另一个 264-byte entry 为 `already-minimal` |

campaign 在 32 次 QEMU 的硬预算内完成全部三个请求 batch；第 2、3 批各留下一个
严格可恢复的 pending attribution job，没有为清空后台任务突破预算。运行中未发现
Linux/Starry mismatch、提前完成、panic、timeout、harness error 或 coverage 缺失，
因此没有修改 StarryOS 生产等待或原子实现。完整设计、兼容边界和非目标见
`book/design/starry-eventfd-blocking-oracle.md`。

### 10.2 Stage 6.2：剩余受控并发模型

**状态：未开始。**

Stage 6.2 明确保留以下工作，不把它们反向塞入 Stage 6.1：

- eventfd 多等待者、多 reader/writer、公平性和唤醒数量；
- pipe 阻塞 read/write、多 writer 下的 `PIPE_BUF` 原子性，以及 EOF/`EPIPE` 状态
  转换；
- comparator 的允许结果集合和跨 actor 不变量，替代对自然调度顺序的比较；
- signal、`EINTR`、`SA_RESTART` 及信号与阻塞 syscall 的受控交错；
- 非零 timeout 的 poll 与 epoll 注册、状态变化、唤醒和超时交错；
- close/lifetime 竞争，以及这些场景所需但 Stage 6.1 明确禁止的资源转换。

pipe 提供第二个真实阻塞实现后，才能从 eventfd 中提取公共 actor/barrier/join
抽象。Stage 6.2 仍须满足：固定场景可稳定重放；watchdog、schedule timeout、
harness failure 与语义 mismatch 分开；宿主重复稳定性达到适配器声明的门槛；
comparator 对每个字段明确采用 exact result、允许结果集合或不变量；不得通过扩大
timeout 或降低生成权重掩盖死锁、丢失唤醒和不稳定场景。

## 11. 阶段 7：持续扩展与优先级管理

后续场景不按 syscall 数量推进，而按以下证据排序：

1. 已知 bug 或与 Linux 的实际 mismatch；
2. StarryOS 实现和 Linux 语义存在明显结构差异；
3. 当前 coverage 显示入口已到达但关键分支长期未覆盖；
4. syzkaller corpus 中重复出现且可转为确定性输入的调用序列；
5. 真实应用依赖但现有测试只有 happy path 的接口。

每个场景适配器维护一份简短目录，登记 operation、resource、关键参数桶、输出
字段、规范化规则、coverage 目标、人工 seed、导入 seed、非目标和已知环境依赖。

## 12. 推荐的近期 PR 切分

前七个 PR 应保持小而可独立验证：

1. `test(pipe-oracle): report generator and corpus effectiveness`
2. `refactor(pipe-oracle): introduce structured scenario IR`
3. `feat(pipe-oracle): add canonical corpus and structured mutations`
4. `test(pipe-oracle): add boundary and invalid-resource scenarios`
5. `feat(pipe-oracle): persist and deduplicate coverage corpus`
6. `feat(pipe-oracle): attribute coverage inputs exactly`
7. `feat(pipe-oracle): minimize attributed coverage inputs`
8. `test(pipe-oracle): expand deterministic fd and boundary scenarios`

阶段 4 的 syzkaller importer 应在这些项目完成后开始。否则导入更多程序仍会受到
弱 mutation、粗粒度归因和不可持久化 corpus 的限制。

## 13. 验证分层

| 层级 | 必须验证的内容 |
|---|---|
| IR/codec 单元测试 | round trip、版本拒绝、canonical digest、malformed 输入 |
| Generator 单元测试 | operation 可达性、resource 不变量、边界参数桶、确定性 |
| Mutation 单元测试 | mutation 有效性、splice、依赖修复、显式非法场景保留 |
| Corpus 单元测试 | 去重、原子保存、版本迁移、归因和中断恢复 |
| Host harness | record/compare 自洽、trace 损坏失败、重复运行稳定性 |
| Orchestrator 测试 | artifact 注入、当前 run profraw、failure 分类和 replay |
| StarryOS QEMU | 实际差分、coverage 提取、新场景的原始失败命令 |

文档、测试和 implementation 应在同一阶段保持同步。新增用户可见命令时更新快速
入口；改变 failure schema 或场景版本时同时更新 replay 验证和兼容策略。

## 14. 阶段决策门槛

- **阶段 0 后：**根据无效变异和重复场景数据确认阶段 1 的具体表示方案。
- **阶段 2 后：**比较单位 QEMU 时间的 region 收益，决定 batch 归因和调度策略
  是否需要继续优化。
- **阶段 3.1 后：**检查同步 pipe 语义和 coverage 缺口，再选择 flags、readiness
  或 syzkaller importer 的优先级。
- **阶段 4 后：**根据导入场景的接受率和新增 coverage，决定是否扩展 `.syz`
  allowlist。
- **阶段 5 前：**必须已有第二个真实适配器，不能只为预想的未来调用方抽象。
- **阶段 6 前：**同步场景应已具备稳定 corpus、归因和最小化能力。

## 15. 兼容、回滚与长期约束

- failure artifact 和持久 corpus 必须带 schema/generator 版本。
- 已保存 failure 要么继续 replay，要么给出显式迁移工具或清楚的拒绝原因。
- 每个阶段都应可以独立回滚，不影响生产 StarryOS 的非测试构建。
- 新 coverage 反馈算法可以回滚到 seed-only campaign，人工 regression corpus 不得
  因调度策略改变而丢失。
- syzkaller 导入结果必须保留来源，不把外部 corpus 静默变成本项目人工场景。
- generator 和 minimizer 始终只描述输入及资源关系；预期语义始终来自 host
  Linux 实际执行。

## 参考资料

- [Syzkaller syscall descriptions](https://github.com/google/syzkaller/blob/master/docs/syscall_descriptions.md)
- [Syzkaller coverage](https://github.com/google/syzkaller/blob/master/docs/coverage.md)
- [Linux KCOV documentation](https://docs.kernel.org/dev-tools/kcov.html)
- [StarryOS 开发指南](/docs/development/starryos)
