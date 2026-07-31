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
- batch 获得新 coverage 时，当前无法确定由 batch 中哪个输入贡献。
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

### 6.1 持久化和去重

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

常规路径继续使用 batch 降低 QEMU 次数。只有 batch 获得新 region 时，才对子集
进行重放：

1. 保存该 batch 的候选集合和 region 差异；
2. 二分或逐项重放候选；
3. 找到能覆盖目标 region 的最小输入集合；
4. 只将实际贡献者加入持久 corpus。

归因不能使用后续不同构建产生的 coverage 与原 batch 混合。用于比较的 profraw
必须来自相同 instrumented StarryOS ELF。

归因结果记录每个 batch 的新增 region，以及每个真实 corpus entry 对这些 region
的具体贡献，作为后续评估单位 QEMU 时间收益的基础。

### 6.3 场景最小化

对 mismatch 和获得新 region 的场景分别使用对应谓词最小化：

- 删除整个 scenario；
- 删除 operation 或连续片段；
- 替换为更简单的资源关系；
- 将参数逐步缩到边界值；
- 删除不影响目标 mismatch 或 region 的初始化操作。

mismatch 最小化必须保持相同差异类别和关键操作；coverage 最小化必须保持指定
region 集合，不能仅要求“仍有任意 coverage”。

### 验收标准

- campaign 重启后能够继续使用已保存 corpus；
- raw 输入不同但 canonical 场景相同的 entry 只保存一次；
- 每个新 region 能追溯到至少一个具体场景；
- 最小化前后的 predicate 有自动化测试；
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

中期增加：

- `pipe2` 的 `0`、`O_NONBLOCK`、`O_CLOEXEC` 和非法 flags；
- `F_GETFL`、`F_SETFL` 动态切换 `O_NONBLOCK`；
- `F_GETFD` 和 `FD_CLOEXEC`；
- `dup2`、`dup3` 和目标 fd 覆盖；
- `readv`、`writev` 的空 iovec、跨 iovec 和部分完成；
- 一次 `poll` 多个 fd、重复 fd 和负 fd。

阻塞 flag 组合必须使用不会自然挂起的操作序列，或由明确 watchdog 判定基础设施
失败；不能用宽松 timeout 把不确定结果当作语义通过。

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

**定位：长期，投入大；仅在同步场景收益趋于稳定后启动。**

为场景格式增加 actor、barrier、join 和 watchdog，而不是直接生成任意线程。典型
结构为：

```text
actor reader:
  barrier ready
  blocking read

actor writer:
  wait ready
  write
  close
```

目标场景包括：

- blocking read/write 的唤醒；
- 多 reader 和多 writer；
- 多 writer 下的 `PIPE_BUF` 原子性；
- close 与阻塞操作竞争；
- signal、`EINTR` 和 `SA_RESTART`；
- poll/epoll 与状态变化交错。

并发比较不能要求 host 与 StarryOS 产生相同调度顺序。比较对象应是允许结果集合
和不变量，例如数据不丢失、不重复、小写入不交错、所有 actor 最终退出，以及
wakeup、EOF、`EPIPE` 的合法状态转换。

### 验收标准

- actor 和 barrier 调度可由固定场景稳定重放；
- watchdog 失败与语义 mismatch 分开分类；
- 候选输入通过配置数量的重复 host 稳定性检查后才进入 corpus；
- comparator 明确记录比较的是 exact result、允许结果集合还是不变量；
- 不以扩大 timeout 掩盖死锁、丢失唤醒或不稳定场景。

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
6. `feat(pipe-oracle): attribute and minimize coverage inputs`
7. `test(pipe-oracle): expand deterministic fd and boundary scenarios`

阶段 4 的 syzkaller importer 应在这七项完成后开始。否则导入更多程序仍会受到
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
