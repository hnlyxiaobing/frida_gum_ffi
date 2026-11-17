# frida_gum_ffi 测试系统设计（第一性原理）

> 建立：2026-11-16 ｜ 状态：**W1–W6 已交付（2026-11-16），W7 选项 A 维持冻结（真实面 SKIPPED）** ｜ 适用仓库：本仓库（独立自包含）
> 配套文档：[2026-11-16-gated-instrumentation-dev-plan.md](2026-11-16-gated-instrumentation-dev-plan.md)（`T-W*-*` 验收 ID 一一对应；B# 事实行出自该文档 §0，B26–B28 实施补遗见其 §10）
> 开发前基线：2026-11-16 五门禁实跑全绿，`moon test` 12/12（黑盒 2 + 白盒 10），零 `#skip`，快照零漂移。
> 交付后终态：2026-11-16 五门禁实跑全绿，`moon test` **21/21**（黑盒 5 + 白盒 16），零 `#skip`，快照累计 **+5 行纯加法**（零删改）；错误簿记 **13/13**；变异自检三类缺陷全红、SHA-256 还原一致后复绿 21/21。交付明细与证据见开发文档 §10。

## 1. 第一性原理：本库的正确性是什么

本库的数学形态：一个**门禁化的进程内插桩契约函数族**——
`(符号/地址, 回调对) → HookId | GumError`；`(地址, 长度) → 字节 | GumError`；`()` → 值数组（模块/区间）；被钩线程事件流 → owner 线程上下文快照序列。后端当前为确定性 stub 世界（3 符号/2 模块/4 区间/4096B 模拟内存），真实后端被 G1/G2 门禁锁定。

正确性不可约简为以下断言（FFI 模块在通用六条上裁剪 A6、增补 A7/A8），每条必须有测试层承载：

| # | 断言 | 含义 | 反例（测试必须抓住） |
|---|---|---|---|
| A1 | 寻址忠实 | 内存读写字节、记录解析字段（base/end/prot/args/ret/depth/thread_id）与 stub 序列化格式逐字节同构 | 小端解析偏移错位；`Bytes::to_unchecked_string` 式 UTF-16 重解释；read 回环值不符 |
| A2 | 完整性 fail-closed | 门禁未过必显式报错（LicenseReviewRequired/PtraceDenied）；非法地址/回绕/负长度必拒；未校验≠通过 | 门禁静默放行；UINT64_MAX+len 回绕绕过边界检查；失败 init 消耗生命周期 |
| A3 | 边界纯净 | 只输出值类型快照（InvocationContext 无寄存器原始指针）；不产出下游语义结论；不做符号解析/扫描 | 上下文携带跨线程悬挂引用；库内做 W^X 裁决 |
| A4 | 输入安全 | 任意畸形记录/参数不 panic、不越界写；缓冲容量预检在 memcpy 之前；内存有界 | parse_context_record 对截断记录 panic；dst 容量 < length 仍 memcpy |
| A5 | 契约稳定 | mbti 快照纯加法；status 0–9 映射不变（含 B17 不对称、B20 point 容错冻结口径）；demo 退出码登记内变更 | 旧函数语义漂移；新增错误变体；快照意外 diff |
| A6 | 平台等价（裁剪） | 本模块 preferred_target=native 无 wasm 面；等价口径改为 **Win32（SRWLOCK/CreateThread）与 POSIX（pthread_mutex/pthread_create）分支行为等价** | POSIX 线程 id 硬编码致并发断言失效（历史已修，须回归守护） |
| A7 | 句柄生命周期配平（FFI 增补） | `#owned` 闭包 set/detach/close 成对 decref；rc 触发前后不变；不二次释放；失败路径也释放 | detach 后 rc 泄漏；重复 destroy 二次 decref；attach 失败闭包悬挂 |
| A8 | 线程收敛（FFI 增补，E1） | 被钩线程绝不执行 MoonBit 闭包；闭包执行线程恒等于 owner 线程；队列满不阻塞被钩线程；滞留事件安全丢弃 | drain 在入队线程执行闭包；队列满阻塞；detach 后派发已释放闭包 |

设计推论：A1 → 回环/逐字段黄金断言；A2 → 门禁白盒 + 边界值矩阵 + 错误簿记；A3/A5 → 快照门禁 + 冻结口径钉住用例；A4 → 截断扫描 + 容量预检时序断言；A6 → CI 双平台 job（POSIX 当前 [仍需实测]）；A7 → rc 观测缝断言；A8 → 真实 OS 线程并发缝 + 执行线程 id 断言。

## 2. 测试分层

```text
L0 单元与程序化 fixture（每个 pub fn 行为样例；交付后：黑盒 5 + 白盒 16）
L1 性质与变异（变形律/截断扫描/边界值/变异自检；交付后：回绕/容量/并发/重入/竞态 + 截断扫描/边界矩阵/P1/P3 律/变异自检已建 W6）
L2 受控黄金差分（stub 世界即确定性黄金源：模块表/区间表/内存初值逐字段断言；现状：黑盒全链路部分承载）
L3 外部 oracle 差分（真实 frida-gum devkit/GumJS 行为对照；G1/G2 门禁锁定 → 全部显式 SKIPPED，W7 解冻后启用）
L4 CLI 场景 E2E（cmd/main demo 成功/失败路径 + 退出码矩阵；交付后：成功 exit 0 / 失败 exit 1 均实跑，`--selftest-fail` 自测入口 W4）
L5 元契约门禁（快照/错误簿记/平台等价/变异自检/引用实存性；交付后：快照/簿记 13/13/引用扫描/变异自检已启用，平台等价仍待实测 B23）
R  真实样本本地 runner（仓库外 .so/进程样本 + SHA-256 门禁 + 显式 SKIPPED；门禁未过，零入库）
```

断言×层承载表：

| 断言 | 主承载层 | 辅助层 |
|---|---|---|
| A1 寻址忠实 | L0（回环/上下文逐字段） | L2（stub 黄金表）、L1（截断扫描保真侧） |
| A2 fail-closed | L0（门禁/非法地址白盒） | L1（边界值矩阵）、L5（错误簿记） |
| A3 边界纯净 | L5（快照门禁） | L0（值类型断言） |
| A4 输入安全 | L1（截断扫描/容量预检） | L0（负 length/畸形参数） |
| A5 契约稳定 | L5（快照 + 冻结口径钉住） | L0（status 映射用例） |
| A6 平台等价 | L5（CI ubuntu job，待实测） | L0（Windows 本机等价基线） |
| A7 生命周期配平 | L0（rc/live 计数缝断言） | L1（rc 配平律） |
| A8 线程收敛 | L0（真实 OS 线程并发缝） | L1（FIFO 律）、L5（变异自检：跨线程执行缺陷必红） |

## 3. fixture 体系

| 类 | 形态 | 入库 | 许可 | 现状 |
|---|---|---|---|---|
| F-A 程序化构造 | 测试代码内字节/记录 builder（上下文记录 50 字节布局、模块/区间记录） | 是 | 随仓库 Apache-2.0 | 已交付（W6）：`w6_ctx_record`/`w6_push_u32_le`/`w6_push_u64_le` 直接字节 builder；上下文经 stub 序列化间接构造路径并存 |
| F-B 受控文件 fixture | tests/fixtures/* | — | — | **本模块无 fixtures 目录**（实测）；stub 世界常量即黄金源，无死资产风险 |
| F-C 生成器资产 | stub 世界确定性常量（内存初值 i&0xFF、3 符号/2 模块/4 区间表） | 是（C 源码） | 自产 | 已实现；世界自洽性（模块基址 ∈ 区间）有黑盒断言 |
| F-D 真实第三方样本 | 真实 .so/devkit/进程样本 | **否（红线）** | wxWindows/不明 | 零入库；G1/G2 门禁锁定；R runner 预留 |

红线：F-D 永不入库；stub 世界常量变更须同步黄金断言 + CHANGELOG（防「改世界假绿」）。
builder 能力清单（W6 已落地）：上下文记录构造维度 = point（1/2/畸形 0/3/255）× argc（2/3/0xFFFFFFFF 负值）× has_ret（0/1）× 全前缀截断（0..49 字节），已用例化；depth 极大值与模块/区间记录 name_len/path_len 边界 builder 未用例化，列为后续扩展（非本轮缺口）。

## 4. L1 性质与变异

- **变形律 P#**：
  - P1 init-close 重置律：`close` 后 re-`init`，模拟内存逐字节复原初值（i&0xFF）、hook/闭包/胶水/队列计数全零（**W6 已用例化**，含内存逐字节复原断言）。
  - P2 读写回环律：`write(addr, data)` 后 `read(addr, len)` 逐字节等于 data（合法域内任意 addr/len；既有黑盒 4 字节样例 + W6 边界矩阵承载）。
  - P3 marshal FIFO 律：入队序列经任意分批 pump 后，派发序列保持 FIFO；(thread_index, seq) 恰好一次（既有并发用例承载 + **W6 分批 2+3+1 逐项一致用例化**）。
  - P4 rc 配平律：attach 后 rc=1；任意次触发 rc 不变；detach/close 后 live_closures=0（现有白盒已承载）。
  - P5 门禁幂等律：gate 置位→init 必拒→清位→init 必成，失败 init 不消耗生命周期（现有白盒已承载）。
  - **P6 防火墙律（固化）**：任一 W# 新函数合入后，旧 API 在全部既有用例/语料上输出逐字节不变，旧用例零改动全绿；新通道（attach_address/pending_callbacks 等）不改变旧符号 attach/测试缝语义。
- **位翻转/字段翻转口径**：stub 记录无 checksum——翻转后可能仍是合法输入，断言口径为「要么返回声明的错误类型/None，要么输出与翻转前不同」，**不得断言全部必错**（防假绿）。
- **边界值矩阵**（W6 已交付）：内存 base-1/base+4096/UINT64_MAX 非法域 + len 0/1/4096/4097/负 + 跨末尾读拒绝（黑盒）；队列满 256 + 溢出 dropped 精确计数（白盒 W5/W6）；argc 2/3/负（白盒 W6）。hook 表第 9 个拒绝、pump max_events 极大值未单列用例（既有负值/0 用例已覆盖拒绝路径），列为后续扩展。
- **截断扫描**（W6 已交付）：50 字节上下文记录全部真前缀（0..49）一律 None 零 panic + has_ret=1 返回值截断窗口 + 42/41 字节无返回值边界；扫描中发现两处潜在越界（B27），已 fail-closed 加固并登记 CHANGELOG。模块/区间记录截断扫描未建（stub 侧长度恒受控），列为后续扩展。
- **变异语料**：固定种子大规模变异体（≥1000/轮）未实施，列为后续扩展；本轮以定向变异自检（下条）承载缺陷注入验证。
- **变异自检**（W6 已交付，L5 联动）：实际注入 3 类缺陷并全部变红——① 删除内存末尾越界守卫（原设计「加法形式回绕检查」经核实与减法式数学等价、属无效变异，B28，已替换；黑盒越界读进程崩溃变红）；② dropped 计数恒 0（11 用例败）；③ 被钩线程经 fire_marshal 缝直接执行闭包（E1「只入队」断言变红，11 用例败；原设计注入 spawn 路径不可观测，已改缝）。备份 SHA-256 还原一致后复绿 21/21；命令+日期+证据表登记于开发文档 §10。

## 5. L3 oracle 矩阵 + R runner

| oracle | 差分对象 | 规范化口径 |
|---|---|---|
| 真实 frida-gum devkit（GumJS Interceptor/Memory/Process） | 仅比本库声明输出的值字段（hook 成功/失败、上下文字段、模块/区间值） | 不比 Stalker/扫描等界外能力；地址/线程 id 规范化为相对序 |
| G2 替代库（ShadowHook 等，若裁决选项 B） | hook 安装/卸载结果与原函数调用保真 | 同上；listener 语义差异显式登记 |

纪律：**G1/G2 门禁未过，L3 全部显式 SKIPPED + 原因（退出码 78 口径），不得写成通过**；oracle 版本随结果登记；devkit 不获取不落盘（红线）。
R runner（W7 解冻后）：样本仓库外路径 + 登记 SHA-256 → 哈希不符拒绝执行 → 规范化差分 → 报告「本地已差分+哈希+日期」；入库 `#skip` 用例保留不删，真实结论永不进入通过计数。

## 6. 覆盖矩阵与错误簿记

### 6.1 能力×场景×安全 覆盖矩阵

| ID | 能力/场景 | L0 | L1 | L2 | L3 | L4 | 现状（交付后） | 缺口→W# |
|---|---|---|---|---|---|---|---|---|
| F1 | init/close 生命周期 | ✅ | ✅ | ✅ | SKIPPED | ✅ | B1/B25 + W6 P1 重置律（含内存逐字节复原） | 无（已交付） |
| F2 | 符号 attach/detach | ✅ | 部分 | ✅ | SKIPPED | ✅ | B1 + W3 地址面 attach_address 全链路；hook 表第 9 个拒绝未单列（后续扩展） | 无（本轮已交付） |
| F3 | 回调桥与上下文 | ✅ | ✅ | ✅ | SKIPPED | — | B7 + W6 截断扫描/畸形 builder（B27 加固后零 panic） | 无（已交付） |
| F4 | E1 marshal pump | ✅ | ✅ | — | SKIPPED | — | B6 + W5 pending/dropped 可观察查询 + W6 FIFO 分批律 | 无（已交付） |
| F5 | memory_read/write | ✅ | ✅ | ✅ | SKIPPED | ✅ | B9/B17 + W2 不对称双断言 + W6 边界矩阵 | 无（已交付） |
| F6 | modules 枚举 | ✅ | ✅ | ✅ | SKIPPED | ✅ | B1 + W2 force_enum 错误路径显式用例 | 无（已交付） |
| F7 | regions 枚举 | ✅ | ✅ | ✅ | SKIPPED | ✅ | B1 + W2 双路径（复用变体） | 无（已交付） |
| F8 | 门禁信号 | ✅ | ✅ | — | SKIPPED | — | B8：license/ptrace 双信号+幂等 | 无（维持） |
| F9 | trait 契约 | ✅ | — | — | SKIPPED | — | W3 已交付：3 个 impl + trait 对象派发逐字节等价用例 | 无（已交付） |
| F10 | listener 胶水预留 | ✅ | 部分 | — | SKIPPED | — | B4：只入队/配平/重复销毁/close 释放有用例 | 无（真实胶水属 W7） |
| S1 | demo 端到端成功 | — | — | — | — | ✅ | 实跑 exit 0，输出契约不变 | 无（已交付） |
| S2 | demo 失败可观测 | — | — | — | — | ✅ | W4 已交付：真实失败路径 exit 1 实跑 + `--selftest-fail` 自测 | 无（已交付） |
| C1 | 地址回绕/越界拒绝 | ✅ | ✅ | — | — | — | B9 + W6 全边界矩阵（含 UINT64_MAX/跨末尾） | 无（已交付） |
| C2 | 缓冲容量预检时序 | ✅ | — | — | — | — | 白盒「shim 缓冲容量校验」：预检在 memcpy 前（mb_buf_ok 先行） | 无（维持） |
| C3 | 生命周期不泄不二次释放 | ✅ | ✅ | — | — | — | B7/B25：rc/live 计数断言 | 无（维持） |
| C4 | 线程收敛（被钩线程零闭包） | ✅ | ✅ | — | — | — | B6 + W6 变异自检③必红复绿 | 无（已交付） |
| C5 | **防火墙（新函数不改旧语义）** | ✅ | ✅ | — | — | — | W1–W6 逐包旧 12 用例零改动全绿；快照累计 +5 行零删改 | 无（常驻 DoD） |
| C6 | **许可红线（F-D 零入库）** | — | — | — | — | — | B24：零第三方二进制；W1 引用扫描清零 | L5 引用/资产扫描常驻 |
| C7 | POSIX/CI 平台等价 | — | — | — | — | — | B23：[仍需实测] | W7 M7-3 补实跑；CI job 常驻 |

### 6.2 错误变体触发簿记（13/13 强制）

| 变体 | 触发 fixture（交付后，显式断言变体名） | 备注 |
|---|---|---|
| NotInitialized | 黑盒全链路（close 后 7 类操作）+ pump 关闭后 + W5 查询关闭后 | 9 处 |
| AlreadyInitialized | 黑盒重复 init | 维持 |
| DevkitNotFound | W2：force_init_status(8) → init 兜底分支（消息含 '8'） | 已补齐 |
| AttachFailed | 黑盒重复挂接（2 处）+ W3 重复地址挂接 | 已扩展 |
| DetachFailed | 黑盒重复 detach | 维持 |
| UnknownSymbol | 黑盒 no_such_symbol + W3 未知地址（十进制地址串 "2457"） | 已扩展 |
| InvalidAddress | 黑盒 0x99999999 read + W6 边界矩阵全非法域 | 已扩展 |
| MemoryReadFailed | 黑盒负 length + 白盒容量 | 维持 |
| MemoryWriteFailed | W2：非法地址 write（钉住 B17 不对称双断言） | 已补齐 |
| ModuleEnumerateFailed | W2：force_enum_status(8) → modules/regions 双路径 + 世界复位断言 | 已补齐 |
| CallbackBridgeFailed | pump max_events 0/-1（黑盒+白盒）+ W5 查询非 -5 负值路径 | 已扩展 |
| PtraceDenied | 白盒 gate 2 置位 | 维持 |
| LicenseReviewRequired | 白盒 gate 1 置位（W1 后消息指向 README §2/§6，已登记 CHANGELOG 例外） | 维持 |

交付后 **13/13**（2026-11-16 逐变体 grep 实测全部 ≥1）。门禁：§6.2 与测试代码双向 grep 核对，缺一即红（L5）。

### 6.3 恒等式断言（语义契约，全路径成立）

- `GumState` 恒 `Initialized`（唯一构造点 init 成功；死分支不补齐，B25）。
- `hook_count` 恒 0（死字段冻结口径，B16；任何包不得悄悄改变，改则走四件例外）。
- `memory_write` 非法地址 ⇒ `MemoryWriteFailed`（非 InvalidAddress，B17 冻结）；`memory_read` 非法地址 ⇒ `InvalidAddress`。
- 上下文记录 point 字节 ≠1 ⇒ `PointCut::Leave`（B20 容错冻结口径，W6 畸形 point 0/3/255 用例钉住）。
- 上下文记录截断/畸形 argc ⇒ `None` 零 panic（W6 fail-closed 加固后口径，B27；生产路径 stub 恒 50 字节，公开 API 行为不变）。
- Enter 事件 `return_value` 恒 None；Leave 事件恒 Some（stub 世界口径，mb_fill_record）。
- rc 恒等式：attach 后 rc=1 ∧ 触发任意次 rc=1 ∧ detach/close 后 live_closures=0。
- 线程恒等式：∀ 派发事件，exec_thread = owner_thread（A8）。
- **防火墙恒等式：任一 W# 合入后，旧函数全部既有用例零改动全绿，旧 API 输出逐字节不变。**

### 6.4 #skip 清单（显式单列，永不计入通过）

| 用例 | 位置 | 原因 |
|---|---|---|
| （无） | — | **当前基线零 #skip（2026-11-16 全仓库 grep 实测）** |

计数口径：交付后 21 条声明 − 0 条 #skip = 21 执行，**21/21 通过**（黑盒 5 + 白盒 16，2026-11-16 实测）；开发前基线 12/12 保留于文首。未来 L3/R 层 SKIPPED 用例在此单列，退出码 78 口径，永不计入通过。

### 6.5 验收 ID 双向追溯表

| T-W*-* | W#（开发文档） | 矩阵缺口行 | 断言/层 | 状态（2026-11-16） |
|---|---|---|---|---|
| T-W1-1 引用实存性扫描零命中 | W1 | C6/F1-F10 注释面 | A5/L5 | 已交付 |
| T-W1-2 README 索引↔mbti 逐条一致 | W1 | B13 | A5/L5 | 已交付 |
| T-W1-3 五门禁+快照 diff=0 | W1 | C5 | A5/L5 | 已交付 |
| T-W1-4 旧用例零改动全绿 | W1 | C5 | A5/L0 | 已交付（消息文本例外已登记） |
| T-W2-1 DevkitNotFound 显式用例 | W2 | §6.2 缺口 | A2/L0 | 已交付 |
| T-W2-2 MemoryWriteFailed+不对称双断言 | W2 | F5/§6.2 | A2/A5/L0 | 已交付 |
| T-W2-3 ModuleEnumerateFailed 双路径 | W2 | F6/F7/§6.2 | A2/L0 | 已交付 |
| T-W2-4 簿记 13/13 双向核对 | W2 | §6.2 | A5/L5 | 已交付（grep 实测） |
| T-W2-5 五门禁+防火墙 | W2 | C5 | A5/L5 | 已交付 |
| T-W3-1 地址 attach 全链路 | W3（已裁决 A） | F9 | A1/L0 | 已交付 |
| T-W3-2 trait 派发等价 | W3 | F9 | A1/A5/L0 | 已交付（逐字节等价） |
| T-W3-3 未知/重复地址错误显式断言 | W3 | §6.2 | A2/L0 | 已交付 |
| T-W3-4 快照纯加法+CHANGELOG | W3 | C5 | A5/L5 | 已交付（+3 行，含 Gum::read/impl） |
| T-W3-5 防火墙旧 attach 零改动 | W3 | C5 | A5/L0 | 已交付 |
| T-W4-1 demo 成功退出码 0+输出逐字节 | W4 | S1 | A5/L4 | 已交付（实跑） |
| T-W4-2 demo 失败退出码 1 实跑 | W4 | S2 | A2/L4 | 已交付（真实失败路径，B26） |
| T-W4-3 五门禁+cmd 快照 diff=0 | W4 | C5 | A5/L5 | 已交付 |
| T-W5-1 pending 精确一致 | W5 | F4 | A1/L0 | 已交付 |
| T-W5-2 dropped 增量精确一致 | W5 | F4 | A1/A8/L0 | 已交付 |
| T-W5-3 close 后 NotInitialized | W5 | F4/§6.2 | A2/L0 | 已交付 |
| T-W5-4 快照纯加法+CHANGELOG | W5 | C5 | A5/L5 | 已交付（+2 行） |
| T-W5-5 防火墙旧测试缝零改动 | W5 | C5 | A5/L0 | 已交付 |
| T-W6-1 截断扫描全前缀零 panic | W6 | F3/C1 | A4/L1 | 已交付（含 B27 加固） |
| T-W6-2 边界值矩阵全断言 | W6 | C1/F5 | A2/A4/L1 | 已交付 |
| T-W6-3 五条变形律用例 | W6 | F1/F4/C3 | A1/A7/A8/L1 | 已交付（P1/P3 新用例化，P2/P4/P5 既有承载） |
| T-W6-4 变异自检 3 类必红复绿 | W6 | C4 | A2/A8/L5 | 已交付（M1 替换后三红，B28） |
| T-W7-1..4 真实对接里程碑 | W7（已裁决 A：维持冻结） | F2-F7 真实面/C7 | R/L3（SKIPPED 纪律） | 未启动（SKIPPED，不得预写通过） |

## 7. L4 CLI 场景 E2E

| 场景 | 命令序列 | 断言要点（退出码+输出） |
|---|---|---|
| demo 成功 | `moon run cmd/main` | exit 0；输出含 module×2、regions: 4、read 4 bytes、"gum lifecycle ok"、"desktop stub demo ok"（2026-11-16 实跑基线） |
| demo 失败（W4 已交付） | `moon run cmd/main -- --selftest-fail`（真实失败路径：非法地址读，B26：GumError 只读不可伪造） | exit 1；输出 "demo failed"；**失败不得 exit 0（已修复，实跑验证）** |
| 复验序列 | `moon clean; moon check --deny-warn; moon build; moon test; moon fmt --check; moon info; git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti` | 每步 exit 0；测试计数 21（交付后）；快照纯加法审阅（合入前 diff 应为已登记的 +5 行，合入后零漂移） |

记录行/输出契约冻结口径：demo 成功输出行序列为既有契约（W4 未追加新演示行，成功路径输出逐字节不变）；退出码矩阵 0（成功）/1（失败）已逐例实跑断言。本模块无发布 CLI、无落盘产物，无写盘逃逸面。

## 8. L5 元契约门禁

1. **快照门禁**：`moon info` + `git diff --exit-code`（根 + cmd/main 两处；纯加法审阅）——已在 ci.yml Gate 5/5。
2. **平台等价**：CI ubuntu job 跑同一测试套（POSIX 分支）；当前 [仍需实测]（B23），通过前结论只标「Windows 本地等价」。
3. **错误簿记门禁**：§6.2 与测试代码双向 grep 核对（13 变体各 ≥1 显式断言），缺一即红（**W2 后已启用，13/13 实测**）。
4. **变异自检**：注入 §4 三类缺陷，套件必须变红后还原复绿；登记命令+日期（**W6 已执行，证据表见开发文档 §10**）。
5. **计数纪律**：#skip/SKIPPED 不计通过；测试过滤串以 `*` 结尾防空转假绿；计数一律实跑重测。
6. **引用实存性扫描**：注释/帮助文本/ci.yml/脚本引用的仓库内路径全部实存（**W1 已清零悬空 docs/* 引用，常驻扫描**；B26–B28 等历史描述中提及已删文件名属事实记录，允许）；README API 索引与快照逐条一致（含 pub type/trait/alias/suberror，W3/W5 新增 5 行已同步）。
7. **许可资产扫描**：仓库内零第三方二进制/devkit；stub 为唯一 C 资产且自产（C6 常驻）。

## 9. CI 集成与执行入口

五门禁不变（ci.yml five-gates job，工具链版本断言强制）；L0/L1/L2 挂 `moon test`；L3/L4 失败注入/R/平台等价/变异自检为脚本层可选 job，缺失显式 SKIPPED。`.githooks/pre-commit` 仅 `moon check`（B22），合入判定以五门禁为准，不以 hook 为准。
复验命令（本仓库自包含）：`moon clean; moon check --deny-warn; moon build; moon test; moon fmt --check; moon info; git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti`。

## 10. 维护规则与验收清单

1. 新增 pub API ⇒ 同提交附 L0 样例 + L1 性质 + 矩阵/簿记更新；无测试不合入。
2. 新增解析路径 ⇒ 进截断扫描 fixture 集（builder 维度同步扩展）。
3. stub 世界常量变更 ⇒ 黄金断言 + CHANGELOG 同提交更新（防改世界假绿）。
4. 每包合入 ⇒ 开发文档 DoD 勾选 + 矩阵现状刷新 + CHANGELOG 测试增量。
5. 「通过」须可复验：命令 + 日期 + 计数；SKIPPED 永远单列。

落地验收（逐层勾选，2026-11-16 交付后）：
- [x] L0 基线 12/12 → 交付后 **21/21**（黑盒 5 + 白盒 16，实测）
- [x] L1 截断扫描/边界矩阵/变形律（P1/P3）/变异自检（W6 已交付；大规模变异语料列为后续扩展）
- [x] L2 stub 黄金表承载（黑盒全链路 + W6 逐字段保真断言）
- [ ] L3 oracle（G1/G2 锁定，全部 SKIPPED；W7 选项 A 维持冻结，不得预写通过）
- [x] L4 失败路径退出码（W4 已交付，exit 0/1 实跑）
- [x] L5 簿记 13/13/引用扫描/变异门禁（W1/W2/W6 已启用；平台等价仍待实测 B23）
- [ ] R runner（W7 裁决后；F-D 零入库红线常驻）