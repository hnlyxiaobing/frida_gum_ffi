# G2-ALTERNATIVES-EVAL.md — MIT/Apache 免 root 替代方案评估（G2 设计侧，仅据文档）

> 日期：**2026-11-09**（R4 轮）｜ 范围：**设计侧评估**——许可、能力面、与本项目需求的差距、取舍论证。
> **红线声明**：G2 的「真实 devkit 链接 + 真实 hook 验证」在 G1→G2 通过前一律不做（ADR-0006 / D8-4）；本文**未链接任何真实二进制、未做任何设备验证**，全部能力/许可陈述标 `[仅据文档]`（URL + 摘录 + 访问日期 2026-11-09），结论性选型标 `[仍需实测]`。
> 关联：`DECISIONS.md` §1（G1/G2 双门禁）、`LICENSE-AUDIT-G1.md`（G1 许可清单）、`E1-CALLBACK-THREAD-SAFETY.md`（回调线程安全）、`../../docs/adr/ADR-0006-frida-deferred-with-gate.md`（更小替代决策）。

---

## 0. 本项目需求基线（源自申报书 §4/§5、DECISIONS §4）

| # | 需求 | 来源 |
|---|---|---|
| N1 | 函数级 hook：按「库名 + 符号名」或地址挂接，回调拿得到**参数与返回值**（`InvocationContext.args/return_value`） | 申报书场景 1；`Gum::attach` 契约 |
| N2 | Enter/Leave 两次截断、可重入深度观测（`depth`） | `InvocationContext` 值类型 |
| N3 | 回调线程安全：回调不在被钩线程执行 MoonBit 闭包（E1 marshal） | ADR-0009 决策 4 |
| N4 | 进程内存读写 + 模块/内存区间枚举 | `memory_read/write`、`modules`、`regions` |
| N5 | 稳定 C ABI 供 MoonBit FFI 封装；桌面（Linux x86-64 / Windows）与 Android（arm64）目标 | `preferred_target=native`；DESIGN §7 |
| N6 | 显式错误模型（许可门禁可观察、权限拒绝可观察） | `GumError`、DECISIONS §2 |
| 暂不需要 | Stalker 指令跟踪、Java 方法 hook、断点管理、符号解析（DECISIONS §4 明示非目标） | DECISIONS §4 |

## 1. 替代方案逐个评估

### 1.1 ShadowHook（bytedance/android-inline-hook）

- **许可**：MIT `[仅据文档]`——[LICENSE](https://raw.githubusercontent.com/bytedance/android-inline-hook/main/LICENSE)："MIT License Copyright (c) 2021-2026 ByteDance Inc. Permission is hereby granted, free of charge…"；README 尾注第三方：queue.h（BSD-3）、tree.h（BSD-2）、linux-syscall-support（BSD-3）、xDL（MIT）——分发须附各自声明。
- **能力面** `[仅据文档]`（[README](https://raw.githubusercontent.com/bytedance/android-inline-hook/main/README.md)）：
  - **inline hook**（整函数替换：用户写 proxy 函数、内调原函数）+ **intercept**（指令级，读写寄存器，"similar to the breakpoint debugging"）；
  - hook/intercept 目标可按「地址」或「库名 + 函数名」指定；自动覆盖新加载 ELF；proxy 递归/环路自动防护；
  - 架构 **armeabi-v7a / arm64-v8a**；Android **4.1–17（API 16–37）**；免 root（进程内库）；
  - CFI/FP unwind 兼容；Prefab/Maven 分发；hook 记录导出。
- **回调模型**：proxy 函数**在被钩线程执行**（"when the hooked function is executed, the proxy function will be executed first"）——**与 gum 相同的线程语义**，E1 marshal 照样必需。
- **差距 vs N1/N2**：无 `GumInvocationListener` 等价物——**没有**「按符号挂一个通用 listener 就拿 args/retval/depth」的语义；proxy 需按目标函数签名逐个书写（类型化 trampoline）。要复刻 `InvocationContext`，须自研按 ABI 提取参数的 trampoline 层（arm64 x0-x7/x8、栈参数等）或用 intercept 读寄存器 `[推断]`，C 胶水量显著上升。
- **平台差距 vs N5**：**仅 Android**，桌面 Linux/Windows 不可用。

### 1.2 ByteHook / bhook（bytedance/bhook）

- **许可**：MIT `[仅据文档]`——[LICENSE](https://raw.githubusercontent.com/bytedance/bhook/main/LICENSE)："MIT License Copyright (c) 2020-2026 ByteDance, Inc."；第三方 queue.h（BSD-3）、linux-syscall-support（BSD-3）。
- **能力面** `[仅据文档]`（[README](https://raw.githubusercontent.com/bytedance/bhook/main/README.md)）：
  - **PLT hook**（"an Android PLT hook library"）：hook 单个/部分/全部 caller 动态库的 PLT/GOT 引用；同函数多 hook 不冲突；自动覆盖新加载库；`BYTEHOOK_CALL_PREV` 调原函数；
  - 架构 **armeabi-v7a / arm64-v8a / x86 / x86_64**；Android **4.1–17（API 16–37）**；免 root；unwind 兼容；Prefab/Maven。
- **差距**：PLT hook 只覆盖**跨 so 的导入调用**，进程内直调/内部函数 hook 不了 `[推断]`（PLT 语义决定）；同样无 listener 语义、proxy 自写；仅 Android。

### 1.3 xHook（bytedance/xhook）

- **许可/文档**：**上游仓库当前不可达**——`https://api.github.com/repos/bytedance/xhook` 与 `raw.githubusercontent.com/bytedance/xhook/master/` 均 **HTTP 404**（2026-11-09）`[已复验]`；ADR-0006 历史调研记为 MIT `[仅据文档-历史调研]`，本轮**无法核对原文** `[仍需实测]`。
- **能力面**（ADR-0006 历史口径 `[仅据文档-历史调研]`）：Android PLT hook（ByteHook 前身），MIT，免 root。
- **差距**：同 1.2（PLT only、proxy 自写、仅 Android）；且仓库不可达，**不建议选型**。

### 1.4 Dobby（jmpews/Dobby）

- **许可**：Apache-2.0 `[仅据文档]`——[LICENSE](https://raw.githubusercontent.com/jmpews/Dobby/master/LICENSE)："Apache License Version 2.0, January 2004…"（全文，含专利授予与 NOTICE 条件）。
- **能力面** `[仅据文档]`（[README](https://raw.githubusercontent.com/jmpews/Dobby/master/README.md)）：
  - "lightweight, multi-platform, multi-architecture exploit hook framework"；**multi-platform：Windows/macOS/iOS/Android/Linux**；**multi-arch：X86 / X86-64 / ARM / ARM64**；"Minimal and modular library"；
  - Credits 列 frida-gum / minhook / substrate / v8 / dart / vixl（即 trampoline/relocator 思路同源）。
- **回调模型**：inline hook + 用户代理函数（README 未描述 listener 语义）`[仅据文档]`；细粒度 API（DobbyHook 等）未在 README 展开，**不据未见文档下断言** `[仍需实测]`。
- **差距 vs N1/N2**：同 1.1——无 enter/leave listener 与 args/retval 抽取；trampoline 层需自研；但**平台面是唯一覆盖桌面 + Android 的替代**。

### 1.5 附：And64InlineHook / LSPlant（ADR-0006 已判定，不展开）

- And64InlineHook：MIT、仅 arm64、极小 inline hook `[仅据文档-历史调研]`（ADR-0006）；能力面窄（无 ARM32/桌面）。
- LSPlant：**LGPL-3.0 且无静态链接例外** `[仅据文档-历史调研]`（ADR-0006）——闭源静态分发负担**重于** frida-gum（有例外），且只覆盖 **Java/ART 方法 hook**（本项目非目标），否决理由维持。

## 2. 能力对比矩阵（`[仅据文档]`；gum 列据 frida-gum 公开文档/ADR-0006 口径）

| 维度 | frida-gum（现方案） | ShadowHook | ByteHook | xHook | Dobby |
|---|---|---|---|---|---|
| 许可 | wxWindows 3.1（含静态链接例外）+ 15 组件（见 G1 清单） | MIT（+BSD/xDL 声明） | MIT（+BSD 声明） | MIT（历史，仓库 404） | Apache-2.0 |
| inline hook（函数入口） | ✅ Interceptor | ✅（整函数 proxy） | ❌ | ❌ | ✅（hook 框架） |
| 指令级截断 | ✅（Stalker/拦截，暂非目标） | ✅ intercept | ❌ | ❌ | 未见文档 `[仍需实测]` |
| PLT hook | ✅ | ❌ | ✅ | ✅ | 未见文档 `[仍需实测]` |
| **GumInvocationListener 等价物**（通用 enter/leave + args/retval/depth） | ✅ 原生 | ❌ proxy 自写 | ❌ proxy 自写 | ❌ proxy 自写 | ❌ proxy 自写 |
| Java 方法 hook | ❌（需 frida-java-bridge，Frida 17 起不捆绑） | ❌ | ❌ | ❌ | ❌（LSPlant 另论） |
| 架构覆盖 | x86/x86-64/ARM/ARM64 等 | arm32/arm64 | arm32/arm64/x86/x86_64 | arm32/arm64（历史） | x86/x86-64/ARM/ARM64 |
| 平台覆盖 | Linux/macOS/Windows/**Android** | **仅 Android** | **仅 Android** | 仅 Android | Windows/macOS/iOS/Android/Linux |
| Android 版本 | 文档称广泛（root 或 ptrace_scope 依赖） | 4.1–17（API 16–37） | 4.1–17（API 16–37） | 历史口径 | 未列 `[仍需实测]` |
| 免 root | ❌（需 root / `ptrace_scope=0`，E5 待实测） | ✅ | ✅ | ✅（历史） | 进程内，无 root 声明 |
| 回调执行线程 | 被钩线程（→ E1 marshal） | 被钩线程（proxy）→ 同需 marshal | 被钩线程（proxy）→ 同需 marshal | 同左 | 被钩线程（proxy）→ 同需 marshal |
| 内存读写/模块枚举 | ✅ Memory/Module API | 部分（xDL 符号查询） | ❌ | ❌ | 未列 `[仍需实测]` |
| 体量 | 数 MB devkit（9–16MB 历史值） | 小（Prefab `.so`） | 小 | 极小 | 小（modular） |

## 3. 差距分析与「为何仍需 gum 或可替代」论证

1. **回调线程安全（N3）在任何选择下都同样成立**：ShadowHook/ByteHook/Dobby 的 proxy/interceptor 同样**在被钩线程执行**，MoonBit 闭包仍须经 E1 marshal 到 owner 线程——**替代方案不消除该成本**（本仓 marshal 设计与库选型正交，已实现部分对两者通用）`[推断]`。
2. **`GumInvocationListener` 等价物（N1/N2）是最大差距**：四个替代均是「用户写类型化 proxy 函数」模型，**没有**「挂一个通用 listener 即可拿 args/return_value/depth」的语义。用替代方案复刻 `InvocationContext`，须自研 ABI trampoline/寄存器提取层（arm64/arm32/x86 各一套），把胶水成本从「转发」推到「trampoline 编译器」级别 `[推断]`。**这正是 gum 仍被需要的核心理由**（Interceptor + InvocationContext + get_depth 原生提供）。
3. **平台面（N5）**：ShadowHook/ByteHook/xHook **仅 Android**；本库目标含桌面 Linux x86-64（开发/测试主场）与 Windows stub 链路。仅 Dobby 平台面够，但其 listener 语义缺口同 2。**Android 免 root 部署**（E5 未决）则是替代方案的反向优势：MIT 栈免 root，gum 需 root / `ptrace_scope=0`。
4. **能力冗余裁剪**：gum 的 Stalker/Writer-Relocator/Backtracer 等超出本库声明范围（DECISIONS §4 非目标）；若最终只需要 Android 函数 hook + 内存读写，**ShadowHook（inline）+ 自研薄 trampoline** 或 **Dobby** 在许可上更优（MIT/Apache，无 wxWindows 例外解读负担），但 C 胶水与验证成本上升 `[推断]`。
5. **取舍结论（设计侧，三情景）**：
   - **情景 A（维持现方案）**：需要桌面 + Android、需要通用 enter/leave + args/retval 语义、不愿自研 trampoline → **仍需 gum**（G1 法务结论 + G2 链接验证后接入；本库接口不变）。
   - **情景 B（Android-only 可接受）**：MIT 栈（ShadowHook ± ByteHook）+ 本仓 E1 marshal + 自研签名 trampoline（仅 arm64 起步）→ 许可最优，弃用 gum 实现任务；**代价**：N2 depth/args 语义自研、桌面测试缺位。
   - **情景 C（跨平台但精简）**：Dobby（Apache-2.0）做 inline hook + 自研 listener 层；许可负担介于两者，工作量最大头在 listener 语义复刻。
   - **最终选型待 G2 真实验证**（hook 生效/detach 无悬挂/回调线程实测）后由主控+用户裁决 `[仍需实测]`。
6. **xHook 建议剔除候选**：上游仓库 404（2026-11-09）`[已复验]`，许可无法核对 `[仍需实测]`。

## 4. G2 门禁状态

| 项 | 状态 | 等级 |
|---|---|---|
| 至少评估一个 MIT 免 root 替代并说明为何仍需/可弃 gum | **设计侧完成**（本文 1–3：ShadowHook/ByteHook 深评 + xHook/Dobby/And64InlineHook/LSPlant） | `[仅据文档]` |
| 真实 devkit 链接验证 | **未做**（G1 未闭环，红线冻结） | `[仍需实测]` |
| 真实 hook 验证（x86-64 Linux hook libc / Android arm64） | **未做**（同上） | `[仍需实测]` |
| G2 门禁整体 | **未通过**（设计侧输入已备齐，验证腿冻结） | `[已复验]`（`DECISIONS.md`「门禁状态」） |
