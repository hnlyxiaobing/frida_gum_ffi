# frida_gum_ffi · 设计决策记录（DECISIONS.md）

> 本文整合本库开发期的设计决策（源自开发期决策记录，已去过程化改写），是仓库内设计决策的**唯一权威文本**；每条按「背景 → 决策 → 理由 → 后果」组织。许可事实、数字与证据等级与 `LICENSE-AUDIT.md` 一致（证据等级标注：`[已复验]` / `[已复验-本地等价]` / `[仅据文档]` / `[仍需实测]`，定义见 `LICENSE-AUDIT.md` 头部）。

---

## 1. 真实 frida-gum devkit 对接延后，并设 G1 / G2 双门禁

### 背景

- **许可事实修正**：frida-gum 与 frida-core 的 `COPYING` **主体一致**，均为 **wxWindows Library Licence, Version 3.1**（SPDX: `wxWindows`；GNU Library General Public Licence v2 "or any later version" 再许可条款 + `EXCEPTION NOTICE` 四条静态链接例外）。早期「LGPL/wxWindows 混合许可」的说法不准确；"LGPL-2.1+" 只是 2014-01-11 Frida 1.0.6 公告的历史简写。PyPI `frida 17.25.2` 分类器即 `wxWindows Library Licence, Version 3.1`。但许可风险并未消失：
  1. `subprojects/*.wrap` 打包 **15 个上游组件**（capstone / glib / quickjs / openssl / v8 / xz …），许可须逐项核对——若 devkit 产物含纯 (L)GPL 组件，`EXCEPTION NOTICE` 第 3 条会让例外对那部分失效；
  2. **静态链接进闭源 App** 的解读高度版本 / 司法辖区相关，上线前须法务复核；
  3. devkit 体积数 MB（16.x arm64 约 **9–16 MB**）；
  4. Android 部署需 root 或 `PTRACE_ATTACH` 权限（官方排错文档明确 `kernel.yama.ptrace_scope=0`）；W^X / SELinux `untrusted_app` 对 `mprotect(PROT_WRITE|PROT_EXEC)` 的限制来自技术博客，**待实测**；
  5. `on_enter` / `on_leave` 在被钩线程同步执行且可重入，MoonBit 运行时的回调线程安全**未实测**（见 `DESIGN.md` §12 风险与待验证）。
- **更小替代客观存在**：ShadowHook（bytedance，MIT，Android 4.1–17 / API 16–37，免 root，Prefab）、bhook / ByteHook（MIT，PLT）、xHook（MIT，PLT）、Dobby（Apache-2.0）、And64InlineHook（MIT）均更小且免 root；LSPlant 是 LGPL-3.0 且**无**静态链接例外，合规负担更重。
- **成本判定**（2026-11-06 检索 mooncakes.io，`frida` / `gum` / `ptrace` 关键词均无可用包）：MoonBit C-FFI 已足够强（`extern "C"`、`#external`、`FuncRef`、`#borrow`/`#owned`、`native-stub`），frida-gum 是 C 库，绑定在语言层面可行；真正的成本在**回调桥接、线程安全与许可**，不在语言能力。

### 决策

1. **真实 devkit 对接不进入实现候选**，延后到双门禁通过之后；此前只链接仓库自带的桌面 stub `../stub/mb_gum_stub.c`，**不下载、不链接、不引入**任何 devkit。
2. 进入真实链接前设两道**显式门禁**，必须同时通过：
   - **G1（许可审查）**：15 个 `subprojects/*.wrap` 上游组件**逐项许可**核对 + **wxWindows 3.1 静态链接例外（`EXCEPTION NOTICE` 第 2 条）对目标分发形态的适用性**确认 + **法务结论**；
   - **G2（更小替代方案评估）**：在 ShadowHook / bhook / xHook / Dobby 等 **MIT（或 Apache-2.0）免 root 替代**中至少评估一个，说明为何仍选 / 不选 gum（例如确需 Stalker / 跨架构 Writer-Relocator）；若替代够用，则改用 MIT 免 root 方案并注销本库真实实现任务。
3. 门禁状态在本仓 `DECISIONS.md`「门禁状态」小节单点维护；**未通过前不得把门禁写成已通过**。

### 理由

- 把整个项目最大的法务 / 平台 / 线程安全不确定性推到有实证依据之后再承担。wxWindows 3.1 例外第 2 条使「静态链接 `libfrida-gum.a` devkit、以自有条款分发二进制」在许可文本层面**可行**（条款摘录见 `LICENSE-AUDIT.md` §3），但 15 个上游组件逐项许可与法务解读未闭环前不应启动真实链接。
- 许可结论从「高风险」修正为「**中风险但需逐项核对 + 法务复核**」：避免过度保守，也避免误判。
- 更小替代评估（G2）防止为不需要的能力付许可与体积成本；若 MIT 免 root 替代够用，直接换方案比硬上 gum 更划算。

### 后果

- **正面**：不确定性后移；桌面 stub 全链路可独立测试（`moon test` 4/4）；许可原文事实固化在 `LICENSE-AUDIT.md`。
- **负面**：若后续确需 Java 方法 hook 或 Stalker，仍需引入 gum + frida-java-bridge / ART 方案，工作量可能上升；G1 法务结论不出则真实链接一直阻塞（G2 可并行评估，且备选路线不依赖 G1）。
- **被否决的替代**：① 直接实现 gum 封装（否决：门禁缺失、许可描述错误未纠正）；② 完全放弃 gum 只用 ptrace（否决：ptrace 无 inline hook，无法覆盖函数级参数观测）；③ 用 LSPlant（否决：LGPL-3.0 无静态链接例外，负担更重）。

---

## 2. `LicenseReviewRequired`：把门禁做成可观察运行时信号

### 背景

门禁若只是文档约定，实现阶段容易静默绕过；调用方与测试也无法感知「许可审查是否已通过」。

### 决策

错误模型 `GumError`（13 个构造）保留 **`LicenseReviewRequired`** 与 **`PtraceDenied`**；`Gum::init` 的探针事务在门禁未过时**主动返回** `LicenseReviewRequired`（C status 3）而非静默继续；ptrace 权限不足返回 `PtraceDenied`（status 4）；失败的 init 不消耗生命周期（逆序释放）。

### 理由

门禁状态由此成为**运行时可观察、可测试**的信号：白盒测试「许可门禁可观察路径」通过 stub 门禁开关验证「未过 → 明确错误、已过 → 正常 init/close」；调用方可以显式分支处理「许可未过」。

### 后果

实现阶段若未通过许可审查，会以明确错误暴露而不是带病运行；错误消息随附门禁说明；stub 的门禁开关（测试缝）模拟该信号，真实实现须保持同一 status code 契约（见 `../stub/mb_gum_stub.c` 头部）。

---

## 3. 与 `ptrace_lite` 互斥备选、零互相 import、组合根二选一

### 背景

动态插桩层有两条候选路线：frida-gum（进程内 inline hook）与 ptrace（外部调试器式附加）。两者的许可、平台与能力特性不同，过早合并会互相拖累。

### 决策

1. `frida_gum_ffi` 与 `ptrace_lite` 是**互斥备选、零互相 import**；本库不 import 任何本地模块。
2. 抽象（`InstrumentationBackend` / `MemoryView`）留在各自模块与**组合根**，不新建公共模块，避免模块依赖环；由**组合根二选一**。
3. 本库提供 `InstrumentationBackend` trait（`attach` / `detach` / `read` 契约），使组合根可换成 `ptrace_lite` 或 MIT 免 root 替代（ShadowHook / bhook / xHook）而不改上层。

### 理由

避免公共模块造成的依赖环与过早耦合；选型权留在组合根，两条路线可独立演进、独立测试、独立发布。

### 后果

两库零耦合、可各自验证；组合根承担选型与互斥约束；两库之间不能复用类型，抽象需各写一份。

---

## 4. 能力边界：只封装 gum（进程内插桩），不含 frida-core

### 背景

早期需求描述把「设备发现 / 注入 / 传输 / 脚本运行时 / Java hook」都算进本库能力，会高估本库单独能做的事。

### 决策（能力边界，事实层）

- **做**：gum 是**进程内插桩库**（Interceptor / Stalker / MemoryAccessMonitor / Module / DebugSymbol / Backtracer / Writer-Relocator 一类能力）；本库只封装其中的 Interceptor / Memory / Module 映射为 MoonBit 值类型与显式错误。
- **不做**：设备发现 / spawn-attach / 传输 / QuickJS-V8 脚本运行时——这些属 **frida-core**，不在本库。
- **Java 方法 hook 不可（本库单独做不到）**：需 ART 插桩 + `frida-java-bridge`，且 **Frida 17.0.0 起 bridges 不再捆绑**。
- Stalker 指令跟踪当前**不声明**；符号解析（配 `dwarfscope`）、断点管理亦不在本库。

### 理由

防止能力预期错位；把边界写进文档注释与 `../README.md`，让使用者在读签名前就知道缺什么。

### 后果

非目标明确；若后续需要 Java 方法 hook，须另行引入 `frida-java-bridge` + ART 方案，且须重新过 G1/G2 门禁。

---

## 5. 回调桥设计：`FuncRef` 无捕获适配器 + `#owned` 闭包二元组，detach 成对释放

### 背景

- MoonBit `FuncRef[T]` 只能是**无捕获**闭包（捕获变量报 E4151），C 后端映射为函数指针；带捕获状态的回调只能表示为「函数 + 环境对象」二元组。
- frida-gum 的 `on_enter` / `on_leave` **同步执行在被钩线程、可重入**（`GumInvocationContext.get_depth` 与 per-thread listener data 即为证）。
- 若涉 JNI：`JNIEnv*` 线程局部、不可缓存、不可跨线程共享；跨线程长期持有对象须 global ref。回调需要的 JavaVM / global ref / attach 状态 / per-thread data **不能装进 MoonBit 闭包**。

### 决策

1. 回调签名固定为二元组：`extern "C" fn mb_gum_set_callbacks(interceptor, hook_id, cb : FuncRef[(() -> Unit) -> Unit], closure : () -> Unit)`，`closure` 以 `#owned(closure)` 标注——C 侧长期持有闭包，**detach / close 时 `moonbit_decref` 成对释放**。
2. 回调状态（JavaVM / global ref / attach 状态 / per-thread data）**全部下沉 C 侧 listener**，不装进 MoonBit 闭包。
3. 回调内**禁止阻塞、禁止跨线程 JNI、禁止保存栈上指针**；必须浅拷贝数据后 marshal 到 owner 线程。
4. 每个 API 在文档注释里写明线程约束（不只写在总体文档里）。

### 理由

避免跨线程 JNIEnv 非法与悬空闭包崩溃；`#borrow` / `#owned` 全部显式标注，规避官方「默认语义正在从 owned 迁移到 borrow」的升级风险。

### 后果

C shim 不再「极薄」——**薄在 ABI 转发，厚在生命周期与线程编排**（须承担闭包引用计数与 marshal）；attach / detach、set / close 必须成对（测试断言 stub 持有闭包引用计数成对，不泄不溢）。

---

## 6. `preferred_target = "native"`

### 背景

wasm 后端不支持 `extern "C"`（`E4156 extern "C" is unsupported in wasm backend`），而本库的价值就是外部 C ABI；其余纯 MoonBit 模块不受影响。

### 决策

`../moon.mod` 的 `preferred_target` 由 `"wasm"` 改为 `"native"`；Windows native 需 MSVC（`cl.exe` / `clang-cl.exe`，MinGW 不支持）；LLVM 后端不支持 FFI。

### 理由

FFI 模块的 `extern "C"` / `#external` / `#borrow` / `#owned` / `FuncRef` 声明只有在 native 目标下才会被真实编译器检查。

### 后果

`moon check` / `moon build` / `moon test` 在 native 后端真实编译、链接、运行（链接仓库自带 C stub）；Windows 构建依赖 MSVC 工具链。

---

## 7. 死分支收紧：`GumState` 仅保留 `Initialized`

### 背景

`GumState` 的 `Uninitialized` / `Attached` / `Closed` 分支从未被构造或匹配，是死分支。

### 决策

只保留实际代码路径使用到的 `Initialized`，删除三个死分支，**不补齐状态机**（状态语义由 `Gum::init` / `close` 的错误模型表达：重复 close → `NotInitialized`，重复 detach → `DetachFailed`）。

### 理由

不留无人维护的状态分支；重复调用的语义已在错误模型中显式表达，状态机与错误模型二选一即可。

### 后果

导出面收窄（`../pkg.generated.mbti` 快照中 `GumState` 仅 `Initialized`）；后续若真实实现需要新状态，按加法性变更走 API 快照审阅。

---

## 8. shim 可见性收敛：`mb_gum_*` 全部包私有

### 背景

14 个 `mb_gum_*` `extern "C"` shim 一度以 `pub` 导出，出现在 `moon info` 快照里，被误当作公共 API。

### 决策

其中 12 个（`../frida_gum_ffi.mbt`）由 `pub` 收敛为**包私有**，与 `../internal.mbt` 的 2 个（`mb_gum_region_at` / `mb_gum_current_context`）合计 **14 个 `mb_gum_*` 全部为私有实现 ABI、非公共 API**，均不出现在 `moon info` 快照（`../pkg.generated.mbti`）中；对外唯一入口是 `Gum::{init,close,attach,detach,memory_read,memory_write,modules,regions}`（8 个 API）。

### 理由

shim 是私有实现 ABI（转发 gum C API、统一 status code），不是稳定接口；收敛后升级/替换 C 侧实现不构成公共 API 变更。

### 后果

快照中 0 个 `mb_gum_*` 导出；调用方只能经 `Gum::*` 使用；白盒测试仍可调用包私有 shim。

---

## 门禁状态

> 本表是 G1/G2 门禁状态的**唯一口径**；与 `LICENSE-AUDIT.md` 的许可事实一致。**不得**把 G1/G2 写成已通过。

| 项 | 状态 | 证据等级 |
|---|---|---|
| 许可证 | **wxWindows Library Licence, Version 3.1**（GNU Library GPL v2 or later + `EXCEPTION NOTICE` 第 2 条允许以自有条款分发二进制目标码）——**不是** "LGPL/wxWindows 混合" | `[仅据文档]` |
| 是否引入 | **未引入**：无 devkit、无 `.h` 头文件、无 `.so/.a/.dll` 库文件入库；只有项目内 `../stub/mb_gum_stub.c` | `[已复验]` |
| 是否下载/链接 | **未下载、未链接**（不下载 devkit 是硬约束） | `[已复验]` |
| **G1（许可）门禁** | **未通过** —— devkit 所含 15 个上游组件（capstone/glib/quickjs/openssl/v8/xz…）逐项许可未核对、法务结论未取得 | `[仍需实测]` |
| **G2（更小替代）门禁** | **未通过** —— ShadowHook / bhook / xHook 尚未评估，未说明 gum 是否仍必需 | `[仍需实测]` |
| 未决事项 | 15 个上游组件逐项许可；静态链接 wxWindows 3.1 进闭源 App 的合规结论（法律解读属 `[推断]`） | `[仍需实测]` |
| stub 例外 | `frida_gum_ffi` 的 C stub 是**项目内行为模拟桩**，不是真实 devkit 对接；真实对接须 **G1+G2 同时通过**后分阶段进行 | `[已复验]`（源码头注释 + `../moon.pkg` `native-stub` 配置） |

## 参考（仓库内）

`LICENSE-AUDIT.md`（许可原文事实与条款摘录）· `DESIGN.md`（设计契约与风险）· `API.md`（接口）· `../README.md`。许可原文来源（URL，供复核比对）：`https://raw.githubusercontent.com/frida/frida-gum/main/COPYING`、`https://raw.githubusercontent.com/frida/frida-core/main/COPYING`；能力边界参考 frida 官方文档 `https://frida.re/docs/bridges`。
