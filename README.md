# hnlyxiaobing/frida_gum_ffi

**frida-gum 插桩核心的 C-FFI 封装 —— 为 MoonBit 程序提供函数 hook、内存读写与模块枚举能力。**

> 状态：**Round-1 架构与声明可评审**。已写入 `#external` 句柄、`extern "C"` shim 签名、回调与所有权、值类型及 `declare` 包装 API，`moon check` 0 error（8 条预期 `0068` 告警）。**无 hook 逻辑、无 shim 实现**。
> `preferred_target` 本轮由 `wasm` 改为 `native`（唯一配置改动，理由见 ADR-0007）。
> **实现门禁（ADR-0006）**：本库本轮只写声明，**不进入第一轮实现候选**；需先通过「许可审查 + 更小替代方案评估」两道门禁。

## 定位与为什么存在

路线图「拼图二」复核（2026-11-06）：`frida` / `gum` / `ptrace` 关键词均无可用包。MoonBit C-FFI 已足够强（`extern "C"`、`#external`、`FuncRef`、`#borrow/#owned`、`native-stub`），frida-gum 是 C 库，绑定在语言层面可行。但真正的成本在**回调桥接、线程安全与许可**，不在语言能力（ADR-0009）。

**三处报告修正（`docs/research-and-verification.md` D3）**：

1. **许可**：frida-gum 与 frida-core 的 `COPYING` 逐字相同，均为 **wxWindows Library Licence 3.1**（LGPL-2.0-or-later + `EXCEPTION NOTICE` 第 2 条静态链接例外），不是「LGPL/wxWindows 混合」。但 15 个 `subprojects/*.wrap` 上游组件许可待核，且静态链接进闭源 App 的解读须法务复核（Q2/Q3）。
2. **能力边界**：gum 只做进程内插桩；设备发现 / spawn-attach / 传输 / QuickJS-V8 运行时属 **frida-core**；Java 方法 hook 需 ART 插桩 + `frida-java-bridge`，且 **Frida 17.0.0 起 bridges 不再捆绑**。本库单独做不到 Java hook。
3. **更小替代**：ShadowHook / bhook / xHook / Dobby / And64InlineHook 均为 MIT 或 Apache-2.0、免 root、体积远小于 gum devkit。

## 能力范围 / 非目标

- **做**：`gum_init_embedded` / `deinit_embedded`、Interceptor 事务、`attach` / `detach`、`on_enter` / `on_leave` 回调注册、进程内存读写、模块与内存区间枚举。
- **不做**：设备发现 / 注入 / 传输 / 脚本运行时（frida-core）、Java 方法 hook（ART bridge）、Stalker 指令跟踪（第一轮不声明）、符号解析（配 `dwarfscope`）、断点管理。
- 与 `ptrace_lite` **互斥备选、零互相 import**，由组合根二选一（ADR-0006）。

## 公开接口（速览）

`Gum::{init, close, attach, detach, memory_read, memory_write, modules, regions}`。外部句柄与 shim 清单见 `API.md`。

## 依赖

- **本轮零依赖、零 shim 实现**；独立 `moon.mod`，`moon check` 独立通过。
- 后续轮（门禁通过后）：Frida releases 的 `libfrida-gum.a` devkit（16.x arm64 约 9–16 MB）、`native-stub` C 文件、GObject `GumInvocationListener` vtable 胶水。

## 平台与许可风险

| 风险 | 说明 |
|---|---|
| **许可（G1 门禁）** | wxWindows 3.1 例外第 2 条允许以自有条款分发静态链接二进制，但 15 个上游 `.wrap` 组件许可未逐项核对；法律解读高度版本/辖区相关，须法务复核 |
| **更小替代（G2 门禁）** | 必须至少评估 ShadowHook(MIT, 免 root, API 16–37) / bhook / xHook 之一，并说明为何 gum 仍必需；若替代够用则注销本库实现任务 |
| 平台 | `preferred_target = "native"`；Linux x86-64 桌面可验证；Android 需 root 或 `PTRACE_ATTACH` 权限 |
| 部署 | 官方排错文档明确 root / `kernel.yama.ptrace_scope=0`；W^X / SELinux 对 `mprotect(PROT_WRITE|PROT_EXEC)` 的限制来自技术博客，**待实测**（E5） |
| 线程 | `on_enter`/`on_leave` 同步跑在**被钩线程**、可重入；MoonBit 运行时在该线程执行闭包的线程安全**未实测**（E1，P0） |
| 体积 | devkit 数 MB；`[待验证假设]` 17.25.2 gum devkit 实际尺寸（Q12） |

## 测试与验收

- **测试策略**：x86-64 Linux hook 一个 libc 函数并打印参数；回调重入与 `begin/end_transaction` 事务测试；detach 后无悬挂；Android arm64 hook native 入口；许可清单核对。
- **验收标准**（实现轮，门禁通过后）：hook 生效且 detach 无悬挂；许可审查通过；回调线程安全实测通过。
- **本轮阻塞（预期）**：`moon build` / `moon test` 会在链接期失败（`mb_gum_*` shim 未实现）。

## 当前状态 / 本轮产物

| 项 | 状态 |
|---|---|
| `frida_gum_ffi.mbt`：`#external` 句柄 ×4、`extern "C"` shim ×14、`declare` API ×8 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ |
| devkit 链接 / GObject 胶水 / 事务与重入保护 / 许可审查 | ❌ 后续轮（且设门禁） |
| `moon check` | ✅ 0 error（8 × `0068`，预期） |

## 文档索引

`DESIGN.md` · `API.md` · `../docs/adr/ADR-0006`（门禁）、`ADR-0007`、`ADR-0009` · `../docs/open-questions.md` E1/E5/Q2/Q3/Q12
