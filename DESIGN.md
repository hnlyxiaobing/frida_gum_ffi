# frida_gum_ffi · 设计契约（DESIGN.md）

> 2026-11-07 ｜ 状态：桌面 stub 实现 + 4 测试全过（`moon check --deny-warn` 等五项门禁全绿）；**真实 devkit 链接仍设门禁（G1/G2 开放，见 `DECISIONS.md`）**

## 1. 分层位置与职责

L2 动态插桩层的**进程内插桩 FFI 封装**。职责：把 frida-gum 的 Interceptor / Memory / Module 能力映射为 MoonBit 值类型与显式错误。**不含 frida-core**（能力边界见 `DECISIONS.md`「能力边界」）。

## 2. 模块边界 / 依赖方向 / 数据流

```
组合根（选择插桩方案）
   ├─► frida_gum_ffi::Gum ──► mb_gum_* shim（包私有）──► stub/mb_gum_stub.c（当前）
   │                                            └──► libfrida-gum.a (gum C API)（G1/G2 门禁后）
   └─► ptrace_lite::Target  （互斥备选）
```

两库**零互相 import**；抽象（`InstrumentationBackend` / `MemoryView`）留在各自模块与组合根，不新建公共模块，避免模块依赖环。本库不 import 其它任何本地模块（互斥备选决策见 `DECISIONS.md`）。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `GumRuntimeRaw` / `GumInterceptorRaw` / `GumListenerRaw` / `GumModuleRaw` | `#external` 句柄（C `void*`，MoonBit 不引用计数） |
| `Gum { runtime, interceptor, state, hook_count }` | 进程级单例包装值 |
| `InvocationContext { hook_id, point_cut, thread_id, depth, function_address, args, return_value }` | 只读上下文快照；**不含 CPU 寄存器原始指针**，避免跨线程悬挂引用 |
| `ModuleInfo` / `MemoryRegion` / `MemoryProtection` | 枚举结果 |
| `PointCut` / `GumState` | Enter/Leave；`GumState` 收紧为实际使用的 `Initialized`（死分支收紧决策：`Uninitialized`/`Attached`/`Closed` 死分支已删，不补齐状态机，见 `DECISIONS.md`） |
| `Address` / `HookId` | `UInt64` 别名 |
| `GumError` | 13 个错误构造（含 `PtraceDenied`、`LicenseReviewRequired`） |
| `InstrumentationBackend` trait | `attach` / `detach` / `read` 契约（供组合根选择方案） |

## 4. 错误模型

`GumError`：`NotInitialized`、`AlreadyInitialized`、`DevkitNotFound`、`AttachFailed`、`DetachFailed`、`UnknownSymbol`、`InvalidAddress`、`MemoryReadFailed`、`MemoryWriteFailed`、`ModuleEnumerateFailed`、`CallbackBridgeFailed`、`PtraceDenied`、`LicenseReviewRequired`。

`LicenseReviewRequired` 把 G1/G2 门禁状态变成**可观察信号**（见 `DECISIONS.md`「`LicenseReviewRequired`」）：实现阶段若未通过许可审查，应主动返回该错误而非静默继续。

## 5. 资源生命周期

| 资源 | 获取 | 唯一释放点 | 规则 |
|---|---|---|---|
| runtime | `mb_gum_init_embedded` | `Gum::close` | **进程级单例，init/deinit 各一次** |
| interceptor | `mb_gum_interceptor_obtain` | 不单独释放（依附 runtime） | 借用 |
| hook listener | `mb_gum_attach` / `mb_gum_set_callbacks` | `mb_gum_detach` | 摘除时释放 |
| `#owned` 回调闭包 | `mb_gum_set_callbacks` | `mb_gum_detach` | C 侧 `moonbit_decref` |
| module 数组 | `mb_gum_enumerate_modules` | `mb_gum_modules_free` | 唯一释放点 |
| 读写缓冲 | `FixedArray[Byte]` / `Bytes` | 调用方持有 | 校验 length |

`Gum::close` / `Gum::detach` 统一措辞：**不会二次释放，重复调用返回明确错误**（重复 close → `NotInitialized`；重复 detach → `DetachFailed`，运行时已关闭 → `NotInitialized`）。

## 6. 线程 / 并发边界（最严格；回调桥设计见 `DECISIONS.md`「回调桥设计」）

- `init` / `deinit` 必须在**单一线程**完成，且各一次；禁止并发 init/deinit。
- `on_enter` / `on_leave` **同步执行在被钩线程、可重入**；`InvocationContext.depth` 与 per-thread listener data 正是为此设计（frida-gum `GumInvocationContext` 提供 `get_depth`）。
- 回调内**禁止阻塞、禁止跨线程 JNI、禁止保存栈上指针**；必须浅拷贝数据后 marshal 到 owner 线程。
- MoonBit `FuncRef` 只能无捕获；回调所需的 JavaVM / global ref / attach 状态 / per-thread data **必须下沉到 C shim 或 `#external` 句柄**，不能装进 MoonBit 闭包。
- `begin_transaction` / `end_transaction` 批量激活；17.17.0 曾修复 "detach hang when transaction ended twice"，真实实现须保证事务配平。
- `[待验证假设]` **MoonBit 运行时在被钩线程执行闭包的线程安全（GC / 引用计数 / 重入）本机未实测**（见 §12 风险与待验证）。

## 7. 平台约束与外部依赖

- `preferred_target = "native"`（理由见 `DECISIONS.md`）；Windows native 需 MSVC；LLVM 后端无 FFI。
- Linux x86-64 桌面可验证；Android 需 root 或 `PTRACE_ATTACH`（官方排错文档明确 `kernel.yama.ptrace_scope=0`）。
- 后续依赖：`libfrida-gum.a` devkit（`frida-gum-devkit-<ver>-android-*.tar.xz`）、`native-stub` C 文件、GObject listener vtable 胶水。
- **Java 方法 hook 不在本库能力内**：Frida 17+ 需显式 `frida-java-bridge` + ART 插桩。

## 8. 外部类型 / 句柄 / 回调签名 / 所有权规则

| 类别 | 声明 | 规则 |
|---|---|---|
| 外部类型 | 4 个 `#external pub type` | C `void*`；不引用计数；**永不跨模块传递** |
| 外部函数 | 14 个 `extern "C" fn mb_gum_* = "…"`（**包私有 · 私有实现 ABI，非公共 API**，均不出现在 `moon info` 快照） | 转发 gum C API；统一 status code。其中 12 个在 `frida_gum_ffi.mbt`（由 `pub` 收敛为包私有，见 `DECISIONS.md`「shim 可见性收敛」），2 个在 `internal.mbt`（`mb_gum_region_at` / `mb_gum_current_context`） |
| 回调签名 | `mb_gum_set_callbacks(interceptor, hook_id, cb : FuncRef[(() -> Unit) -> Unit], closure : () -> Unit) -> Int` | `FuncRef` 无捕获；`closure` 用 `#owned(closure)`，detach 时 `moonbit_decref` |
| `#borrow` | `mb_gum_attach(symbol)`、`mb_gum_memory_read(dst)`、`mb_gum_memory_write(src)`、`mb_gum_module_at(dst)` | MoonBit 保留所有权，C 侧只读/填充，不 decref |
| 缓冲 | `FixedArray[Byte]` / `Bytes` + `length` | 地址/长度校验；W^X 约束由调用方保证 |

## 9. 可替换性与实现细节不泄漏

上层只看到 `Gum` / `InvocationContext` / `ModuleInfo`；看不到 gum devkit、GObject vtable、trampoline 细节。`InstrumentationBackend` trait 让组合根可换成 `ptrace_lite` 或 MIT 免 root 替代（ShadowHook / bhook / xHook），不改上层。

## 10. 测试策略

| 层次 | 内容 |
|---|---|
| 黑盒 | x86-64 Linux hook libc 函数并打印参数；detach 后无悬挂 |
| 白盒 | 回调重入 / `get_depth`、事务配平、`ignore_current_thread` 语义 |
| 平台 | Android arm64 native 入口 hook；root / ptrace_scope / SELinux 记录 errno |
| 合规 | devkit 上游许可逐项清单、静态链接分发结论 |
| 门禁 | `moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check`（在 `frida_gum_ffi/` 依次实跑，全部 exit 0；测试数不得少于 4 个） |

## 11. 验收标准（真实实现阶段，且必须先过 G1/G2 门禁）

1. **G1**：15 个 `subprojects` 许可核对完成 + 法务结论写入本仓 `LICENSE-AUDIT.md` / `DECISIONS.md`「门禁状态」；
2. **G2**：至少评估一个 MIT 免 root 替代并给出取舍结论；
3. hook 生效、detach 无悬挂、事务配平；4. 回调线程安全实测通过；5. `--deny-warn` 门禁保持全绿。

## 12. 风险与待验证

> 本节是本库「不得进入架构决策」事项的跟踪点（内容源自开发期决策记录，已内联）。

1. **回调线程安全 `[待验证假设]`（最高优先，P0）**：MoonBit 运行时在被钩线程执行回调的线程安全（GC、引用计数、重入）本机未实测，直接决定回调桥设计是否成立。最小实验：Linux x86-64 native 目标下从一个 pthread 反复调用无捕获 `FuncRef` 与 `#owned` 闭包，观察引用计数/崩溃；再加可重入场景。
2. **W^X / SELinux 部署限制 `[待验证假设]`（P1）**：W^X / SELinux `untrusted_app` 对 inline hook（`mprotect PROT_WRITE|PROT_EXEC`）的实际限制；是否需要 root / `ptrace_scope` 未实测。最小实验：目标设备上做一次最小 inline hook 与一次 `PTRACE_ATTACH`，记录 errno。决定部署形态，是 G2 评估输入。
3. **`subprojects` 许可 `[未解决]`**：frida-gum `subprojects/*.wrap` 中 15 个上游组件（capstone/glib/quickjs/openssl/v8/xz…）的逐项许可未核对（当前只有 `COPYING` 主文与 BSD 片段清单已核实）。动作：逐 `.wrap` 核对后并入本仓 `DECISIONS.md`「门禁状态」/ `LICENSE-AUDIT.md`；G1 输入。
4. **静态链接法务 `[未解决]`**：静态链接 wxWindows 3.1 代码进闭源 App 在本项目分发形态下的合规结论——例外第 2 条文本已核实，但法律解读属 `[推断]`，须法务出具结论（G1 硬门禁）。
5. **devkit 尺寸与组件 `[未解决]` `[待验证假设]`**：17.25.2 gum devkit 的实际体积与所含组件未核实（仅确认 16.6.6 / 17.5.3 的 9–16 MB 历史值）；须在允许获取 devkit 后核对清单，作为 G2 评估输入。
6. **Java 方法 hook 前提（评审确认点）**：当前按「不需要 Java 方法 hook」设计；若目标 App 确需 Java 层 hook，须引入 `frida-java-bridge` + ART 方案并重过 G1/G2 门禁。

## 13. 当前状态与 TODO

`frida_gum_ffi.mbt` 已写入 4 个 `#external` 句柄、14 个 `mb_gum_*` shim 声明（**全部包私有**，其中 12 个由 `pub` 收敛）、值类型、错误模型与 8 个已实现的 `Gum::*` API；`stub/mb_gum_stub.c` 桌面 stub 已实现 Interceptor 表 / 内存区 / 模块与区间表，`moon test` **4/4 全过**（1 黑盒 + 3 白盒）。**无 devkit 链接、无真实 gum 运行时；真实实现仍被 G1/G2 门禁挡在后续阶段（见 `DECISIONS.md`）**。

快照：仓内 `pkg.generated.mbti` 已与新导出面一致（**0 个 `mb_gum_*` 导出、`GumState` 仅 `Initialized`**）——该文件由 `moon check` 的 `rr_moon_pkg` 特性在门禁运行中自动再生成，未手动运行 `moon info`、未手工编辑任何 `pkg.generated.mbti`。

## References

设计决策与门禁状态见本仓 `DECISIONS.md`；许可事实见本仓 `LICENSE-AUDIT.md`。外部来源（URL，供复核比对）：`https://raw.githubusercontent.com/frida/frida-gum/main/COPYING` · `https://frida.re/docs/bridges` · frida-gum `guminterceptor.h` / `guminvocationlistener.h`。
