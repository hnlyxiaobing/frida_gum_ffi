# frida_gum_ffi · 设计契约（DESIGN.md）

> Round-1 / 2026-11-06 ｜ 状态：架构与声明可评审，无 shim 实现、无 hook 逻辑；**实现设门禁**

## 1. 分层位置与职责

L2 动态插桩层的**进程内插桩 FFI 封装**。职责：把 frida-gum 的 Interceptor / Memory / Module 能力映射为 MoonBit 值类型与显式错误。**不含 frida-core**（ADR-0006）。

## 2. 模块边界 / 依赖方向 / 数据流

```
组合根（选择插桩方案）
   ├─► frida_gum_ffi::Gum ──► mb_gum_* shim ──► libfrida-gum.a (gum C API)
   └─► ptrace_lite::Target  （互斥备选）
```

两库**零互相 import**；抽象（`InstrumentationBackend` / `MemoryView`）留在各自模块与组合根，不新建公共模块，避免 K4 环。本库不 import `pose` / `apk` / 任何本地模块。

## 3. 核心数据结构

| 类型 | 作用 |
|---|---|
| `GumRuntimeRaw` / `GumInterceptorRaw` / `GumListenerRaw` / `GumModuleRaw` | `#external` 句柄（C `void*`，MoonBit 不引用计数） |
| `Gum { runtime, interceptor, state, hook_count }` | 进程级单例包装值 |
| `InvocationContext { hook_id, point_cut, thread_id, depth, function_address, args, return_value }` | 只读上下文快照；**不含 CPU 寄存器原始指针**，避免跨线程悬挂引用 |
| `ModuleInfo` / `MemoryRegion` / `MemoryProtection` | 枚举结果 |
| `PointCut` / `GumState` | Enter/Leave；Uninitialized/Initialized/Attached/Closed |
| `Address` / `HookId` | `UInt64` 别名 |
| `GumError` | 12 个错误构造（含 `PtraceDenied`、`LicenseReviewRequired`） |
| `InstrumentationBackend` trait | `attach` / `detach` / `read` 契约（供组合根选择方案） |

## 4. 错误模型

`GumError`：`NotInitialized`、`AlreadyInitialized`、`DevkitNotFound`、`AttachFailed`、`DetachFailed`、`UnknownSymbol`、`InvalidAddress`、`MemoryReadFailed`、`MemoryWriteFailed`、`ModuleEnumerateFailed`、`CallbackBridgeFailed`、`PtraceDenied`、`LicenseReviewRequired`。

`LicenseReviewRequired` 把 ADR-0006 的门禁状态变成**可观察信号**：实现轮若未通过许可审查，应主动返回该错误而非静默继续。

## 5. 资源生命周期

| 资源 | 获取 | 唯一释放点 | 规则 |
|---|---|---|---|
| runtime | `mb_gum_init_embedded` | `Gum::close` | **进程级单例，init/deinit 各一次** |
| interceptor | `mb_gum_interceptor_obtain` | 不单独释放（依附 runtime） | 借用 |
| hook listener | `mb_gum_attach` / `mb_gum_set_callbacks` | `mb_gum_detach` | 摘除时释放 |
| `#owned` 回调闭包 | `mb_gum_set_callbacks` | `mb_gum_detach` | C 侧 `moonbit_decref` |
| module 数组 | `mb_gum_enumerate_modules` | `mb_gum_modules_free` | 唯一释放点 |
| 读写缓冲 | `FixedArray[Byte]` / `Bytes` | 调用方持有 | 校验 length |

`Gum::close` 幂等，重复调用返回 `NotInitialized`。

## 6. 线程 / 并发边界（ADR-0009，最严格）

- `init` / `deinit` 必须在**单一线程**完成，且各一次；禁止并发 init/deinit。
- `on_enter` / `on_leave` **同步执行在被钩线程、可重入**；`InvocationContext.depth` 与 per-thread listener data 正是为此设计（frida-gum `GumInvocationContext` 提供 `get_depth`）。
- 回调内**禁止阻塞、禁止跨线程 JNI、禁止保存栈上指针**；必须浅拷贝数据后 marshal 到 owner 线程。
- MoonBit `FuncRef` 只能无捕获；回调所需的 JavaVM / global ref / attach 状态 / per-thread data **必须下沉到 C shim 或 `#external` 句柄**，不能装进 MoonBit 闭包。
- `begin_transaction` / `end_transaction` 批量激活；17.17.0 曾修复 "detach hang when transaction ended twice"，实现轮须保证事务配平。
- `[待验证假设]` **MoonBit 运行时在被钩线程执行闭包的线程安全（GC / 引用计数 / 重入）本机未实测**（E1，P0）。

## 7. 平台约束与外部依赖

- `preferred_target = "native"`（本轮调整）；Windows native 需 MSVC；LLVM 后端无 FFI。
- Linux x86-64 桌面可验证；Android 需 root 或 `PTRACE_ATTACH`（官方排错文档明确 `kernel.yama.ptrace_scope=0`）。
- 后续依赖：`libfrida-gum.a` devkit（`frida-gum-devkit-<ver>-android-*.tar.xz`）、`native-stub` C 文件、GObject listener vtable 胶水。
- **Java 方法 hook 不在本库能力内**：Frida 17+ 需显式 `frida-java-bridge` + ART 插桩。

## 8. 外部类型 / 句柄 / 回调签名 / 所有权规则

| 类别 | 声明 | 规则 |
|---|---|---|
| 外部类型 | 4 个 `#external pub type` | C `void*`；不引用计数；**永不跨模块传递** |
| 外部函数 | 14 个 `pub extern "C" fn mb_gum_* = "…"` | 转发 gum C API；统一 status code |
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
| 门禁 | `moon fmt --check` / `moon check`（本轮不加 `--deny-warn`） |

## 11. 验收标准（实现轮，且必须先过 G1/G2 门禁）

1. **G1**：15 个 `subprojects` 许可核对完成 + 法务结论写入 `COMPATIBILITY.md`；
2. **G2**：至少评估一个 MIT 免 root 替代并给出取舍结论；
3. hook 生效、detach 无悬挂、事务配平；4. 回调线程安全实测通过；5. R4 `--deny-warn` 转绿。

## 12. 未解决问题 / 待验证假设

E1（P0）MoonBit 回调线程安全 · E5 W^X/SELinux · Q2 subprojects 许可 · Q3 静态链接法务 · Q12 17.25.2 devkit 尺寸 · 第一轮是否真的不需要 Java 方法 hook（评审拍板点）。

## 13. 当前状态与 TODO

`frida_gum_ffi.mbt` 已写入 4 个 `#external` 句柄、14 个 shim 声明、值类型、错误模型与 8 个 `declare` API，公开 API 有 `///` 文档注释与 `TODO(实现轮)`。**无 devkit、无 C shim、无业务逻辑；实现被 ADR-0006 门禁挡在 W2 之后**。

## References

`../docs/adr/ADR-0006`、`ADR-0007`、`ADR-0009` · `https://raw.githubusercontent.com/frida/frida-gum/main/COPYING` · `guminterceptor.h` / `guminvocationlistener.h` · `https://frida.re/docs/bridges`
