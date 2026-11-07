# frida_gum_ffi · 公开 API（API.md）

> 与 `pkg.generated.mbti` 一致。`declare` 函数**无实现**（预期 `0068`）；`extern "C"` 只有声明。
> `preferred_target = "native"`。错误传播统一 `raise GumError`。
> **实现门禁**：ADR-0006 的 G1（许可）+ G2（更小替代评估）通过前不进入实现轮。

## 外部句柄（`#external` = C `void*`）

| 句柄 | C 侧对应 | 释放点 |
|---|---|---|
| `GumRuntimeRaw` | gum 嵌入式运行时 | `Gum::close`（进程级单例） |
| `GumInterceptorRaw` | `GumInterceptor*` | 借用，依附 runtime，不单独释放 |
| `GumListenerRaw` | `GumInvocationListener*` | `mb_gum_detach` |
| `GumModuleRaw` | 模块枚举数组 | `mb_gum_modules_free` |

## 外部 C shim 声明（14 个）

| shim | 所有权 / 回调 | 语义 |
|---|---|---|
| `mb_gum_init_embedded() -> GumRuntimeRaw` | — | 进程级，必须且只能一次 |
| `mb_gum_deinit_embedded(runtime)` | — | 释放运行时 |
| `mb_gum_interceptor_obtain(runtime) -> GumInterceptorRaw` | — | 借用句柄 |
| `mb_gum_transaction(interceptor, begin : Int) -> Int` | — | begin=1 开启 / 0 提交 |
| `mb_gum_attach(interceptor, symbol : Bytes) -> UInt64` | `#borrow(symbol)` | 返回 hook id（0 = 失败） |
| `mb_gum_detach(interceptor, hook_id) -> Int` | — | 摘除并释放 listener |
| `mb_gum_set_callbacks(interceptor, hook_id, cb : FuncRef[(() -> Unit) -> Unit], closure : () -> Unit) -> Int` | `#owned(closure)` | 无捕获适配器 + C 侧持有闭包 |
| `mb_gum_memory_read(address, dst : FixedArray[Byte], length) -> Int` | `#borrow(dst)` | 读进程内存 |
| `mb_gum_memory_write(address, src : Bytes, length) -> Int` | `#borrow(src)` | 写进程内存（W^X 由调用方保证） |
| `mb_gum_enumerate_modules() -> GumModuleRaw` | — | 返回数组句柄 |
| `mb_gum_module_at(modules, index, dst : FixedArray[Byte], capacity) -> Int` | `#borrow(dst)` | 1=有效 / 0=结束 |
| `mb_gum_modules_free(modules)` | — | 唯一释放点 |

> 回调状态（JavaVM / global ref / attach / per-thread data）**全部在 C 侧 listener**，不装进 MoonBit 闭包。

## 值类型 / 错误 / 契约

`Gum` · `InvocationContext` · `ModuleInfo` · `MemoryRegion` · `MemoryProtection` · `PointCut` · `GumState` · `GumError`（`pub suberror`，13 个构造）· `Address` / `HookId`（`UInt64` 别名）· `InstrumentationBackend`(trait)。

## MoonBit 侧公开 API（全部 `declare`）

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Gum::init() -> Gum raise GumError` | 无参数 | 进程级单例 / `GumError`（含 `PtraceDenied` / `LicenseReviewRequired`） | **init/deinit 单线程各一次**；失败逆序释放 | devkit 链接、许可清单、ptrace 权限 |
| `Gum::close(self) -> Unit raise GumError` | 消耗释放责任 | `Unit` / `NotInitialized` | 幂等；所有句柄释放 | — |
| `Gum::attach(self, symbol : Bytes, on_enter : (InvocationContext) -> Unit, on_leave : (InvocationContext) -> Unit) -> HookId raise GumError` | `symbol` 只读；两个回调经 FuncRef+`#owned` 传 C 侧 | `HookId` / `AttachFailed`、`UnknownSymbol` | **回调在被钩线程同步、可重入**；禁止阻塞/跨线程 JNI | GObject vtable 胶水、事务配平、重入保护 |
| `Gum::detach(self, hook_id : HookId) -> Unit raise GumError` | `hook_id` 由 attach 返回 | `Unit` / `DetachFailed` | 释放 listener 与 `#owned` 闭包 | — |
| `Gum::memory_read(self, address : Address, length : Int) -> Bytes raise GumError` | `self` 只读 | 原始字节 / `InvalidAddress`、`MemoryReadFailed` | 缓冲由 MoonBit 持有；校验长度 | 地址有效性 |
| `Gum::memory_write(self, address : Address, data : Bytes) -> Unit raise GumError` | `data` 只读 | `Unit` / `MemoryWriteFailed` | 调用方须保证目标页可写与 W^X | mprotect 策略 |
| `Gum::modules(self) -> Array[ModuleInfo] raise GumError` | `self` 只读 | 模块列表 / `ModuleEnumerateFailed` | 枚举结果由 `mb_gum_modules_free` 释放 | — |
| `Gum::regions(self) -> Array[MemoryRegion] raise GumError` | `self` 只读 | 内存区间列表 | 用于定位目标 .so 基址 | `/proc/self/maps` 或 gum API |

## 非目标 / 能力边界

设备发现 / spawn-attach / 传输 / QuickJS-V8 脚本运行时（frida-core）· Java 方法 hook（需 ART + frida-java-bridge）· Stalker 指令跟踪（第一轮不声明）· 符号解析 · 断点管理。

## 状态与已知阻塞

`moon check`：✅ 0 error，8 × `0068`。`moon build` / `moon test`：❌ **预期链接期失败**（shim 未实现）。实现：❌ **ADR-0006 门禁未通过**。
