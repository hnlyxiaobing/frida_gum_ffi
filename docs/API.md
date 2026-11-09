# frida_gum_ffi · 公开 API（API.md）

> 与 `../pkg.generated.mbti` 一致。`extern "C"` shim **只有声明、无 MoonBit 侧实现**，且已收敛为**包私有**（见下节）。
> `preferred_target = "native"`。错误传播统一 `raise GumError`。`Gum::{init,close,attach,detach,memory_read,memory_write,modules,regions}` 为**已实现**的桌面 stub 实现（真实 frida-gum devkit 未链接）。
> **实现门禁**：G1（许可）+ G2（更小替代评估）双门禁（见 `DECISIONS.md`「G1 / G2 双门禁」）通过前不链接真实 devkit（当前维持开放）。

## 外部句柄（`#external` = C `void*`）

| 句柄 | C 侧对应 | 释放点 |
|---|---|---|
| `GumRuntimeRaw` | gum 嵌入式运行时 | `Gum::close`（进程级单例） |
| `GumInterceptorRaw` | `GumInterceptor*` | 借用，依附 runtime，不单独释放 |
| `GumListenerRaw` | `GumInvocationListener*` | `mb_gum_detach` |
| `GumModuleRaw` | 模块枚举数组 | `mb_gum_modules_free` |

## 外部 C shim 声明（12 个 · 包私有 · 私有实现 ABI，非公共 API）

> **可见性（shim 可见性收敛，见 `DECISIONS.md`）**：下列 12 个 `mb_gum_*` 已由 `pub` 改为包私有，**不再出现在 `moon info` 快照（`../pkg.generated.mbti`）中**；调用方只能经 `Gum::*` MoonBit 层 API 使用。`../internal.mbt` 另有 2 个包私有 shim（`mb_gum_region_at` / `mb_gum_current_context`），合计 14 个 `mb_gum_*` C 声明**全部为私有实现 ABI，非公共 API**。C 符号由 `../stub/mb_gum_stub.c` 提供，链接真实 devkit 受 G1/G2 门禁约束。

| shim（包私有） | 所有权 / 回调 | 语义 |
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

`Gum` · `InvocationContext` · `ModuleInfo` · `MemoryRegion` · `MemoryProtection` · `PointCut` · `GumState`（死分支收紧，见 `DECISIONS.md`：仅保留实际使用的 `Initialized` 分支，`Uninitialized` / `Attached` / `Closed` 死分支已删）· `GumError`（`pub suberror`，13 个构造）· `Address` / `HookId`（`UInt64` 别名）· `InstrumentationBackend`(trait)。

## MoonBit 侧公开 API（全部已实现 · 桌面 stub）

| 签名 | 参数与所有权 | 返回 / 错误 | 资源与线程约束 | TODO |
|---|---|---|---|---|
| `Gum::init() -> Gum raise GumError` | 无参数 | 进程级单例 / `GumError`（含 `PtraceDenied` / `LicenseReviewRequired`） | **init/deinit 单线程各一次**；失败逆序释放 | devkit 链接、许可清单、ptrace 权限 |
| `Gum::close(self) -> Unit raise GumError` | 消耗释放责任 | `Unit` / `NotInitialized` | **不会二次释放，重复调用返回明确错误**（重复 close → `NotInitialized`）；所有句柄释放 | — |
| `Gum::attach(self, symbol : Bytes, on_enter : (InvocationContext) -> Unit, on_leave : (InvocationContext) -> Unit) -> HookId raise GumError` | `symbol` 只读；两个回调经 FuncRef+`#owned` 传 C 侧 | `HookId` / `AttachFailed`、`UnknownSymbol` | **回调在被钩线程同步、可重入**；禁止阻塞/跨线程 JNI | GObject vtable 胶水、事务配平、重入保护 |
| `Gum::detach(self, hook_id : HookId) -> Unit raise GumError` | `hook_id` 由 attach 返回 | `Unit` / `DetachFailed`、`NotInitialized` | **不会二次释放，重复调用返回明确错误**（重复 detach → `DetachFailed`；已 close → `NotInitialized`）；释放 listener 与 `#owned` 闭包 | — |
| `Gum::memory_read(self, address : Address, length : Int) -> Bytes raise GumError` | `self` 只读 | 原始字节 / `InvalidAddress`、`MemoryReadFailed` | 缓冲由 MoonBit 持有；校验长度 | 地址有效性 |
| `Gum::memory_write(self, address : Address, data : Bytes) -> Unit raise GumError` | `data` 只读 | `Unit` / `MemoryWriteFailed` | 调用方须保证目标页可写与 W^X | mprotect 策略 |
| `Gum::modules(self) -> Array[ModuleInfo] raise GumError` | `self` 只读 | 模块列表 / `ModuleEnumerateFailed` | 枚举结果由 `mb_gum_modules_free` 释放 | — |
| `Gum::regions(self) -> Array[MemoryRegion] raise GumError` | `self` 只读 | 内存区间列表 | 用于定位目标 .so 基址 | `/proc/self/maps` 或 gum API |

## 非目标 / 能力边界

设备发现 / spawn-attach / 传输 / QuickJS-V8 脚本运行时（frida-core）· Java 方法 hook（需 ART + frida-java-bridge）· Stalker 指令跟踪（当前不声明）· 符号解析 · 断点管理。

## 状态与已知阻塞

`moon clean` / `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check`：✅ 全部 exit 0，**4 个测试全过**（1 黑盒 + 3 白盒，测试数与既有 4 个基线持平）。

快照对账：可见性收敛前 `../pkg.generated.mbti` 中 `mb_gum_*` 导出恰为 **12 个**；收敛后仓内 `../pkg.generated.mbti` 已显示 **0 个** `mb_gum_*` 导出、`GumState` 仅 `Initialized`（该文件由 `moon check` 的 `rr_moon_pkg` 特性在门禁运行中**自动再生成**；未手动运行 `moon info`、未手工编辑该文件），与本节及 `_build` 接口文件逐项一致。
**实现门禁**：G1（15 个 subprojects 许可逐项审查）+ G2（更小替代评估）**保持开放**（状态见 `DECISIONS.md`「门禁状态」），真实 frida-gum devkit 链接仍被阻塞，当前不触碰。
