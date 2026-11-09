///|
/// frida-gum 插桩核心的 C-FFI 契约。
///
/// 本文件：外部句柄声明、`extern "C"` 薄 shim 签名、中性值类型、错误模型与 trait。
/// 公开 API 实现见 `gum.mbt`；私有 shim 与记录解析见 `internal.mbt`；
/// 桌面 C shim stub（模拟 interceptor 表 / 内存区 / 模块与区间表）见 `stub/mb_gum_stub.c`。
/// 没有设备发现/传输/脚本运行时、没有 Java 方法 hook。
///
/// 能力边界（见 DECISIONS.md「能力边界」）：仅进程内插桩（Interceptor / Memory / Module）；
/// device 发现、spawn/attach、传输、QuickJS/V8 运行时属 frida-core，不在本库。
/// Java 方法 hook 需 ART 插桩与 frida-java-bridge（Frida 17+ 不再捆绑），亦不在本库。
///
/// 回调与线程总则：on_enter/on_leave 同步执行在**被钩线程**、可重入；
/// MoonBit `FuncRef` 只能是无捕获闭包，因此回调状态（JavaVM*/global ref/attach 状态）
/// 必须下沉到 C shim 或 `#external` 句柄，不能靠 MoonBit 闭包携带。
/// 许可：frida-gum = wxWindows Library Licence 3.1（LGPL-2.0-or-later + 静态链接例外），
/// 但 subprojects 的 15 个上游组件许可需逐个核对；分发前须法务复核。

///|
#external
pub type GumRuntimeRaw

///|
#external
pub type GumInterceptorRaw

///|
#external
pub type GumListenerRaw

///|
#external
pub type GumModuleRaw

///|
/// 进程内虚拟地址。
pub type Address = UInt64

///|
/// hook 标识（由本库分配，用于 detach）。
pub type HookId = UInt64

///|
/// 内存区域权限。
pub(all) struct MemoryProtection {
  read : Bool
  write : Bool
  execute : Bool
}

///|
/// 模块内存区间（`/proc/self/maps` 语义）。
pub(all) struct MemoryRegion {
  base : Address
  end : Address
  protection : MemoryProtection
  path : String
}

///|
/// 已加载模块摘要。
pub(all) struct ModuleInfo {
  name : String
  path : String
  base : Address
  size : UInt64
}

///|
/// 回调截断位置。
pub(all) enum PointCut {
  Enter
  Leave
}

///|
/// 一次调用的上下文快照（只读；不含 CPU 寄存器原始指针，避免跨线程悬挂引用）。
pub(all) struct InvocationContext {
  hook_id : HookId
  point_cut : PointCut
  thread_id : UInt64
  depth : Int32
  function_address : Address
  args : Array[UInt64]
  return_value : UInt64?
}

///|
/// 运行时状态机（死分支收紧决策，见 DECISIONS.md：仅保留实际代码路径使用到的分支）。
/// 实现只在 `Gum::init` 成功时置为 `Initialized`，其余状态从未被构造或匹配，
/// 故 `Uninitialized` / `Attached` / `Closed` 三个死分支已删除（不补齐状态机）。
pub(all) enum GumState {
  Initialized
}

///|
/// MoonBit 侧运行时包装值。`runtime` 为进程级单例句柄，禁止并发 init/deinit。
pub(all) struct Gum {
  runtime : GumRuntimeRaw
  interceptor : GumInterceptorRaw
  state : GumState
  hook_count : Int32
}

///|
/// FFI / 插桩错误模型。
#derive(Debug)
pub suberror GumError {
  NotInitialized
  AlreadyInitialized
  DevkitNotFound(String)
  AttachFailed(Int32, String)
  DetachFailed(Int32, String)
  UnknownSymbol(String)
  InvalidAddress(Address)
  MemoryReadFailed(Address, Int32)
  MemoryWriteFailed(Address, Int32)
  ModuleEnumerateFailed(Int32)
  CallbackBridgeFailed(String)
  PtraceDenied(String)
  LicenseReviewRequired(String)
}

///|
pub extend GumError with Debug::{to_repr}

///|
/// 插桩后端契约；`ptrace_lite` 是同类备选，二者不得互相依赖，由组合根二选一。
pub trait InstrumentationBackend {
  fn attach(Self, Address) -> HookId raise GumError
  fn detach(Self, HookId) -> Unit raise GumError
  fn read(Self, Address, Int32) -> Bytes raise GumError
}

///|
/// ---- 外部 C shim 声明（包私有 · 私有实现 ABI，非公共 API）----
/// 符号由项目自带的桌面 stub `stub/mb_gum_stub.c` 提供，一对一模拟 gum C API 语义。
/// 链接真实 frida-gum devkit 受 G1 许可审查 + G2 更小替代评估双门禁（见 DECISIONS.md）约束，当前不做。
///
/// 可见性（shim 可见性收敛决策，见 DECISIONS.md）：本节 12 个 `mb_gum_*` 已由 `pub` 收敛为包私有，
/// 仅供 `gum.mbt` / 包内白盒测试调用，**不出现在 `moon info` 快照（pkg.generated.mbti）中**。
/// 对外唯一入口是 `gum.mbt` 的 `Gum::{init,close,attach,detach,memory_read,memory_write,modules,regions}`。

///|
/// 初始化嵌入式 gum 运行时（`gum_init_embedded`）。进程级，必须且只能调用一次。
extern "C" fn mb_gum_init_embedded() -> GumRuntimeRaw = "mb_gum_init_embedded"

///|
/// 反初始化（`gum_deinit_embedded`）；调用后所有句柄失效。
extern "C" fn mb_gum_deinit_embedded(runtime : GumRuntimeRaw) -> Unit = "mb_gum_deinit_embedded"

///|
/// 获取进程内唯一 Interceptor（借用语义，不释放）。
extern "C" fn mb_gum_interceptor_obtain(
  runtime : GumRuntimeRaw,
) -> GumInterceptorRaw = "mb_gum_interceptor_obtain"

///|
/// 批量挂 hook 的事务边界：`begin=1` 开启，`begin=0` 提交并激活。
extern "C" fn mb_gum_transaction(
  interceptor : GumInterceptorRaw,
  begin : Int32,
) -> Int32 = "mb_gum_transaction"

///|
/// 按符号名挂 hook；`symbol` 为 `#borrow`，C 侧只读取。返回 hook id（0 表示失败）。
#borrow(symbol)
extern "C" fn mb_gum_attach(
  interceptor : GumInterceptorRaw,
  symbol : Bytes,
) -> UInt64 = "mb_gum_attach"

///|
/// 摘除 hook 并释放对应 listener 句柄。
extern "C" fn mb_gum_detach(
  interceptor : GumInterceptorRaw,
  hook_id : UInt64,
) -> Int32 = "mb_gum_detach"

///|
/// 注册 on_enter/on_leave 适配器。`closure` 为 `#owned`：gum 长期持有回调，
/// detach 时须由 shim `moonbit_decref`。`cb` 为无捕获 `FuncRef`，
/// 真正的回调状态（JNI attach / global ref）保存在 C 侧 listener 中。
#owned(closure)
extern "C" fn mb_gum_set_callbacks(
  interceptor : GumRuntimeRaw,
  hook_id : UInt64,
  cb : FuncRef[(() -> Unit) -> Unit],
  closure : () -> Unit,
) -> Int32 = "mb_gum_set_callbacks"

///|
/// 读进程内存；`dst` 由 C 侧填充，`#borrow` 表示 MoonBit 保留所有权。
#borrow(dst)
extern "C" fn mb_gum_memory_read(
  address : Address,
  dst : FixedArray[Byte],
  length : Int32,
) -> Int32 = "mb_gum_memory_read"

///|
/// 写进程内存；`src` 为 `#borrow`，C 侧只读取。
#borrow(src)
extern "C" fn mb_gum_memory_write(
  address : Address,
  src : Bytes,
  length : Int32,
) -> Int32 = "mb_gum_memory_write"

///|
/// 枚举已加载模块，返回 C 侧数组句柄（借用；由 `mb_gum_modules_free` 释放）。
extern "C" fn mb_gum_enumerate_modules() -> GumModuleRaw = "mb_gum_enumerate_modules"

///|
/// 读取模块数组的第 `index` 项到调用方缓冲；返回 1 表示有效，0 表示结束。
#borrow(dst)
extern "C" fn mb_gum_module_at(
  modules : GumModuleRaw,
  index : Int32,
  dst : FixedArray[Byte],
  capacity : Int32,
) -> Int32 = "mb_gum_module_at"

///|
/// 释放模块枚举结果（唯一释放点）。
extern "C" fn mb_gum_modules_free(modules : GumModuleRaw) -> Unit = "mb_gum_modules_free"

///|
/// ---- MoonBit 侧公开 API ----
/// `Gum::{init,close,attach,detach,memory_read,memory_write,modules,regions}`
/// 的实现见 `gum.mbt`（签名与 API.md / pkg.generated.mbti 一致）。
