///|
/// ---- GumInvocationListener vtable 胶水 · 接口预留契约（本文件仅契约文档，无声明）----
///
/// 本节是 G1→G2 解禁后「真实 GObject listener 胶水」的**接口预留与类型设计**，
/// 不链接任何真实二进制（本仓库 G1/G2 门禁决策 红线）。预留签名当前声明于
/// `frida_gum_ffi_wbtest.mbt`「listener vtable 胶水（接口预留）」节（与其余测试缝同
/// 处置：仅供白盒测试调用，规避 `--deny-warn` 的 unused_value 告警；真实胶水落地时
/// 随实现迁入 `internal.mbt` 并由 C shim 内部构造），符号由 `stub/mb_gum_stub.c`
/// 的契约模拟实现提供，白盒测试验证线程契约与生命周期配平。
///
/// 预留签名（C 符号同名，`GumListenerRaw` = C `void*`）：
///
/// ```moonbit
/// #owned(closure)
/// extern "C" fn mb_gum_listener_glue_create(
///   hook_id : UInt64,
///   cb : FuncRef[(() -> Unit) -> Unit],
///   closure : () -> Unit,
/// ) -> GumListenerRaw = "mb_gum_listener_glue_create"
///
/// extern "C" fn mb_gum_listener_glue_on_enter(
///   listener : GumListenerRaw,
///   arg0 : UInt64,
///   arg1 : UInt64,
/// ) -> Int32 = "mb_gum_listener_glue_on_enter"
///
/// extern "C" fn mb_gum_listener_glue_on_leave(
///   listener : GumListenerRaw,
///   arg0 : UInt64,
///   arg1 : UInt64,
///   ret : UInt64,
/// ) -> Int32 = "mb_gum_listener_glue_on_leave"
///
/// extern "C" fn mb_gum_listener_glue_destroy(
///   listener : GumListenerRaw,
/// ) -> Int32 = "mb_gum_listener_glue_destroy"
/// ```
///
/// 真实胶水的职责边界（本仓库回调线程契约，实现时不得偏离）：
///   1. GObject 侧：class_init/instance_init 注册 `on_enter` / `on_leave` 两个
///      `GumInvocationListenerInterface` vtable 槽，并管理 listener 实例生命周期；
///   2. 两个槽函数由**被钩线程**同步调用、可重入——其唯一职责是把
///      `GumInvocationContext`（point/depth/thread_id/fn_addr/args/return_value）
///      **浅拷贝**为 marshal 记录入队；**禁止**直接执行 MoonBit 闭包、禁止阻塞、
///      禁止跨线程 JNI、禁止保存栈上指针；
///   3. MoonBit 闭包 (cb, closure) 对由胶水以 `#owned(closure)` 长期持有，
///      仅在 owner 线程的派发泵（`Gum::pump_callbacks` → `mb_gum_marshal_drain`）
///      中执行；destroy / detach / close 时 `moonbit_decref` 成对释放；
///   4. 与 hook 的绑定关系由 C 侧 listener 状态机维护，MoonBit 侧不携带跨线程状态。
///
/// stub 模拟口径（`stub/mb_gum_stub.c` 同名符号）：create 校验 hook 存在并接管
/// 闭包所有权（无论成败都释放）；on_enter/on_leave 只入队（返回 0，队列满返回 6）；
/// destroy 成对释放闭包（重复销毁返回 8、不二次释放）；close 释放未销毁胶水。
