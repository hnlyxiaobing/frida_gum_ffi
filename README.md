# frida_gum_ffi · Frida Gum 插桩封装

> 独立发布单元 ｜ L2 动态验证 ｜ `preferred_target = native` ｜ Apache-2.0
> 状态：`moon test` **21/21** 通过（2026-11-16 本机实测，黑盒 5 + 白盒 16，零 `#skip`）；本文件是本仓库入口说明文档（设计与测试文档见 `docs/`，变更记录见 `docs/CHANGELOG.md`）。
> 公开 API 以 `pkg.generated.mbti` 为准（由 `moon info` 生成，禁手工编辑）；加法性变更须登记簿记 + 快照审阅 + 快照门禁。

## 1. 定位与边界

为 Frida Gum 提供进程内插桩的最小 MoonBit FFI 面；在许可门禁解除前只用桌面 stub 验证接口与线程模型。

**能力**

- `Gum` 十二个方法：九个基础方法（含 `pump_callbacks`）+ `attach_address`（地址语义）+ `pending_callbacks` / `dropped_callbacks`（队列可观察值）；`InstrumentationBackend` trait 三方法已有 `impl ... for Gum`
- 18 个活跃包私有 `mb_gum_*` 生产 shim（含 `mb_gum_marshal_drain` / `mb_gum_attach_address` / `mb_gum_marshal_pending` / `mb_gum_marshal_dropped`），`.mbti` 导出 0 个；另 14 个测试缝仅供白盒测试
- 回调线程安全：被钩线程只入队，owner 线程 `pump_callbacks` 派发（队列容量 256，满则丢弃计数，可经 `dropped_callbacks` 观察）
- `GumError` 13 构造（只读 suberror，下游不可构造），含 `LicenseReviewRequired` / `PtraceDenied` 两个门禁可观察信号；13/13 变体均有显式触发用例

**非目标**

- 不获取/落盘 gum devkit 或源码包（G1 闭环前禁止）
- 不做 Java hook、不假定 root；本库为独立发布单元，无跨库 import

## 2. 关键设计决策（本仓库自足记录）

- 延后 devkit，设 G1（许可）+ G2（更小替代）双门禁；frida-gum 许可为 **wxWindows Library Licence 3.1**。
- G1 事实层已完成 15/15 个 `subprojects/*.wrap` 组件许可清单（libdwarf 的 `dwarfdump/` 为 GPL-2 隐患、libsoup 钉定树 LGPL v2、xz 0BSD、sqlite 公有领域），**法务终裁未取得，G1 未通过**；G2 设计侧评估已登记、真实链接验证未做。
- 回调不在被钩线程执行 MoonBit 闭包（设计不变量 I1–I6）；`#owned` 闭包在 detach/close 成对 decref。
- **回调桥**：`FuncRef[(() -> Unit) -> Unit]` 无捕获适配器（`fn(f) { f() }`）+ `#owned` 捕获闭包二元组；触发为 borrow 约定（不 incref，rc 恒 1）。
- **E1 marshal 线程收敛**：被钩线程只浅拷贝入互斥队列（Win32 SRWLOCK / POSIX pthread_mutex，容量 256，满则丢弃并计数），owner 线程经 `pump_callbacks` 派发、可重入；detach/close 滞留事件安全丢弃。
- **shim 可见性收敛**：全部 `mb_gum_*` C 声明包私有，不出现在 `pkg.generated.mbti`；对外唯一入口是 `Gum` 方法与类型。
- **冻结口径（已知且钉住，不改既有语义）**：`hook_count` 为预留字段恒 0，hook 计数以 `mb_gum_test_live_hooks` 测试缝为准；`memory_write` 失败统一映射 `MemoryWriteFailed`（`memory_read` 区分 `InvalidAddress`，不对称是冻结现状）；`point` 非 1 一律归 `Leave`。
- **桌面 stub 世界容量**：3 符号（target_add / target_concat / target_swap）/ 2 模块 / 4 区间 / 最多 8 hook / 固定 2 args / 4096B 模拟内存；记录格式小端同构（见 `stub/mb_gum_stub.c` 头部契约）。
- `GumState` 仅 `Initialized`；`preferred_target = native`。

## 3. 公开 API 索引（自动抽取 `pkg.generated.mbti` 的 `pub` 声明行；完整字段见快照）

```text
pub(all) struct Gum {
pub fn Gum::attach(Self, Bytes, (InvocationContext) -> Unit, (InvocationContext) -> Unit) -> UInt64 raise GumError
pub fn Gum::attach_address(Self, UInt64, (InvocationContext) -> Unit, (InvocationContext) -> Unit) -> UInt64 raise GumError
pub fn Gum::close(Self) -> Unit raise GumError
pub fn Gum::detach(Self, UInt64) -> Unit raise GumError
pub fn Gum::dropped_callbacks(Self) -> Int32 raise GumError
pub fn Gum::init() -> Self raise GumError
pub fn Gum::memory_read(Self, UInt64, Int32) -> Bytes raise GumError
pub fn Gum::memory_write(Self, UInt64, Bytes) -> Unit raise GumError
pub fn Gum::modules(Self) -> Array[ModuleInfo] raise GumError
pub fn Gum::pending_callbacks(Self) -> Int32 raise GumError
pub fn Gum::pump_callbacks(Self, Int32) -> Int32 raise GumError
pub fn Gum::read(Self, UInt64, Int32) -> Bytes raise GumError
pub fn Gum::regions(Self) -> Array[MemoryRegion] raise GumError
pub impl InstrumentationBackend for Gum
pub(all) enum GumState {
pub(all) struct InvocationContext {
pub(all) struct MemoryProtection {
pub(all) struct MemoryRegion {
pub(all) struct ModuleInfo {
pub(all) enum PointCut {
pub suberror GumError { 13 变体，含 LicenseReviewRequired / PtraceDenied 门禁信号 }
pub trait InstrumentationBackend { fn attach(Self, UInt64) -> UInt64 raise GumError; fn detach(Self, UInt64) -> Unit raise GumError; fn read(Self, UInt64, Int32) -> Bytes raise GumError }
pub type Address = UInt64
pub type HookId = UInt64
#external pub type GumRuntimeRaw / GumInterceptorRaw / GumListenerRaw / GumModuleRaw
```

trait 为**地址语义**（`attach(Self, UInt64)`），符号语义入口是 `Gum::attach(Self, Bytes, ...)`；地址入口 `attach_address` 与 trait 实现已交付（W3，见 `docs/CHANGELOG.md`）；`Gum::read` 为 trait read 的显式方法提升，与 `memory_read` 逐字节等价。

## 4. 依赖、平台与许可

零第三方依赖（仅 `stub/mb_gum_stub.c`）；`preferred_target = native`；Apache-2.0。

## 5. 命令行与验证

- `cmd/main` 为模板 demo（init → modules/regions → memory → detach → close），非发布 CLI；**失败退出码 1（fail-closed）**，成功 exit 0；`moon run cmd/main -- --selftest-fail` 为确定性失败自测（走真实公开 API 失败路径）。
- 复验：`moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` → `moon info` 后检查 `pkg.generated.mbti` 无意外 diff。
- 本仓库为独立 Git 仓库，文档与 CI 均自包含，不依赖工作区其他目录。

## 6. 风险与未决

- G1 法务终裁与 G2 真实链接验证均未闭环，本库不得进入真实对接。
- E1 原 Linux pthread 直调实验在本机 Windows 未实测。
- 更小替代（ShadowHook / bhook / xHook）评估显示仍缺 `GumInvocationListener` 等价物，但 G2 最终选型待真实验证后裁决。

