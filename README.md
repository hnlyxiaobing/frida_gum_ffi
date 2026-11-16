# frida_gum_ffi · Frida Gum 插桩封装

> 独立发布单元 ｜ L2 动态验证 ｜ `preferred_target = native` ｜ Apache-2.0
> 状态：`moon test` **12/12** 通过（2026-11-11 本机实测）；本文件是本仓库**唯一**说明文档。
> 公开 API 以 `pkg.generated.mbti` 为准（由 `moon info` 生成，禁手工编辑）；加法性变更须登记簿记 + 快照审阅 + 快照门禁。

## 1. 定位与边界

为 Frida Gum 提供进程内插桩的最小 MoonBit FFI 面；在许可门禁解除前只用桌面 stub 验证接口与线程模型。

**能力**

- `Gum` 九个方法（含 `pump_callbacks`）与 `InstrumentationBackend` trait 三方法
- 15 个活跃包私有 `mb_gum_*` shim（含 `mb_gum_marshal_drain`），`.mbti` 导出 0 个
- 回调线程安全：被钩线程只入队，owner 线程 `pump_callbacks` 派发（队列容量 256，满则丢弃计数）
- `GumError` 13 构造，含 `LicenseReviewRequired` / `PtraceDenied` 两个门禁可观察信号

**非目标**

- 不获取/落盘 gum devkit 或源码包（G1 闭环前禁止）
- 不做 Java hook、不假定 root；不与 `ptrace_lite` 互相 import

## 2. 关键设计决策（本仓库自足记录）

- 延后 devkit，设 G1（许可）+ G2（更小替代）双门禁；frida-gum 许可为 **wxWindows Library Licence 3.1**。
- G1 事实层已完成 15/15 个 `subprojects/*.wrap` 组件许可清单（libdwarf 的 `dwarfdump/` 为 GPL-2 隐患、libsoup 钉定树 LGPL v2、xz 0BSD、sqlite 公有领域），**法务终裁未取得，G1 未通过**；G2 设计侧评估已登记、真实链接验证未做。
- 回调不在被钩线程执行 MoonBit 闭包（设计不变量 I1–I6）；`#owned` 闭包在 detach/close 成对 decref。
- `GumState` 仅 `Initialized`；`preferred_target = native`。

## 3. 公开 API 索引（自动抽取 `pkg.generated.mbti` 的 `pub` 声明行；完整字段见快照）

```text
pub(all) struct Gum {
pub fn Gum::attach(Self, Bytes, (InvocationContext) -> Unit, (InvocationContext) -> Unit) -> UInt64 raise GumError
pub fn Gum::close(Self) -> Unit raise GumError
pub fn Gum::detach(Self, UInt64) -> Unit raise GumError
pub fn Gum::init() -> Self raise GumError
pub fn Gum::memory_read(Self, UInt64, Int32) -> Bytes raise GumError
pub fn Gum::memory_write(Self, UInt64, Bytes) -> Unit raise GumError
pub fn Gum::modules(Self) -> Array[ModuleInfo] raise GumError
pub fn Gum::pump_callbacks(Self, Int32) -> Int32 raise GumError
pub fn Gum::regions(Self) -> Array[MemoryRegion] raise GumError
pub(all) enum GumState {
pub(all) struct InvocationContext {
pub(all) struct MemoryProtection {
pub(all) struct MemoryRegion {
pub(all) struct ModuleInfo {
pub(all) enum PointCut {
```

## 4. 依赖、平台与许可

零第三方依赖（仅 `stub/mb_gum_stub.c`）；`preferred_target = native`；Apache-2.0。

## 5. 命令行与验证

- `cmd/main` 为模板 demo（init → modules/regions → memory → detach → close），非发布 CLI。
- 复验：`moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` → `moon info` 后检查 `pkg.generated.mbti` 无意外 diff。
- 本仓库为独立 Git 仓库，文档与 CI 均自包含，不依赖工作区其他目录。

## 6. 风险与未决

- G1 法务终裁与 G2 真实链接验证均未闭环，本库不得进入真实对接。
- E1 原 Linux pthread 直调实验在本机 Windows 未实测。
- 更小替代（ShadowHook / bhook / xHook）评估显示仍缺 `GumInvocationListener` 等价物，但 G2 最终选型待真实验证后裁决。

