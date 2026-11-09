# hnlyxiaobing/frida_gum_ffi

**frida-gum 插桩核心的 C-FFI 封装 —— 为 MoonBit 程序提供函数 hook、内存读写与模块枚举能力。**

> 状态（2026-11-07）：**桌面 stub 实现已落地**（`stub/mb_gum_stub.c` 模拟 interceptor 表 / 内存区 / 模块与区间表），`Gum::{init,close,attach,detach,memory_read,memory_write,modules,regions}` 8 个 API 均已实现，`moon test` **4/4 全过**（1 黑盒 + 3 白盒），`moon clean` / `moon check --deny-warn` / `moon build` / `moon test` / `moon fmt --check` 五项门禁全绿。12 个 `mb_gum_*` C shim 已由 `pub` 收敛为**包私有**（私有实现 ABI，非公共 API，不再出现在 `moon info` 快照）。
> `preferred_target` 已由 `wasm` 改为 `native`（唯一配置改动，理由见 `DECISIONS.md`「`preferred_target = "native"`」）。
> **实现门禁（见 `DECISIONS.md`「G1 / G2 双门禁」）**：**真实 frida-gum devkit 链接仍不进入实现候选**，须先通过「G1 许可审查 + G2 更小替代方案评估」两道门禁（当前保持开放）；当前只链接自带桌面 stub，不下载/引入任何 devkit。

## 定位与为什么存在

**成本判定**（2026-11-06 检索 mooncakes.io，`frida` / `gum` / `ptrace` 关键词均无可用包）：MoonBit C-FFI 已足够强（`extern "C"`、`#external`、`FuncRef`、`#borrow/#owned`、`native-stub`），frida-gum 是 C 库，绑定在语言层面可行。但真正的成本在**回调桥接、线程安全与许可**，不在语言能力（背景与决策见 `DECISIONS.md`）。

**三处常见误解的更正**（开发期核对结论，许可细节与证据等级见 `LICENSE-AUDIT.md`）：

1. **许可**：frida-gum 与 frida-core 的 `COPYING` **主体一致**，均为 **wxWindows Library Licence 3.1**（LGPL-2.0-or-later + `EXCEPTION NOTICE` 第 2 条静态链接例外），不是「LGPL/wxWindows 混合」；但非逐字相同——gum 的 `COPYING`（5696B）另附第三方 BSD-3-Clause 片段声明（Mozilla/Closure/regenerator 三段版权与免责声明），core 的（2416B）无附录（详见 `LICENSE-AUDIT.md`）。但 15 个 `subprojects/*.wrap` 上游组件许可待核，且静态链接进闭源 App 的解读须法务复核（两项均未决，见 `DESIGN.md` §12 风险与待验证）。
2. **能力边界**：gum 只做进程内插桩；设备发现 / spawn-attach / 传输 / QuickJS-V8 运行时属 **frida-core**；Java 方法 hook 需 ART 插桩 + `frida-java-bridge`，且 **Frida 17.0.0 起 bridges 不再捆绑**。本库单独做不到 Java hook。
3. **更小替代**：ShadowHook / bhook / xHook / Dobby / And64InlineHook 均为 MIT 或 Apache-2.0、免 root、体积远小于 gum devkit。

## 能力范围 / 非目标

- **做**：`gum_init_embedded` / `deinit_embedded`、Interceptor 事务、`attach` / `detach`、`on_enter` / `on_leave` 回调注册、进程内存读写、模块与内存区间枚举。
- **不做**：设备发现 / 注入 / 传输 / 脚本运行时（frida-core）、Java 方法 hook（ART bridge）、Stalker 指令跟踪（当前不声明）、符号解析（配 `dwarfscope`）、断点管理。
- 与 `ptrace_lite` **互斥备选、零互相 import**，由组合根二选一（见 `DECISIONS.md`「与 `ptrace_lite` 互斥备选」）。

## 公开接口（速览）

`Gum::{init, close, attach, detach, memory_read, memory_write, modules, regions}`（均已实现，桌面 stub）。外部句柄清单见 `API.md`；12 个 `mb_gum_*` C shim 为**包私有的私有实现 ABI，非公共 API**，只能经 `Gum::*` 使用。

生命周期统一措辞：**`Gum::close` / `Gum::detach` 不会二次释放，重复调用返回明确错误**（重复 close → `NotInitialized`；重复 detach → `DetachFailed`，运行时已关闭 → `NotInitialized`）。

## 依赖

- **当前依赖**：零第三方依赖；只链接自带 `stub/mb_gum_stub.c` 桌面 stub，**不下载、不链接 frida-gum devkit**。独立 `moon.mod`，五项门禁独立通过。
- 门禁通过后的后续阶段：Frida releases 的 `libfrida-gum.a` devkit（16.x arm64 约 9–16 MB）、GObject `GumInvocationListener` vtable 胶水。

## 平台与许可风险

| 风险 | 说明 |
|---|---|
| **许可（G1 门禁）** | wxWindows 3.1 例外第 2 条允许以自有条款分发静态链接二进制，但 15 个上游 `.wrap` 组件许可未逐项核对；法律解读高度版本/辖区相关，须法务复核 |
| **更小替代（G2 门禁）** | 必须至少评估 ShadowHook(MIT, 免 root, API 16–37) / bhook / xHook 之一，并说明为何 gum 仍必需；若替代够用则注销本库实现任务 |
| 平台 | `preferred_target = "native"`；Linux x86-64 桌面可验证；Android 需 root 或 `PTRACE_ATTACH` 权限 |
| 部署 | 官方排错文档明确 root / `kernel.yama.ptrace_scope=0`；W^X / SELinux 对 `mprotect(PROT_WRITE|PROT_EXEC)` 的限制来自技术博客，**待实测**（见 `DESIGN.md` §12 风险与待验证） |
| 线程 | `on_enter`/`on_leave` 同步跑在**被钩线程**、可重入；MoonBit 运行时在该线程执行闭包的线程安全**未实测**（最高优先待验证项，见 `DESIGN.md` §12） |
| 体积 | devkit 数 MB；`[待验证假设]` 17.25.2 gum devkit 实际尺寸（见 `DESIGN.md` §12） |

## 测试与验收

- **测试策略**：当前为桌面 stub 全链路（init → attach → memory 读写回环 → modules/regions → detach → close）、回调重入与事务配平、闭包引用计数成对、缓冲容量校验、许可/ptrace 门禁可观察路径；G1/G2 通过后的真实实现阶段再做 x86-64 Linux hook libc、Android arm64 入口 hook 与许可清单核对。
- **验收标准**（真实实现阶段，门禁通过后）：hook 生效且 detach 无悬挂；许可审查通过；回调线程安全实测通过。
- **门禁实跑**：`moon clean` → `moon check --deny-warn` → `moon build` → `moon test` → `moon fmt --check` 全部 exit 0；`moon test` 输出 `Total tests: 4, passed: 4, failed: 0`（测试数与既有 4 个基线持平）。

## 当前状态 / 产物

| 项 | 状态 |
|---|---|
| `frida_gum_ffi.mbt`：`#external` 句柄 ×4、`mb_gum_*` shim ×14（**全部包私有**，其中 12 个已由 `pub` 收敛）、`Gum::*` API ×8（已实现） | ✅ |
| `GumState` 收紧（死分支收紧决策，见 `DECISIONS.md`）：仅 `Initialized`，死分支 `Uninitialized`/`Attached`/`Closed` 已删 | ✅ |
| `pkg.generated.mbti` API 快照 | ✅ 已同步为新导出面（**0 个 `mb_gum_*`**、`GumState` 仅 `Initialized`）；由 `moon check` 自动再生成，未手工编辑 |
| devkit 链接 / GObject 胶水 / 真实 gum 运行时 / 许可审查（G1/G2） | ❌ 后续阶段（门禁保持开放） |
| 五项门禁（clean / check --deny-warn / build / test / fmt --check） | ✅ 全部 exit 0，4/4 测试通过 |

## 文档索引

`DESIGN.md`（设计契约）· `API.md`（公开接口）· `DECISIONS.md`（设计决策与门禁状态）· `LICENSE-AUDIT.md`（许可盘点与合规含义）。本文档集自足，不依赖仓库外文件。
