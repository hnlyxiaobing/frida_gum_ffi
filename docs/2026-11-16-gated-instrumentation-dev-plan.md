# frida_gum_ffi 门禁化插桩原语：边界清理与受控演进开发文档

> 建立：2026-11-16 ｜ 状态：**W1–W6 已交付（2026-11-16），W7 选项 A 维持冻结** ｜ 适用仓库：本仓库（独立自包含）
> 配套文档：[2026-11-16-test-system-design.md](2026-11-16-test-system-design.md)（验收测试 ID `T-W*-*` 出自该文档）
> 本文所有「现状」结论均为 2026-11-16 对本仓库源码的实测核对，非转述历史文档。
> 五门禁 2026-11-16 实跑：`moon check --deny-warn` exit 0；`moon build` exit 0；`moon test` **12/12 通过**（黑盒 2 + 白盒 10，零 `#skip`）；`moon fmt --check` exit 0；`moon info` 后 `git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti` exit 0（快照零漂移）。工具链：moon 0.1.20261104 / moonc v0.10.20+65efd5b93 / moonrun 0.1.20261104（本机 Windows x64 native）。

## 0. 现状基线（实测核对，开发前必读）

| # | 事实 | 证据位置 |
|---|---|---|
| B1 | 已实现：`Gum` 9 个公开方法（init/close/attach/detach/memory_read/memory_write/modules/regions/pump_callbacks）全部有实现；`InstrumentationBackend` trait 3 方法仅声明 | `gum.mbt` 全文；`pkg.generated.mbti` L36-44、L103-107 |
| B2 | 已实现：`GumError` 13 变体（含 `LicenseReviewRequired`/`PtraceDenied` 门禁信号），与 README 口径一致 | `frida_gum_ffi.mbt` L111-125；`pkg.generated.mbti` L12-26 |
| B3 | 已实现：生产 shim 15 个（`frida_gum_ffi.mbt` 12 + `internal.mbt` 3），全部包私有，`.mbti` 导出 0 个；README「15 个活跃 shim」口径正确；历史申报口径「8 API / 14 shim」已滞后（实为 9 API / 15 生产 shim） | `frida_gum_ffi.mbt` L149-229；`internal.mbt` L19-37；`pkg.generated.mbti` 无 `mb_gum_*` |
| B4 | 已实现：listener vtable 胶水 4 个签名（create/on_enter/on_leave/destroy）为**接口预留**，声明暂居白盒测试文件；`listener_glue.mbt` 是纯契约注释（无声明）；`internal.mbt`「合计 19 个」= 15 生产 + 4 胶水，口径自洽 | `frida_gum_ffi_wbtest.mbt` L181-207；`listener_glue.mbt`；`internal.mbt` L4-7 |
| B5 | 漂移：C stub 导出 31 个符号（15 生产 + 4 胶水 + 12 测试缝），但 stub 头部注释的测试缝清单只列 10 个，缺 `mb_gum_test_live_glues` / `mb_gum_test_glue_closure_rc` | `stub/mb_gum_stub.c` L44-48 vs L1198、L1210 |
| B6 | 已实现：E1 marshal 真实落地——互斥队列（Win32 SRWLOCK / POSIX pthread_mutex）、容量 256、满则丢弃计数、drain 只在调用线程执行闭包、重入 depth+1、detach/close 滞留事件安全丢弃 | `stub/mb_gum_stub.c` L221-238、L723-836、L407-423；白盒 6 条 E1 用例 |
| B7 | 已实现：回调桥 borrow 约定注释与实现一致——触发不 incref（rc 不变），`#owned` 唯一释放点在注销 `moonbit_decref`；rc=1 断言守护 | `stub/mb_gum_stub.c` L9-14、L972-975；`frida_gum_ffi_wbtest.mbt` L84、L90 |
| B8 | 已实现：门禁可观察路径——测试缝置 gate 后 `Gum::init` 显式返回 `LicenseReviewRequired` / `PtraceDenied`，失败 init 不消耗生命周期 | `gum.mbt` L13-29；`stub/mb_gum_stub.c` L380-399；白盒「许可门禁可观察路径」 |
| B9 | 已实现：地址+len 回绕防护为减法形式边界检查（`address - BASE > SIZE - length`），UINT64_MAX 回绕被拒（R5/P1 修复真实存在） | `stub/mb_gum_stub.c` L562-566、L579-583；白盒「memory read/write address wraparound rejected」 |
| B10 | 实测基线：五门禁全绿；测试 12/12（黑盒 2 + 白盒 10）；`#skip` 全仓库 0 处；快照零漂移 | 2026-11-16 本机实跑（见文首）；`Select-String '#skip'` 计数 0 |
| B11 | **漂移（大面积）**：`docs/` 为空目录——最新提交 `e08affb` 删除全部 7 份文档（API/DECISIONS/DESIGN/E1-CALLBACK-THREAD-SAFETY/G2-ALTERNATIVES-EVAL/LICENSE-AUDIT-G1/LICENSE-AUDIT），但 `gum.mbt`/`frida_gum_ffi.mbt`/`internal.mbt`/测试/stub 中 25+ 处注释仍引用 `docs/*`；README「本文件是唯一说明文档」与这些悬空引用矛盾 | `git show --stat e08affb`；`Get-ChildItem docs` 空；Grep `docs/[A-Za-z0-9._-]+` 25+ 命中 |
| B12 | **漂移（CI/自包含）**：`ci.yml` 注释引用已删除的 `pkg.generated.mbti.r1`（L16）与 `docs/API.md`（L124 错误消息）；依赖示例 `bobzhang/zip@0.1.2` 是兄弟模块的依赖，本模块零第三方依赖（`moon.mod` 无 import）；`copilot-setup-steps.yml` 同样含 zip 示例且称「四道门禁」（ci.yml 实为五道） | `.github/workflows/ci.yml` L16、L29、L124；`copilot-setup-steps.yml` L7-8；`moon.mod` |
| B13 | **漂移（README 索引）**：README §3「自动抽取 pub 声明行」缺 `GumError`（suberror + `to_repr`）、4 个 `#external` pub type（GumRuntimeRaw/GumInterceptorRaw/GumListenerRaw/GumModuleRaw）、`Address`/`HookId` 别名、`InstrumentationBackend` trait——与快照逐条核对不完整 | `README.md` L32-49 vs `pkg.generated.mbti` 全文 |
| B14 | **缺口（错误簿记）**：13 变体中 10 个有显式断言变体名的用例；`DevkitNotFound` / `MemoryWriteFailed` / `ModuleEnumerateFailed` 显式用例数 = 0 | 对两个测试文件逐变体 grep 计数（2026-11-16） |
| B15 | **缺口（trait 空转）**：`InstrumentationBackend` 无任何 impl；且 trait `attach(Self, UInt64)` 是地址语义，`Gum::attach` 是符号名（Bytes）语义，二者无法直接对接——「经 trait 在后端间切换」目前是纯设计声明 | Grep `InstrumentationBackend` 仅 1 处声明；`frida_gum_ffi.mbt` L132-136 vs L36 |
| B16 | 事实（死字段）：`Gum.hook_count` 仅在 init 构造为 0，attach/detach 从不增减；`pub(all)` 冻结禁止删字段，只能声明为预留 | `gum.mbt` L66；Grep `hook_count` 仅 2 处 |
| B17 | 事实（映射不对称）：`memory_write` 对非法地址（status 7）映射为 `MemoryWriteFailed`，而 `memory_read` 将 7 映射为 `InvalidAddress`；旧语义冻结，不得改 | `gum.mbt` L200-208 vs L220-226 |
| B18 | **缺口（CLI fail-open）**：`cmd/main` demo 失败路径仅 println("demo failed")，进程退出码仍为 0（模板 demo，非发布 CLI，但失败不可被脚本观测） | `cmd/main/main.mbt` L32-38 |
| B19 | 计数修正：历史申报口径「15 条有效提交」实测为 **16**（`git rev-list --count HEAD`）；「8 API / 14 shim」见 B3 修正 | git 实测 2026-11-16 |
| B20 | 事实（stub 世界口径）：3 符号 / 2 模块 / 4 区间 / 最多 8 hook / 上下文固定 2 args / 4096B 模拟内存（初值 i&0xFF）；`parse_context_record` 对 argc>2 或长度不足返回 None（不 panic）；point 字节 ≠1 一律归 Leave（容错口径，非校验拒绝） | `stub/mb_gum_stub.c` L70-151；`internal.mbt` L127-164 |
| B21 | 漂移（注释命名）：`gum.mbt` L91 注释提到名为 `invoke_closure` 的适配器函数，实际不存在该命名（实为内联 `fn(f) { f() }`） | `gum.mbt` L91、L128 |
| B22 | 事实：`.githooks/pre-commit` 仅跑 `moon check`（非五门禁）；README §5 复验序列为 clean+五门禁 | `.githooks/pre-commit`；`README.md` L58 |
| B23 | 未实测：POSIX 分支（pthread_mutex/pthread_self/CreateThread→pthread_create）与 CI ubuntu 云上路径本机 Windows 未实跑；ci.yml 自注「[仍需实测]」，Windows 本机为「[已复验-本地等价]」 | `stub/mb_gum_stub.c` L60-64、L234-238、L1155-1171；`ci.yml` L57-58 |
| B24 | 自包含扫描：全仓库无工作区路径/兄弟模块文件引用；`ptrace_lite` 仅以归属声明出现（「同类备选、零互相依赖」，允许）；零第三方依赖，唯一 C 资产为项目自产 stub | Grep 工作区路径/兄弟模块名 2026-11-16；`moon.pkg` native-stub |
| B25 | 事实：`GumState` 仅 `Initialized`（死分支收紧决策已在注释自足记录）；close/detach 重复调用返回明确错误、不二次释放，有显式用例 | `frida_gum_ffi.mbt` L92-97；黑盒全链路用例 |

**对历史口径的修正**：
1. 申报口径「8 个公开 API / 14 个 shim」→ 实测 **9 个公开方法 / 15 个生产 shim**（另有 4 个胶水预留签名声明在测试文件，B3/B4）。
2. 申报口径「15 条有效提交」→ 实测 **16 条**（B19）。
3. 历史申报口径与 README 曾引用的 `docs/LICENSE-AUDIT-G1.md`、`docs/G2-ALTERNATIVES-EVAL.md`、`docs/LICENSE-AUDIT.md` 等 7 份文档**已被提交 e08affb 删除，docs/ 现为空目录**；G1 事实层清单与 G2 评估的**内容**随删除丢失，仅 README §2/§6 保留结论摘要（B11）。本文不假定这些文件可访问。
4. 「经 InstrumentationBackend trait 切换后端」→ 实测 trait **无实现且签名语义不匹配**，仅为声明性契约（B15）。
5. README「12/12 通过」与「15 shim / 13 变体」口径经重测**确认正确**，无需修正。

## 1. 硬约束（每个工作包都必须满足）

1. **API 冻结**：`pkg.generated.mbti` 为冻结基线，只允许纯加法（新 pub fn / 新 struct / 新 enum / 新 impl）。禁止给既有 `pub(all)` struct（Gum/InvocationContext/MemoryProtection/MemoryRegion/ModuleInfo）加字段；禁止新增 `GumError` 变体（四件例外：ADR + 用户裁决 + CHANGELOG + 主版本）；校验失败用值字段表达，解析失败复用既有变体；语义变更走新函数新类型防火墙，旧 API 语义永不改变（含 B17 不对称映射、B16 死字段、B20 point 容错口径）。
2. **加法三件套**：快照随源码同提交且 diff 纯加法 + CHANGELOG 登记 + CI 快照门禁绿。
3. **依赖不动**：本模块零第三方依赖（`moon.mod` 无 import）；唯一 C 资产为自产 `stub/mb_gum_stub.c`（`moon.pkg` native-stub）。工具链钉死 moon 0.1.20261104 / moonc v0.10.20+65efd5b93（ci.yml 版本断言强制）。不引入任何真实 frida-gum devkit/源码包（G1 闭环前禁止获取与落盘）。
4. **许可红线**：第三方 .so/devkit/真实样本不入库；真实差分只允许「仓库外本地路径 + SHA-256 登记 + 显式 SKIPPED」；入库测试资产一律由 stub 世界确定性自产。frida-gum 上游许可为 wxWindows Library Licence 3.1（LGPL-2.0-or-later + 静态链接例外）[已知常识]，15 个 subprojects 组件许可清单原文件已删（B11），法务终裁未取得——**G1 未通过、G2 真实链接验证未做**，本库不得进入真实对接。
5. **五门禁全绿才可合入**；`#skip`/SKIPPED 不得写成通过。fail-closed 修复（以前静默放行的不安全输入现在拒绝、失败退出码 0→1）属行为增强非契约破坏，但须 CHANGELOG 显式登记 + 回归确认仅受影响路径变化。
6. **边界不变量**：不做 Java hook、不做设备发现/传输/脚本运行时（frida-core 职责）、不假定 root、不做符号解析/内存扫描/Stalker/代码生成；不与同类备选后端（ptrace_lite，归属声明）互相 import；E1 不变量——被钩线程绝不执行 MoonBit 闭包，闭包只在 owner 线程 pump 中执行；`#owned` 闭包成对 decref、不二次释放。
7. **文档自包含**：本仓库 docs/ 与代码注释/帮助文本/脚本不得引用、链接或假定可访问工作区其他目录；跨库事务只声明归属。

## 2. 业界对标摘要（P2 结论，证据三级标注）

**渠道与限定**：2026-11-16 经公开 web 渠道（GitHub 仓库页、官方 README 镜像、技术社区文章）检索。mooncakes.io 站内搜索在此前多轮实测不可用（422/SPA 无法穷举），本轮未重试站内搜索，**不冒充已穷举 registry**。「MoonBit 生态未见同类」结论限定为：MoonBit 语言 + 「进程内 hook + 内存读写 + 模块/区间枚举」组合语义 + 2026-11-16 时点 + 公开 web 渠道。

| 能力（F#） | 本模块（B# 实测） | frida-gum / GumJS（C/JS 上游） | frida-rust（Rust 官方绑定） | funchook（C 库） | ShadowHook（C/Android 库） |
|---|---|---|---|---|---|
| F1 运行时生命周期 | init/close 单例配对、重复报错（B1/B25） | gum_init_embedded/deinit 同语义 [已知常识] | 经 devkit 链接同语义 [需联网核实：crate 细节] | create/destroy 句柄级，无进程单例 [已知常识，web 已核 API] | shadowhook_init 全局一次 [需联网核实] |
| F2 函数 hook | 符号名 attach/detach，事务配平（B1/B3） | Interceptor attach/replace，地址+符号 [已知常识] | 同上游 [需联网核实] | prepare/install/uninstall，地址替换式，可调用原函数 trampoline [已知常识，web 已核] | inline hook thumb/arm32/arm64，代理原函数 [已知常识，web 已核] |
| F3 调用上下文回调 | on_enter/on_leave + InvocationContext 值快照（B1/B6） | GumInvocationListener vtable，寄存器级上下文 [已知常识] | 同上游 [需联网核实] | 无 listener 语义，钩子函数即替换体 [已知常识] | 无 listener 语义，proxy 函数 [已知常识] |
| F4 线程收敛派发 | E1 marshal：被钩线程只入队、owner 线程 pump（B6） | 无等价物（回调在被钩线程同步执行）[已知常识] | 无等价物 [需联网核实] | 无 | 无 |
| F5 内存读写 | memory_read/write，回绕防护（B9/B17） | gum_memory_read/write + 扫描 [已知常识] | 同上游 [需联网核实] | 无 | 无 |
| F6/F7 模块/区间枚举 | modules/regions 值数组（B1/B20） | Process.enumerateModules/Ranges + 导入导出符号 [已知常识] | 同上游 [需联网核实] | 无 | 无 |
| F8 合规门禁信号 | LicenseReviewRequired/PtraceDenied 可观察（B8） | 无等价物 [已知常识] | 无 | 无 | 无 |
| F9 后端抽象 trait | 声明无实现（B15） | 无 | 无 | 无 | 无 |
| F10 listener 胶水预留 | 契约+stub 模拟+白盒（B4） | 真实 GObject vtable [已知常识] | 同上游 [需联网核实] | 无 | 无 |
| 真实插桩能力 | **无**（桌面 stub 模拟，G1/G2 门禁，B11/B23） | 真实 inline hook/Stalker/多架构 [已知常识] | 真实（需 devkit）[需联网核实] | 真实（x86/x64/arm64，Win/Linux/macOS）[已知常识，web 已核平台表] | 真实（Android arm 系）[已知常识，web 已核] |

- 证据等级：上游 gum 能力与许可 [已知常识]；frida-rust 仓库存在性与 devkit 安装方式 [需联网核实→本轮已核 GitHub 仓库页，crate 级 API 细节仍标需核实]；funchook API/平台表、ShadowHook 架构支持 [已知常识，本轮 web 已核]；各库 star/维护状态/最新版本一律 [需联网核实]，本文不给精确数字。
- **最接近 1–3 名与重叠度**：① frida-gum/GumJS（语义上游，能力重叠 ~90%，但本模块是其 MoonBit 值化子集 + stub 模拟，非真实插桩）；② frida-rust（绑定形态最接近：同样「devkit 门禁 + FFI 薄封装」，重叠 ~70%）；③ funchook / ShadowHook（hook 子集重叠 ~30%，无内存/枚举/listener 语义）。
- **差异化判断**（组合语义限定）：「MoonBit + 值类型上下文 + owner 线程 marshal 派发（E1）+ 许可门禁可观察信号」四者组合，在调研时点与渠道内未见同类；E1 线程收敛与合规前置信号是本模块独有设计，上游与替代库回调均在被钩线程同步执行。
- **缺失能力清单**：
  - 已声明非目标（不做）：Java hook、frida-core 职责（设备/传输/脚本运行时）、root 假定、Stalker/内存扫描/代码生成/符号解析、真实 devkit 链接（G1/G2 门禁未过）。
  - 真缺口（本轮工作包来源）：trait 无实现且语义不匹配（B15→W3）；3 个错误变体零显式用例（B14→W2）；demo 失败退出码 0（B18→W4）；marshal 队列状态对用户不可观察（B6 仅测试缝可见→W5）；解析路径无截断/变异扫描（B20→W6）；docs 悬空引用与 CI 漂移（B11/B12/B13/B5/B21→W1）；真实插桩能力整体缺失（门禁锁定→W7 须裁决）。

## 3. 边界裁决（P3 结论）

**本质职责（一句话）**：为 MoonBit 提供「值化、线程收敛、合规可观察」的进程内插桩原语契约面——hook 谁在调用、字节在哪、门禁是否放行；后端真实性由 G1/G2 门禁锁定，契约面与模拟后端同构演进。

**边界判据**：一个能力属于本库，当且仅当它同时满足 (a) 进程内原语（hook/内存/模块区间）或其契约/合规信号；(b) 输出为值类型、不携带跨线程悬挂引用；(c) 不要求真实二进制链接即可在 stub 世界验证。三条任一不满足 → 界外（frida-core 职责、Java/ART 语义、真实 devkit 工程）。

| 灰区 | 判据结论 | 裁决 | 落点（W#） |
|---|---|---|---|
| `InstrumentationBackend` trait 地址语义 vs `Gum::attach` 符号语义，且无 impl（B15） | 界内（契约面），但当前空转 | 冻结 trait 签名不动；选项 A 新增地址 attach + impl 补齐（纯加法），选项 B 零成本声明「预留契约」，选项 C 归属未来独立契约包（本轮只登记） | W3（须裁决） |
| `Gum.hook_count` 死字段（B16） | 界内但冻结 | 不删字段（pub(all) 冻结）；README/注释声明为预留；活跃 hook 数经 C 侧测试缝可观测，不新增公开字段 | W1（声明） |
| `memory_write` 非法地址映射不对称（B17） | 界内、旧语义冻结 | 不改映射（防火墙）；W2 用显式用例钉住现状，README 登记不对称口径 | W2 |
| point 字节 ≠1 归 Leave 的容错口径（B20） | 界内、旧语义冻结 | 不改解析语义；W6 截断扫描钉住「畸形记录 → None 或声明口径，绝不 panic」 | W6 |
| stub 世界容量（8 hook/2 args/3 符号，B20） | 模拟后端固有界 | 声明为 stub 契约而非缺口；真实容量属 W7 真实后端议题 | W1（声明）/W7 |
| docs/ 已删但注释悬空引用（B11/B12/B13/B5/B21） | 自包含纪律 violations | 不恢复已删文档（README 唯一说明文档决策尊重）；注释改写为仓库内自足表述；CI 失效引用清理 | W1 |
| 真实 devkit 链接与真实 hook（G1/G2） | 界外（门禁锁定），解冻后界内 | 保持门禁信号与 stub 同构；真实对接拆里程碑、须用户裁决 | W7（须裁决） |
| 与同类备选后端（ptrace_lite）的 trait 归属 | 跨库事务 | 只声明归属：trait 定义在本库，组合根二选一、零互相 import；不搬代码 | W3 选项 C 登记 |

## 4. 工作包总览

| 包 | 名称 | 优先级 | 规模 | API 影响 | 对应缺口（B#） |
|---|---|---|---|---|---|
| W1 | 文档自包含与悬空引用清理 | P0 | S | 无 | B5/B11/B12/B13/B16/B20/B21 |
| W2 | 错误变体触发补齐（13/13） | P0 | S | 无（仅 C 测试缝） | B14/B17 |
| W3 | 地址 hook 与 trait 落地（已裁决：选项 A） | P1 | M | 加法：`Gum::attach_address` + impl | B15 |
| W4 | demo 失败退出码 fail-closed | P1 | S | 无（cmd/main 私有） | B18 |
| W5 | marshal 队列可观察值查询 | P2 | S | 加法：2 个 pub fn | B6（用户侧不可观察） |
| W6 | L1 性质/截断扫描与变异自检 | P2 | M | 无（仅测试） | B20/B9 |
| W7 | 真实 devkit 对接与真实 hook（已裁决：选项 A 维持冻结） | P3 | XL | 加法（门禁解冻后） | 真实插桩整体缺失 |

## 5. 工作包详细设计

### W1 文档自包含与悬空引用清理（P0/S）

**目标**：消除 B11/B12/B13/B5/B21 全部漂移，使「README 唯一说明文档」决策与代码注释/CI 文本一致。
**非目标**：不恢复已删除的 7 份 docs 文档；不改任何公开 API 与运行时行为；不重写 README 结构。
**新增 API（mbti 草案，纯加法）**：无。
**实现要点**：
- `gum.mbt`/`frida_gum_ffi.mbt`/`internal.mbt`/两个测试文件/`stub/mb_gum_stub.c` 中全部 `docs/DECISIONS.md`、`docs/API.md`、`docs/DESIGN.md`、`docs/E1-CALLBACK-THREAD-SAFETY.md` 引用改写为「见 README §1/§2」或把关键决策 inline 进注释（E1 不变量、回调桥二元组、门禁红线已在 README 有摘要，注释保留结论、去掉文件指向）；`gum.mbt` L91 `invoke_closure` 改为「内联无捕获适配器 `fn(f) { f() }`」。
- `ci.yml`：删除 `pkg.generated.mbti.r1` 注释段（L16-17 改为「快照纳入范围 = 仓库根与 cmd/main 两处」）；L124 错误消息 `docs/API.md` 改为「本仓库 README 与 docs/CHANGELOG.md」；L29 依赖示例改「本模块零第三方依赖；如未来引入，按 moon.mod 钉死版本」。
- `copilot-setup-steps.yml`：L7 zip 示例同上；L8「四道门禁」改「五道门禁」。
- stub 头部测试缝清单补 `mb_gum_test_live_glues` / `mb_gum_test_glue_closure_rc`（10→12）。
- README §3 索引补齐：`pub suberror GumError`（13 变体）、`GumError::to_repr`、4 个 `#external` pub type、`Address`/`HookId` 别名、`InstrumentationBackend` trait；§1 能力节补「hook_count 为预留字段」「stub 世界容量口径」「memory_write 非法地址映射为 MemoryWriteFailed（与 read 不对称，冻结口径）」。
- 新建 `docs/CHANGELOG.md`（本文件与配套测试设计文档同提交登记为首条）。
**验收**：T-W1-1（引用实存性扫描零命中）；T-W1-2（README 索引 ↔ mbti 逐条一致）；T-W1-3（五门禁全绿、快照 diff=0）；T-W1-4（防火墙：旧用例零改动全绿）。

### W2 错误变体触发补齐（P0/S）

**目标**：B14 三个零用例变体各 ≥1 条显式断言变体名的用例，簿记达 13/13；顺带钉住 B17 不对称映射。
**非目标**：不新增公开 API、不新增错误变体、不改任何既有映射语义。
**新增 API（mbti 草案，纯加法）**：无（测试缝仅声明于 `_wbtest.mbt`，不进快照）。
**实现要点**：
- stub 新增 2 个测试缝：`mb_gum_test_force_init_status(code)`（强制下次 init 探针事务回传指定 status，用于触发 `DevkitNotFound`：code=8 → init_failure 兜底分支）、`mb_gum_test_force_enum_status(code)`（强制下次 module_at/region_at 回传指定错误码，用于触发 `ModuleEnumerateFailed`）；一次性生效、用后清零，不污染其他用例。
- `MemoryWriteFailed` 无需新缝：`memory_write(0x99999999, b"\x00")` → status 7 → `MemoryWriteFailed`（钉住 B17：同地址 read 得 `InvalidAddress`，write 得 `MemoryWriteFailed`，双断言成对）。
- `DevkitNotFound` 用例断言消息含 status 数字；`ModuleEnumerateFailed` 对 modules 与 regions 各断言一次（regions 复用同一变体是既有口径，钉住）。
**验收**：T-W2-1（DevkitNotFound 显式用例）；T-W2-2（MemoryWriteFailed 显式用例 + 不对称双断言）；T-W2-3（ModuleEnumerateFailed 显式用例 ×2 路径）；T-W2-4（簿记 13/13 与测试代码双向核对）；T-W2-5（五门禁 + 防火墙旧用例零改动）。

### W3 地址 hook 与 trait 落地（P1/M，已裁决：选项 A，2026-11-16 用户采纳推荐项）

**目标**：消除 B15 trait 空转，使「组合根经 trait 二选一」从声明变为可编译事实。
**非目标**：不改 trait 签名（冻结）；不改 `Gum::attach` 符号语义；不做真实符号解析（stub 世界地址表内查找）。
**选项（已裁决：2026-11-16 用户采纳推荐项 A）**：
- **选项 A（已采纳）**：纯加法补齐——新增 `Gum::attach_address` + stub 地址 attach shim + `impl InstrumentationBackend for Gum`。
- **选项 B（零成本降级）**：不写实现，README 声明 trait 为「预留契约，当前无实现；地址语义与符号语义差异已知」，冻结现状。
- **选项 C（延后）**：trait 归属未来独立契约包（本库与备选后端共同依赖），本轮仅在 README 登记归属决策，不搬代码。
**新增 API（mbti 草案，纯加法，选项 A）**：

```text
pub fn Gum::attach_address(Self, UInt64, (InvocationContext) -> Unit, (InvocationContext) -> Unit) -> UInt64 raise GumError
impl InstrumentationBackend for Gum  // attach=attach_address, detach=detach, read=memory_read
```

**实现要点**：stub 新增 `mb_gum_attach_address(interceptor, addr)`（在 `mb_symbols` 地址表内查找，复用既有 hook 表/事务/错误码：未知地址 → txn_error=1 → 复用 `UnknownSymbol`（字符串为地址十进制），重复地址 → 2 → `AttachFailed`）；`attach_address` 的 MoonBit 侧事务/回调桥/失败逆序释放逻辑与 `attach` 同构（提取包私有公共辅助，不改旧函数行为）；trait impl 的 read 直接转发 memory_read。
**验收**：T-W3-1（地址 attach/detach 全链路 + 回调上下文 function_address 保真）；T-W3-2（trait 对象派发与直调同输入同输出）；T-W3-3（未知地址 → UnknownSymbol、重复地址 → AttachFailed 显式断言）；T-W3-4（快照 diff 纯加法 + CHANGELOG）；T-W3-5（防火墙：旧 attach 用例零改动全绿）。

### W4 demo 失败退出码 fail-closed（P1/S）

**目标**：B18 失败路径退出码 0→1，使脚本可观测 demo 失败（fail-closed 修复例外条款：行为增强，CHANGELOG 显式登记）。
**非目标**：不把 demo 升级为发布 CLI；不改库 API；成功路径输出逐字节不变。
**新增 API（mbti 草案，纯加法）**：无（cmd/main 私有 extern，不进库快照）。
**实现要点**：`cmd/main/main.mbt` 失败分支经私有 `extern "C" fn exit(Int32) -> Unit = "exit"` 调 C runtime `exit(1)`（或等价 MoonBit 进程退出原语，以工具链实测为准）；成功路径 println 序列不变；可选在 demo 中追加 `pump_callbacks(16)` 展示 E1 路径（若追加，成功输出新增一行须 CHANGELOG 登记并同步 T-W4-1 期望）。
**验收**：T-W4-1（成功路径退出码 0 + 输出逐字节比对）；T-W4-2（失败路径退出码 1：经 W2 门禁缝或 stub 故障注入触发 demo 失败，实跑断言退出码）；T-W4-3（五门禁 + cmd/main 快照 diff=0）。

### W5 marshal 队列可观察值查询（P2/S）

**目标**：队列深度/丢弃计数从「仅测试缝可见」升为用户可观察值（B6 的生产化），支撑背压决策。
**非目标**：不改队列容量/锁/派发语义；不动既有测试缝符号（防火墙）。
**新增 API（mbti 草案，纯加法）**：

```text
pub fn Gum::pending_callbacks(Self) -> Int32 raise GumError   // 未派发条数；关闭后 NotInitialized
pub fn Gum::dropped_callbacks(Self) -> Int32 raise GumError   // 累计丢弃（溢出+滞留）；关闭后 NotInitialized
```

**实现要点**：stub 新增生产 shim `mb_gum_marshal_pending` / `mb_gum_marshal_dropped`（读既有计数器，持锁读 depth；未初始化返回 5），与 `mb_gum_test_*` 同逻辑不同符号；MoonBit 侧 status 5 → `NotInitialized`，其余负值复用 `CallbackBridgeFailed`；不新增错误变体。
**验收**：T-W5-1（入队 N 条 → pending=N；pump K 条 → pending=N-K）；T-W5-2（溢出与 detach 滞留 → dropped 增量精确一致）；T-W5-3（close 后两查询 → NotInitialized）；T-W5-4（快照纯加法 + CHANGELOG）；T-W5-5（防火墙：旧测试缝与旧用例零改动全绿）。

### W6 L1 性质/截断扫描与变异自检（P2/M）

**目标**：把配套测试系统设计文档的 L1 层落地（B20 解析路径、B9 边界防护的性质化守护）。
**非目标**：不改任何生产代码语义；不引入第三方依赖。
**新增 API**：无。
**实现要点**：
- `parse_context_record` 截断扫描：合法 50 字节记录的全部前缀（0..49）+ argc 畸形（3、0xFFFFFFFF→负）+ point 畸形值（0/3/255），断言「None 或 B20 声明口径，绝不 panic」。
- 内存边界值矩阵：base-1/base/end-len/end-len+1、len 0/1/4096/4097、UINT64_MAX；read/write 双路径。
- 变形律：init-close 重置律（close 后 re-init，世界初值逐字节复原）、读写回环律、marshal FIFO 律、rc 配平律、防火墙律（详见配套文档 §4）。
- 变异自检：注入 3 类缺陷（回绕检查改加法形式 / dropped 计数恒 0 / drain 在入队线程直接执行闭包），套件必须变红后还原复绿（脚本层，登记命令与日期）。
**验收**：T-W6-1（截断扫描全前缀零 panic）；T-W6-2（边界值矩阵全断言）；T-W6-3（五条变形律用例）；T-W6-4（变异自检 3 类缺陷均变红、还原复绿，登记证据）。

### W7 真实 devkit 对接与真实 hook（P3/XL，已裁决：选项 A 维持冻结，门禁锁定）

**目标**：G1/G2 解冻后把 stub 同构契约接到真实后端，取得真实插桩能力。
**非目标**：本轮（门禁未过）不获取、不落盘、不链接任何真实二进制；不做 Java hook/frida-core 职责。
**选项（已裁决：2026-11-16 用户采纳推荐项 A）**：
- **选项 A（已采纳，当前阶段）**：维持 G1/G2 冻结，零成本；仅维护门禁信号测试与 stub 同构，等待法务终裁。
- **选项 B**：G2 更小替代路线——ShadowHook（MIT，Android inline hook）真实链接实验；仍缺 GumInvocationListener 等价物，需自研胶水（listener_glue.mbt 契约已预留）；MIT 许可相对干净但法务确认仍须前置；平台限 Android arm 系。
- **选项 C**：frida-gum devkit 完整路线——wxWindows 3.1 + 15 个 subprojects 组件法务终裁（原清单文件已删，须重建事实层），x86-64 Linux / Android arm64 双平台。
**里程碑（选项 B/C 通用，每里程碑独立五门禁 + 止损）**：
- M7-1 法务终裁书面结论（止损：未过 → 回选项 A，零代码变更）；
- M7-2 devkit/替代库链接冒烟（x86-64 Linux，init/close 真实句柄；止损：链接失败 → 回 stub，门禁信号不变）；
- M7-3 真实 hook + E1 真实被钩线程验证（GObject 胶水或自研 vtable；Linux pthread 路径实跑补 B23 缺口）；
- M7-4 Android arm64 真实 hook（仓库外样本 + SHA-256 登记 + 显式 SKIPPED 纪律）。
**验收**：T-W7-1..4 对应 M7-1..4；真实验证结论一律 R runner/本地可选 + 显式 SKIPPED，永不进入 `moon test` 通过计数；stub 路径旧用例零改动全绿（防火墙：真实后端是新增实现分支，不改旧契约）。

## 6. 里程碑与合入顺序

```text
M0（第 1 日）  W1 文档/自包含清理（零风险）
M1             W2 错误簿记补齐 + W4 demo fail-closed（安全/可观测缺口）
M2             W3 地址 hook + trait（已裁决选项 A）+ W5 队列可观察
M3             W6 L1 性质/截断/变异自检
M4             W7 真实对接（已裁决选项 A：维持冻结，零代码变更；M7-1..4 待未来解冻）
```

排序判据：先零风险文档、再安全缺口、再高价值低成本、最后安全敏感大工程；每包独立提交、独立过五门禁。W3/W7 已于 2026-11-16 裁决（均选项 A）；W7 对应验收行保持「未实现/SKIPPED」，不得预写通过。

## 7. 簿记与变更管理

- `docs/CHANGELOG.md`（W1 新建）：每包登记「日期/工作包/新增 pub 声明/快照 diff 结论/测试增量」；fail-closed 修复（W4）显式登记行为增强条款。
- README API 索引随 `moon info` 快照同步（禁手编 mbti）；能力/非目标/冻结口径（B16/B17/B20）随包更新。
- 破坏性需求一律走四件例外流程（ADR + 用户裁决 + CHANGELOG + 主版本）；本轮全部工作包零破坏性设计。

## 8. 完成定义（DoD，逐包勾选）

- [x] 新增 API 与 mbti 草案一致（偏差回写本文：W3 额外产生 `Gum::read` 显式方法提升与 `pub impl` 行，见 §10）
- [x] 快照 diff 纯加法，CHANGELOG 已登记（累计 +5 行，零删改，见 §10）
- [x] T-W*-* 验收全绿；#skip 显式标注原因（零 #skip；W7 真实面保持 SKIPPED 纪律）
- [x] 五门禁全绿；CLI 对外契约零意外漂移（W4 退出码变更属登记内行为增强）
- [x] 防火墙回归：旧 12 用例零改动全绿（W1 消息文本例外已登记 CHANGELOG）
- [x] 畸形语料无 panic（截断扫描 0..49 全前缀 + 畸形 argc/point，W6 修复两处潜在越界）
- [x] 零新第三方依赖（cmd/main 新增 core/env 为官方核心库非第三方）；零许可不明二进制入库
- [x] README 能力/非目标同步；本文状态行更新「已交付+日期」

## 9. 风险登记

| 风险 | 等级 | 缓解 |
|---|---|---|
| docs 删除导致 G1 许可清单事实层丢失，未来法务终裁须重建 | 中 | W1 在 README §2 保留结论摘要；W7 M7-1 重建清单作为前置里程碑 |
| trait 落地（W3）引入地址语义后与符号语义混淆 | 中 | 新函数防火墙；T-W3-2 等价断言；README 双语义口径声明 |
| POSIX/CI 云上路径未实测（B23），E1 并发结论仅 Windows 等价 | 中 | ci.yml 已钉版本断言；W7 M7-3 补 Linux 实跑；此前结论一律标「本地等价」 |
| 测试缝一次性故障注入污染相邻用例 | 低 | W2 缝设计为用后清零；用例末尾断言世界复位（init-close 重置律） |
| 真实 devkit 许可（wxWindows + 15 组件）法务风险 | 高 | G1/G2 双门禁硬锁定；W7 选项 A 零成本降级；任何真实二进制不落盘 |
| stub 世界容量（8 hook/2 args）被误当真实能力 | 低 | W1 README 显式声明 stub 契约口径；对标表「真实插桩能力=无」行常驻 |

## 10. 交付记录（2026-11-16，W1–W6 实施当日实测）

**交付后基线**：五门禁全绿；测试 **21/21**（黑盒 5 + 白盒 16，零 `#skip`）；错误变体簿记 **13/13**；demo 成功 exit 0 / `--selftest-fail` exit 1；快照 diff 纯加法 **+5 行零删改**：`Gum::attach_address` / `Gum::pending_callbacks` / `Gum::dropped_callbacks` / `Gum::read`（显式方法提升）/ `pub impl InstrumentationBackend for Gum`。生产 shim 15 → **18**（+attach_address/marshal_pending/marshal_dropped），测试缝 12 → **14**（+force_init_status/force_enum_status），C 导出 31 → **36**；`mb_gum_*` 声明合计 19 → **22**（另胶水 4 不变）。

**实施中新发现（基线表补遗）**：
- B26：`GumError` 为 `pub suberror`（只读错误类型），**下游不可构造变体**（编译器 4036）——W4 失败注入因此改走真实公开 API 失败路径（非法地址读 → InvalidAddress），比原设计（伪造 DevkitNotFound）更忠实。
- B27：`parse_context_record` 存在两处**潜在越界 panic**：头部不足 25 字节时读 argc、has_ret=1 但 n∈[need, need+8) 时读返回值。生产路径 stub 恒回传 50 字节故从未触发；W6 以 fail-closed 加固（返回 None），公开 API 行为不变，已登记 CHANGELOG。
- B28：变异自检 M1 原设计「回绕检查改加法形式」在长度上界守卫（length ≤ SIZE）下与减法式**数学等价**（无回绕窗口），属无效变异；已替换为「删除末尾越界守卫」真实缺陷（见下）。

**变异自检证据（T-W6-4，2026-11-16 本机 Windows）**：
| 变异 | 注入点 | 结果 | 还原 |
|---|---|---|---|
| M1 删除内存末尾越界守卫 | `mb_gum_memory_read` 边界检查 | 变红：黑盒测试进程越界读崩溃（exit 非 0） | SHA-256 一致 |
| M2 溢出丢弃不计数 | `mb_marshal_enqueue` 的 dropped++ | 变红：21 中 11 败（含级联生命周期污染） | SHA-256 一致 |
| M3 入队线程直接执行闭包 | `mb_gum_test_fire_marshal` 入队后直调 cb | 变红：21 中 11 败（E1 只入队不变量被破） | SHA-256 一致 |

还原后复绿 21/21；备份与哈希存于工作区临时目录（不入库）。M3 首版注入 spawn 路径不可观测（闭包读不到上下文），改注入 fire_marshal 缝后有效——变异自检本身也需「可观测性」审查。

**逐包验收映射**：W1（T-W1-1..4：悬空引用清零/缝清单 14/CI 五道/README 索引补齐）；W2（T-W2-1..5：13/13 簿记实测达成）；W3（T-W3-1..4：地址全链路/trait 等价/错误显式/快照纯加法）；W4（T-W4-1..2：exit 0/1 实跑）；W5（T-W5-1..3：与测试缝同值/溢出滞留可观察/close 拒绝）；W6（T-W6-1..4：截断/边界/变形律 P1+P3 新增，P2/P4/P5 由既有用例守护/变异三红复绿）。W7 零代码变更（选项 A），真实面验收行保持 SKIPPED。

**未提交说明**：本轮变更尚在工作区（含快照 +5 行），合入时须源码与快照同提交（门禁 5 要求）；提交动作待用户指示。