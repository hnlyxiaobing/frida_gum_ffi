# CHANGELOG · frida_gum_ffi

本文件登记本仓库全部行为/契约/文档变更。公开 API 冻结基线为 `pkg.generated.mbti`（`moon info` 生成），只允许纯加法；语义变更走新函数新类型防火墙，旧 API 语义永不改变。

## 2026-11-16 · W1 文档自包含与悬空引用清理（零 API 变更）

- 背景：历史提交 e08affb 删除了 docs/ 下 7 份设计/决策/许可文档，但代码注释、CI 与 README 仍残留 25+ 处 `docs/*` 悬空引用（B5/B11/B12/B13/B21）。
- 改写全部悬空引用为仓库内自包含指向（README §1/§2/§3/§6 或本文件）：`frida_gum_ffi.mbt`、`gum.mbt`、`internal.mbt`、`frida_gum_ffi_test.mbt`、`frida_gum_ffi_wbtest.mbt`、`cmd/main/main.mbt`、`stub/mb_gum_stub.c`。
- `gum.mbt` 注释中不存在的 `invoke_closure` 命名修正为实际内联适配器 `fn(f) { f() }`（B21）。
- **登记例外（消息文本）**：`LicenseReviewRequired` 错误消息中的文档指向由 `docs/DECISIONS.md` 改为 `README §2/§6`；错误变体、触发条件与既有断言口径（消息非空）不变，仅诊断文本更新。
- `stub/mb_gum_stub.c` 头部测试缝清单 10 → 12（补 `mb_gum_test_live_glues` / `mb_gum_test_glue_closure_rc`，B5）；「公开 shim」措辞统一为「生产 shim」。
- `.github/workflows/ci.yml`：删除已不存在的 `pkg.generated.mbti.r1` 说明；依赖示例 `bobzhang/zip@0.1.2` 改为本模块零依赖事实；门禁 5 错误消息中 `docs/API.md` 改为 README + 本文件（B12）。
- `.github/workflows/copilot-setup-steps.yml`：「四道门禁」修正为五道；zip 依赖示例同步移除。
- README：§3 索引补齐（GumError / trait / 别名 / external 类型）；§2 补回调桥、E1 marshal、shim 收敛、冻结口径（hook_count 恒 0 / memory_write 映射不对称 / point 容错）与 stub 世界容量；非目标中兄弟模块名引用移除（自包含纪律）；「唯一说明文档」改为入口文档。
- 新建本文件与两份设计文档（`2026-11-16-gated-instrumentation-dev-plan.md` / `2026-11-16-test-system-design.md`）。

## 2026-11-16 · W2 错误变体触发补齐 13/13（零 API 变更，仅 C 测试缝）

- 新增测试缝 `mb_gum_test_force_init_status` / `mb_gum_test_force_enum_status`（一次性强制 status，消费后自动清零，deinit 亦清零防跨用例泄漏）；测试缝 12 → 14。
- 新增白盒用例：DevkitNotFound（强制 init 探针 status=8，消息含 status 数字）；ModuleEnumerateFailed 双路径（modules/regions 各一次，复用同一变体口径钉住）；一次性消费后世界恢复断言。
- 新增黑盒用例：memory_write 失败映射冻结口径不对称双断言（写 → MemoryWriteFailed(addr,len)，同地址读 → InvalidAddress(addr)）。
- 簿记实测：13/13 变体均有显式用例（此前 10/13）。测试 12 → 14。

## 2026-11-16 · W4 demo 失败退出码 fail-closed（行为增强，登记例外）

- **fail-closed 修复**：`cmd/main` demo 失败路径由 exit 0（fail-open）改为 **exit 1**；成功路径输出与退出码不变。退出码集合新增 1（模板 demo 非发布 CLI，属登记内行为增强）。
- 新增 `--selftest-fail` 确定性失败注入旗标：走**真实公开 API 失败路径**（非法地址读 → InvalidAddress）；因 GumError 为只读 suberror 下游不可构造变体（编译器 4036，新事实 B26），不伪造错误。
- cmd/main 新增官方核心库 `moonbitlang/core/env` import（非第三方依赖）；快照无导出面变化。
- 实跑：`moon run cmd/main` exit 0；`moon run cmd/main -- --selftest-fail` exit 1 + "demo failed"。

## 2026-11-16 · W3 地址 hook 与 trait 落地（选项 A，纯加法）

- 新增 `pub fn Gum::attach_address(Self, Address, (InvocationContext) -> Unit, (InvocationContext) -> Unit) -> HookId raise GumError`：stub 世界地址表内查找，与符号入口同 hook 表/同错误码约定；未知地址 → UnknownSymbol（十进制地址串），跨入口重复挂接 → AttachFailed。
- 新增 `pub impl InstrumentationBackend for Gum`（attach 经 attach_address 适配 nop 回调；detach/read 转发）；trait 冻结签名零改动，消除 trait 空转（B15）。
- 工具链适配：`pub extend Gum with InstrumentationBackend::{read}` 显式方法提升（替代已弃用的隐式提升，产生加法 `Gum::read`）；attach 尾段提取为私有 `Gum::finish_attach`（行为逐字节同构，旧用例零改动全绿）。
- 新增 C 生产 shim `mb_gum_attach_address`；新增黑盒/白盒用例各 1（地址全链路/上下文保真/trait 派发逐字节等价）。测试 14 → 16。

## 2026-11-16 · W5 marshal 队列可观察值查询（纯加法）

- 新增 `pub fn Gum::pending_callbacks(Self) -> Int32 raise GumError` / `pub fn Gum::dropped_callbacks(Self) -> Int32 raise GumError`：C 侧持锁读队列深度 / 累计丢弃计数；close 后 NotInitialized；错误码约定与 drain 同构（-5 取负）。
- 新增 C 生产 shim `mb_gum_marshal_pending` / `mb_gum_marshal_dropped`（不动既有测试缝）；生产 shim 15 → 18。
- 新增白盒用例：与测试缝同值/分批派发递减/滞留丢弃/溢出丢弃累计/close 拒绝。测试 16 → 17。

## 2026-11-16 · W6 截断扫描/边界矩阵/变形律/变异自检（含 fail-closed 修复，登记例外）

- **fail-closed 修复（B27）**：`parse_context_record` 两处潜在越界 panic（头部 <25 字节读 argc；has_ret=1 但返回值 8 字节被截断）改为返回 None。生产路径 stub 恒回传完整 50 字节，公开 API 行为不变；属「损坏输入从 panic 变拒绝」行为增强。
- 新增白盒用例：50 字节记录全前缀 0..49 截断扫描零 panic；畸形 argc（3/0xFFFFFFFF）与 point 容错口径（0/3/255 归 Leave）钉住；变形律 P1（init-close 重置律）与 P3（FIFO 分批律）。
- 新增黑盒用例：内存边界值矩阵（基址前/末尾合法/越界一字节/长度 0、1、4096、4097/负长度/UINT64_MAX，读写双断言）。测试 17 → 21。
- 变异自检（T-W6-4）：M1 删除末尾越界守卫 → 黑盒进程崩溃变红；M2 溢出丢弃不计数 → 11 败；M3 入队线程直执闭包 → 11 败；三类均还原（SHA-256 一致）复绿 21/21。原设计 M1「加法形式回绕检查」在长度上界守卫下与减法式数学等价（B28），已替换为真实缺陷。

## 2026-11-16 · W7 真实 devkit 对接（选项 A：维持 G1/G2 冻结）

- 用户裁决采纳推荐项 A：零代码变更；门禁信号测试与 stub 同构继续维护；真实面验收保持 SKIPPED，M7-1..4 待未来法务终裁解冻。