# E1-CALLBACK-THREAD-SAFETY.md — 被钩线程闭包线程安全：marshal 设计 + 本地验证 + E1 原实验方案

> 日期：**2026-11-09**（R4 轮）｜ 关联：`../../docs/adr/ADR-0009-jni-thread-and-callback-ownership.md` 决策 4（marshal 到 owner 线程）、`../../docs/open-questions.md` **E1（P0）**、`DECISIONS.md`「回调桥设计」。
> 证据等级口径：本地实跑 = `[已复验]`；文本/设计依据 = `[仅据文档]`；法律/机制解读 = `[推断]`；未实测 = `[仍需实测]`。**本文不写「已跑通」**——E1 原实验口径（Linux pthread 直接执行 MoonBit 闭包）本机 Windows 无法执行，方案见 §4，状态 `[仍需实测]`。

---

## 0. 一句话结论

**把「MoonBit 闭包能否安全地在被钩线程执行」从运行时前提降级为设计不变量**：被钩线程（GumInvocationListener vtable 槽）只做上下文浅拷贝入队，MoonBit 闭包的唯一执行点收敛到 owner 线程的派发泵 `Gum::pump_callbacks`。该路径已本地实测（真实 OS 线程并发入队 + 单线程派发，11/11 测试全绿）`[已复验]`；E1 原实验（若未来需要「被钩线程直接执行闭包」的直调路径）仍须在 Linux 实测 `[仍需实测]`，**本设计不依赖其结果**。

## 1. 问题（ADR-0009 / E1）

- frida-gum 的 `on_enter` / `on_leave` **同步执行在被钩线程、可重入**（`gum_invocation_context_get_depth` 与 per-thread listener data 即为证）`[仅据文档]`。
- MoonBit `FuncRef` 只能无捕获；带状态回调是「函数 + `#owned` 闭包」二元组（DECISIONS §5）。
- `[待验证假设]`（E1 原文）：**MoonBit 运行时（GC / 引用计数 / 重入）在非 owner 线程执行闭包的线程安全本机未实测**——若不安全，直调路径设计不成立。

## 2. 设计：被钩线程 → owner 线程 marshal（ADR-0009 决策 4 落地）

```
被钩线程（任意，可重入）                owner 线程（MoonBit 运行行线程）
─────────────────────────              ─────────────────────────────
gum on_enter/on_leave（vtable 槽）      Gum::pump_callbacks(max_events)
  │ 浅拷贝 GumInvocationContext          │
  │  (point/depth/thread_id/fn_addr/     ├─ mb_gum_marshal_drain：出队
  │   args/return_value，无 MoonBit 指针) │
  ▼                                      ▼
mb_marshal_enqueue（互斥队列，           对每条记录：置 mb_ctx →
  容量 256，满则丢弃+计数，              h->cb(h->closure) 执行 MoonBit
  绝不阻塞被钩线程）                     闭包（唯一执行点）→ 还原 mb_ctx
```

### 2.1 线程契约（不变量）

| # | 不变量 | 实现位置 | 验证 |
|---|---|---|---|
| I1 | 被钩线程**从不**执行 MoonBit 闭包；只 `memcpy` 级浅拷贝入队 | `../stub/mb_gum_stub.c` `mb_marshal_enqueue` / `mb_gum_listener_glue_on_enter|on_leave` | T1/T2/T5 `[已复验]` |
| I2 | MoonBit 闭包只在调用 `pump_callbacks` 的 owner 线程执行 | `mb_gum_marshal_drain`（`cb(closure)` 唯一调用点） | T1 断言执行线程 id == owner `[已复验]` |
| I3 | 并发入队安全（互斥队列），无丢失、无错乱 | SRWLOCK（Windows）/ pthread_mutex（POSIX） | T2 真实 OS 线程 4×32 `[已复验]` |
| I4 | 可重入：派发中可再入队，观测深度递增、FIFO 尾随 | 记录携带入队时 `depth` | T3 `[已复验]` |
| I5 | 关闭/摘除竞态：滞留事件安全丢弃，绝不执行已释放闭包、不二次释放 | drain 按 hook/glue 存活性二次解析；close 清队列 | T4/T5 `[已复验]` |
| I6 | 被钩线程不阻塞：队列满丢弃并计数（`mb_gum_test_marshal_dropped`） | `mb_marshal_enqueue` 溢出路径 | T-队列满 `[已复验]` |

### 2.2 生命周期

- (cb, closure) 对仍按 DECISIONS §5：`#owned(closure)` 交 C 侧持有，`detach` / `close` / `glue_destroy` 成对 `moonbit_decref`（rc 断言 `mb_gum_test_closure_rc` / `mb_gum_test_glue_closure_rc` 守护）。
- marshal 记录**不含任何 MoonBit 指针**，只含标量浅拷贝；队列项与闭包生命周期解耦，drain 时按 hook 存活性二次解析，杜绝悬挂。
- 交付深度语义：记录携带**被钩线程观测深度**（入队时的派发深度）；派发执行时 `mb_depth = 观测深度 + 1`，重入事件观测深度递增（T3：0 → 1）。

### 2.3 与真实 GObject 胶水的映射（接口预留）

`../listener_glue.mbt`（契约文档）+ `mb_gum_listener_glue_*`（stub 契约模拟）已按真实 `GumInvocationListenerInterface` vtable 形状预留：`on_enter` / `on_leave` 两槽被钩线程调用、只入队；create `#owned` 接管闭包、destroy 成对释放。**不链接任何真实二进制**（ADR-0006 红线）。G1→G2 解禁后，真实胶水把 `GumInvocationContext*` 序列化为同一 marshal 记录格式即可，MoonBit 侧零改动。

## 3. 本地可验证部分：实测证据

> 实测环境：Windows x86-64 + MSVC，`moon 0.1.20261104` / `moonc v0.10.20+65efd5b93`（与 VERSION-LOCK 一致）；全部**本机真实执行** `[已复验]`。

### 3.1 测试清单（新增 7，基线 4 → 共 11，`moon test` 11/11 全绿）

| 测试 | 覆盖 | 对应不变量 |
|---|---|---|
| E1 marshal：被钩线程入队、owner 线程派发（线程收敛） | 入队不执行 → pump 执行 → 执行线程 id == owner → 上下文保真（args/point/ret/thread_id）→ 空队列 pump=0 → `max_events<=0` → `CallbackBridgeFailed` | I1/I2 |
| E1 marshal 并发：多线程入队无丢失无错乱（真实 OS 线程） | `CreateThread` 4 线程 ×32 条并发入队（不同 OS 线程 id）→ 分批 pump 40/40/40/8/0 → (thread_index, seq) 恰好一次 → worker id 一致/互异 → 执行线程全 = owner | I2/I3 |
| E1 marshal 重入：派发中入队（深度递增、FIFO、逐条边界） | pump 中再入队：同泵 FIFO 派发（depth 0→1）；`max_events=1` 时重入件滞留下一次；未知 hook 入队拒绝(8) | I4 |
| E1 marshal 关闭竞态：detach/close 与滞留事件安全丢弃 | 3 条滞留 → detach → pump 派发 0、丢弃计数 3、闭包 rc 归零；close 清队列；关闭后 pump→`NotInitialized`、fire→5 | I5 |
| E1 marshal 队列满：入队拒绝并计数（不阻塞被钩线程） | 300 连发：入队成功 + 满拒 = 300、pending == 成功数、dropped == 满拒数、pump 排空一致 | I6 |
| listener vtable 胶水预留：只入队 + 生命周期配平 | invoke 不执行闭包 → pump 执行 → rc=1；销毁后滞留丢弃/重复销毁(8)/销毁后 invoke(8)；无效 hook create 失败且释放闭包；close 释放未销毁胶水 | I1/I5 |
| pump_callbacks 公开契约：空队列 / 参数非法 / 关闭后 | 空=0；`<=0` → `CallbackBridgeFailed`（不 panic）；关闭后 → `NotInitialized` | 错误路径 |

### 3.2 门禁输出（逐条，2026-11-09 本机实跑）

```
moon clean                exit 0
moon check --deny-warn    exit 0
moon build                exit 0   （main.exe 产出，链接项目内 stub）
moon test                 exit 0   Total tests: 11, passed: 11, failed: 0
moon fmt --check          exit 0
moon info                 exit 0   （快照 +Gum::pump_callbacks，已随代码提交）
git diff --exit-code -- ../pkg.generated.mbti ../cmd/main/pkg.generated.mbti   exit 0
```

### 3.3 实现期发现（设计注意，`[已复验]` + 机制 `[推断]`）

**无捕获常量闭包（如 `fn() { () }`）作为 `#owned` 闭包交接时，`Moonbit_rc_count` 观测为 -1，与捕获型堆闭包（rc=1）不同**。机制推断 `[推断]`：无捕获闭包被编译为静态/常量对象（或裸函数指针），其头部无堆引用计数语义。**设计注意**：`#owned` 交接与 rc 断言应使用**捕获型闭包**；无捕获常量闭包经 `moonbit_decref` 的语义 `[仍需实测]`（E1-B 变体，§4）。

## 4. E1 原实验口径：最小可执行实验方案（Linux x86-64）**[仍需实测]**

> 状态：**[仍需实测]**——本机 Windows 无 pthread 语义等价环境，以下方案**未执行**，不得写成「已跑通」。
> 目的：回答 E1 原文问题「MoonBit 运行时在非 owner 线程执行无捕获 `FuncRef` 与 `#owned` 闭包是否线程安全（GC、引用计数、重入）」——这是**直调路径**（不走 marshal）的前提；marshal 设计不依赖该结果。

**实验 E1-A（pthread 直调无捕获 FuncRef 与 #owned 闭包）**

1. 环境：Linux x86-64、GCC/Clang、`moon 0.1.20261104` / `moonc v0.10.20+65efd5b93`、`../moon.mod` `preferred_target = "native"`（同本仓）。
2. C 侧探针（实验用临时文件 `stub/e1_pthread_probe.c`，实验后不入库）：
   - `mb_e1_run_workers(int threads, int iters)`：`pthread_create` N（1/2/8）个 worker，每个对全局保存的 `(cb, closure)` 对调用 `cb(closure)` 共 M（1e4/1e5/1e6）次；其中 1/100 次在回调内再触发一次（重入）；全程 C11 原子计数器记录调用次数（**不**用 MoonBit 侧数据，避免掩盖运行时问题）。
   - `mb_e1_closure_rc()`：返回 `Moonbit_rc_count(Moonbit_object_header(closure))`。
3. MoonBit 侧：无捕获 `FuncRef` 适配器 `fn(f) { f() }` + 捕获型 `#owned` 闭包（闭包体只递增 C 原子计数）；另备无捕获常量闭包变体（§3.3 注意项）。
4. 断言（任一不满足即判不安全）：
   (a) 全程无崩溃 / 无死锁 / 无 TSAN 报警（`-fsanitize=thread` 变体重跑）；
   (b) 原子计数 == threads × iters（含重入次数）；
   (c) 触发前后 rc 不变，`moonbit_decref` 后 rc 归零（或静态对象语义明确）；
   (d) 重入路径无栈溢出、计数正确。
5. 命令骨架：`moon check --target native && moon test --target native`（Linux）+ 探针由 `_wbtest` 测试触发；TSAN 变体经 `stub-cc-flags` 注入 `-fsanitize=thread`。

**实验 E1-B（变体）**：无捕获常量闭包 `#owned` 交接的 `moonbit_decref` 语义（§3.3 遗留）；并发 decref（多线程同时 detach 同一 listener）语义。

**预期处置**：E1-A 通过 → 直调路径（owner == 被钩线程时的 inline 派发）可声明安全，文档升 `[已复验]`；失败 → 维持 marshal-only（现设计已是如此），并在 API 文档永久标注「禁止在被钩线程执行 MoonBit 闭包」。

## 5. 残余风险与未决

| 项 | 状态 | 等级 |
|---|---|---|
| E1 原实验（pthread 直调闭包线程安全） | 未执行，方案 §4 | `[仍需实测]` |
| 真正并发的 close 与 enqueue 交错（非确定性交错窗口） | 单元测试只覆盖「滞留事件 + 关闭」确定性口径（T4/T5）；真交错需 §4 类探针 + 压力循环 | `[仍需实测]` |
| 无捕获常量闭包 `moonbit_decref` 语义 | §3.3 观察 + `[推断]` 机制 | `[仍需实测]`（E1-B） |
| Android/设备侧线程模型（binder 线程等被钩线程形态） | 设备轮次验证 | `[仍需实测]` |
| marshal 队列容量 256 的生产适配（真实 hook 风暴下溢出率） | G1→G2 解禁后按真实负载调参 | `[仍需实测]` |
