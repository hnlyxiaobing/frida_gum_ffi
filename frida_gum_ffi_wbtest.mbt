// Whitebox tests run within the package scope.
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.
//
// 当前为桌面 stub：真实 frida-gum devkit 链接受 G1 许可审查 + G2 更小替代评估双门禁（见 DECISIONS.md）约束，暂不进行。

///|
/// 测试缝（stub 提供，仅供测试触发模拟调用 / 门禁切换 / 引用计数断言）。
extern "C" fn mb_gum_test_fire(
  hook_id : UInt64,
  point : Int32,
  arg0 : UInt64,
  arg1 : UInt64,
  ret : UInt64,
) -> Int32 = "mb_gum_test_fire"

///|
/// 门禁开关：gate 1 = 许可（G1/G2 双门禁，见 DECISIONS.md），2 = ptrace。
extern "C" fn mb_gum_test_set_gate(gate : Int32, enabled : Int32) -> Int32 = "mb_gum_test_set_gate"

///|
/// 当前活跃 hook 数。
extern "C" fn mb_gum_test_live_hooks() -> Int32 = "mb_gum_test_live_hooks"

///|
/// stub 持有的 `#owned` 闭包数（set/clear 成对性）。
extern "C" fn mb_gum_test_live_closures() -> Int32 = "mb_gum_test_live_closures"

///|
/// 闭包引用计数（触发/注销成对持有与释放，不泄不溢）。
extern "C" fn mb_gum_test_closure_rc(hook_id : UInt64) -> Int32 = "mb_gum_test_closure_rc"

///|
/// 许可门禁可观察路径（见 DECISIONS.md「LicenseReviewRequired」）：门禁未过时 `Gum::init` 主动返回
/// `LicenseReviewRequired` / `PtraceDenied` 而非静默继续；失败的 init 不消耗生命周期。
test "许可门禁可观察路径" {
  assert_eq(mb_gum_test_set_gate(1, 1), 0)
  let r_license = Ok(Gum::init()) catch { e => Err(e) }
  match r_license {
    Err(GumError::LicenseReviewRequired(msg)) => assert_true(msg != "")
    _ => abort("许可门禁未过时 init 应返回 LicenseReviewRequired")
  }
  assert_eq(mb_gum_test_set_gate(1, 0), 0)
  assert_eq(mb_gum_test_set_gate(2, 1), 0)
  let r_ptrace = Ok(Gum::init()) catch { e => Err(e) }
  match r_ptrace {
    Err(GumError::PtraceDenied(_)) => ()
    _ => abort("ptrace 门禁未过时 init 应返回 PtraceDenied")
  }
  assert_eq(mb_gum_test_set_gate(2, 0), 0)
  // 门禁清除后可正常 init/close
  let g = Gum::init()
  g.close()
}

///|
/// hook 回调触发与注销（回调对，见 DECISIONS.md「回调桥设计」）：`FuncRef` 无捕获适配器 + `#owned` 闭包
/// 二元组由 stub 成对持有/释放；回调内可重入（depth 递增）；detach 后不再触发；
/// close 释放未摘除的 listener 与闭包。
/// 注意：`on_enter`/`on_leave` 签名固定为不带 error，断言只记录上下文、在回调外执行。
test "hook 回调触发与注销（回调对）" {
  let g = Gum::init()
  let events : Array[String] = []
  let seen : Array[InvocationContext] = []
  let enter = fn(ctx : InvocationContext) {
    events.push("enter:\{ctx.depth}")
    seen.push(ctx)
    if ctx.depth == 0 {
      // 可重入：被钩线程内再次触发同一 hook（depth 递增）
      if mb_gum_test_fire(ctx.hook_id, 1, 1, 2, 0) != 0 {
        events.push("reenter-failed")
      }
    }
  }
  let leave = fn(ctx : InvocationContext) {
    events.push("leave:\{ctx.depth}")
    seen.push(ctx)
  }
  let hook_id = g.attach(b"target_add", enter, leave)
  assert_true(hook_id != 0)
  // set：listener 与闭包成对登记，闭包引用计数 = 1（stub 独占 #owned 引用）
  assert_eq(mb_gum_test_live_hooks(), 1)
  assert_eq(mb_gum_test_live_closures(), 1)
  assert_eq(mb_gum_test_closure_rc(hook_id), 1)
  // 触发 Enter（args 1,2）→ 回调内重入一次（depth 1）
  assert_eq(mb_gum_test_fire(hook_id, 1, 1, 2, 0), 0)
  // 触发 Leave（args 11,22，返回值 42）
  assert_eq(mb_gum_test_fire(hook_id, 2, 11, 22, 42), 0)
  // 触发前后引用计数不变（incref/decref 成对，不泄不溢）
  assert_eq(mb_gum_test_closure_rc(hook_id), 1)
  // 回调记录：enter(d0) → 重入 enter(d1) → leave(d0)
  assert_eq(events.length(), 3)
  assert_eq(events[0], "enter:0")
  assert_eq(events[1], "enter:1")
  assert_eq(events[2], "leave:0")
  assert_eq(seen.length(), 3)
  // 上下文断言（stub 序列化 → MoonBit 解析）
  let c0 = seen[0]
  assert_true(c0.thread_id > 0)
  assert_true(c0.point_cut is PointCut::Enter)
  assert_true(c0.return_value is None)
  assert_eq(c0.depth, 0)
  assert_true(c0.function_address == 0x140000100)
  assert_eq(c0.args.length(), 2)
  assert_true(c0.args[0] == 1)
  assert_true(c0.args[1] == 2)
  let c1 = seen[1]
  assert_eq(c1.depth, 1)
  assert_eq(c1.thread_id, c0.thread_id)
  assert_true(c1.args[0] == 1)
  assert_true(c1.args[1] == 2)
  let c2 = seen[2]
  assert_true(c2.point_cut is PointCut::Leave)
  assert_eq(c2.depth, 0)
  assert_eq(c2.thread_id, c0.thread_id)
  match c2.return_value {
    Some(v) => assert_true(v == 42)
    None => abort("on_leave 应带返回值")
  }
  assert_true(c2.args[0] == 11)
  assert_true(c2.args[1] == 22)
  // clear：detach 成对释放闭包，注销后不再触发
  g.detach(hook_id)
  assert_eq(mb_gum_test_live_closures(), 0)
  assert_true(mb_gum_test_fire(hook_id, 1, 1, 2, 0) != 0)
  assert_eq(events.length(), 3)
  // close 释放未摘除的 listener 与 #owned 闭包
  let hook2 = g.attach(b"target_concat", enter, leave)
  assert_true(hook2 != 0)
  assert_eq(mb_gum_test_live_closures(), 1)
  g.close()
  assert_eq(mb_gum_test_live_hooks(), 0)
  assert_eq(mb_gum_test_live_closures(), 0)
}

///|
/// 当前 marshal 队列深度（入队未派发条数）。
extern "C" fn mb_gum_test_marshal_pending() -> Int32 = "mb_gum_test_marshal_pending"

///|
/// 队列溢出与「滞留事件安全丢弃」累计计数。
extern "C" fn mb_gum_test_marshal_dropped() -> Int32 = "mb_gum_test_marshal_dropped"

///|
/// 当前线程 id（断言「MoonBit 闭包只在 owner 线程执行」）。
extern "C" fn mb_gum_test_current_thread_id() -> UInt64 = "mb_gum_test_current_thread_id"

///|
/// 模拟被钩线程触发（E1 marshal 路径）：只入队、**不执行** MoonBit 闭包。
extern "C" fn mb_gum_test_fire_marshal(
  hook_id : UInt64,
  point : Int32,
  arg0 : UInt64,
  arg1 : UInt64,
  ret : UInt64,
) -> Int32 = "mb_gum_test_fire_marshal"

///|
/// 真实 OS 线程并发入队（threads × per_thread 条，args = (thread_index, seq)，Leave 带
/// ret = tag*100000+seq），join 后返回总入队条数；< 0 = 错误码取负。
extern "C" fn mb_gum_test_spawn_firers(
  threads : Int32,
  per_thread : Int32,
  hook_id : UInt64,
  tag : UInt64,
) -> Int32 = "mb_gum_test_spawn_firers"

///|
/// 存活 listener 胶水数（create/destroy 成对性）。
extern "C" fn mb_gum_test_live_glues() -> Int32 = "mb_gum_test_live_glues"

///|
/// 胶水持有的 `#owned` 闭包引用计数（未存活返回 -1）。
extern "C" fn mb_gum_test_glue_closure_rc(listener : GumListenerRaw) -> Int32 = "mb_gum_test_glue_closure_rc"

///|
/// ---- listener vtable 胶水（接口预留，契约见 listener_glue.mbt）----
/// 声明暂居测试缝节（仅供白盒测试调用，规避 --deny-warn 的 unused_value 告警）；
/// 真实胶水落地时随实现迁入 `internal.mbt`。
/// 创建胶水并绑定 hook；`closure` 为 `#owned`（无论成败都由 C 侧释放）。失败返回空句柄。
#owned(closure)
extern "C" fn mb_gum_listener_glue_create(
  hook_id : UInt64,
  cb : FuncRef[(() -> Unit) -> Unit],
  closure : () -> Unit,
) -> GumListenerRaw = "mb_gum_listener_glue_create"

///|
/// vtable `on_enter` 槽（被钩线程调用）：只入队不执行闭包。0 = 成功，6 = 队列满，8 = 无效胶水。
extern "C" fn mb_gum_listener_glue_on_enter(
  listener : GumListenerRaw,
  arg0 : UInt64,
  arg1 : UInt64,
) -> Int32 = "mb_gum_listener_glue_on_enter"

///|
/// vtable `on_leave` 槽（被钩线程调用）：语义同 `on_enter`，另带返回值 `ret`。
extern "C" fn mb_gum_listener_glue_on_leave(
  listener : GumListenerRaw,
  arg0 : UInt64,
  arg1 : UInt64,
  ret : UInt64,
) -> Int32 = "mb_gum_listener_glue_on_leave"

///|
/// 销毁胶水并成对释放 `#owned` 闭包；重复销毁返回 8（不二次释放）。
extern "C" fn mb_gum_listener_glue_destroy(listener : GumListenerRaw) -> Int32 = "mb_gum_listener_glue_destroy"

///|
/// E1 marshal 基础路径（见 E1-CALLBACK-THREAD-SAFETY.md）：被钩线程只入队、
/// owner 线程 pump 派发；闭包执行线程收敛到 owner 线程；上下文浅拷贝保真；
/// pump 错误路径（max_events <= 0 → CallbackBridgeFailed）。
test "E1 marshal：被钩线程入队、owner 线程派发（线程收敛）" {
  let g = Gum::init()
  let owner_thread = mb_gum_test_current_thread_id()
  let cuts : Array[String] = []
  let seen : Array[InvocationContext] = []
  let exec_threads : Array[UInt64] = []
  let enter = fn(ctx : InvocationContext) {
    cuts.push("enter")
    seen.push(ctx)
    exec_threads.push(mb_gum_test_current_thread_id())
  }
  let leave = fn(ctx : InvocationContext) {
    cuts.push("leave")
    seen.push(ctx)
    exec_threads.push(mb_gum_test_current_thread_id())
  }
  let hook_id = g.attach(b"target_add", enter, leave)
  // 模拟被钩线程触发：只入队，闭包一次都不执行
  assert_eq(mb_gum_test_fire_marshal(hook_id, 1, 7, 8, 0), 0)
  assert_eq(mb_gum_test_fire_marshal(hook_id, 2, 9, 10, 42), 0)
  assert_eq(cuts.length(), 0)
  assert_eq(mb_gum_test_marshal_pending(), 2)
  // owner 线程派发
  assert_eq(g.pump_callbacks(16), 2)
  assert_eq(mb_gum_test_marshal_pending(), 0)
  assert_eq(cuts.length(), 2)
  assert_eq(cuts[0], "enter")
  assert_eq(cuts[1], "leave")
  // 闭包只在 owner 线程执行
  assert_eq(exec_threads.length(), 2)
  assert_true(exec_threads[0] == owner_thread)
  assert_true(exec_threads[1] == owner_thread)
  // 上下文保真（浅拷贝送达）
  let c0 = seen[0]
  assert_true(c0.point_cut is PointCut::Enter)
  assert_true(c0.args[0] == 7)
  assert_true(c0.args[1] == 8)
  assert_true(c0.return_value is None)
  assert_true(c0.thread_id > 0)
  let c1 = seen[1]
  assert_true(c1.point_cut is PointCut::Leave)
  assert_true(c1.args[0] == 9)
  assert_true(c1.args[1] == 10)
  match c1.return_value {
    Some(v) => assert_true(v == 42)
    None => abort("leave 事件应带返回值")
  }
  // 空队列派发 = 0
  assert_eq(g.pump_callbacks(16), 0)
  // 错误路径：max_events <= 0 → CallbackBridgeFailed（不 panic）
  let r_zero = Ok(g.pump_callbacks(0)) catch { e => Err(e) }
  assert_true(r_zero is Err(GumError::CallbackBridgeFailed(_)))
  let r_neg = Ok(g.pump_callbacks(-1)) catch { e => Err(e) }
  assert_true(r_neg is Err(GumError::CallbackBridgeFailed(_)))
  g.detach(hook_id)
  g.close()
}

///|
/// E1 marshal 并发（真实 OS 线程）：多线程入队无丢失、无错乱；派发分批边界正确；
/// 闭包执行线程全部收敛 owner 线程；(thread_index, seq) 恰好一次；
/// 同一 worker 的 OS 线程 id 一致、不同 worker 互异。
test "E1 marshal 并发：多线程入队无丢失无错乱（真实 OS 线程）" {
  let g = Gum::init()
  let owner_thread = mb_gum_test_current_thread_id()
  let recs : Array[InvocationContext] = []
  let exec_threads : Array[UInt64] = []
  let enter = fn(ctx : InvocationContext) {
    recs.push(ctx)
    exec_threads.push(mb_gum_test_current_thread_id())
  }
  let leave = fn(ctx : InvocationContext) {
    recs.push(ctx)
    exec_threads.push(mb_gum_test_current_thread_id())
  }
  let hook_id = g.attach(b"target_add", enter, leave)
  // 4 个真实 OS 线程 × 32 条并发入队
  let total = mb_gum_test_spawn_firers(4, 32, hook_id, 3)
  assert_eq(total, 128)
  assert_eq(mb_gum_test_marshal_pending(), 128)
  // 分批 pump 边界：40 + 40 + 40 + 8（尾批不足 max）+ 空 0
  assert_eq(g.pump_callbacks(40), 40)
  assert_eq(g.pump_callbacks(40), 40)
  assert_eq(g.pump_callbacks(40), 40)
  assert_eq(g.pump_callbacks(40), 8)
  assert_eq(g.pump_callbacks(40), 0)
  assert_eq(recs.length(), 128)
  assert_eq(exec_threads.length(), 128)
  // (thread_index, seq) 恰好一次 + 语义保真
  let mut ti : UInt64 = 0
  while ti < 4 {
    let mut seq : UInt64 = 0
    while seq < 32 {
      let mut matches = 0
      let mut j = 0
      while j < recs.length() {
        let ctx = recs[j]
        if ctx.args[0] == ti && ctx.args[1] == seq {
          matches = matches + 1
          if seq % 2 == 0 {
            assert_true(ctx.point_cut is PointCut::Enter)
            assert_true(ctx.return_value is None)
          } else {
            assert_true(ctx.point_cut is PointCut::Leave)
            match ctx.return_value {
              Some(v) => assert_true(v == 3 * 100000 + seq)
              None => abort("Leave 事件应带返回值")
            }
          }
        }
        j = j + 1
      }
      assert_eq(matches, 1)
      seq = seq + 1
    }
    ti = ti + 1
  }
  // worker 线程 id：同一 worker 一致、不同 worker 互异
  let tids : Array[UInt64] = []
  let mut ti2 : UInt64 = 0
  while ti2 < 4 {
    let mut found = false
    let mut tid_first : UInt64 = 0
    let mut j2 = 0
    while j2 < recs.length() {
      let ctx = recs[j2]
      if ctx.args[0] == ti2 {
        if !found {
          tid_first = ctx.thread_id
          found = true
          tids.push(ctx.thread_id)
        } else {
          assert_true(ctx.thread_id == tid_first)
        }
      }
      j2 = j2 + 1
    }
    assert_true(found)
    ti2 = ti2 + 1
  }
  assert_eq(tids.length(), 4)
  assert_true(tids[0] != tids[1])
  assert_true(tids[0] != tids[2])
  assert_true(tids[0] != tids[3])
  assert_true(tids[1] != tids[2])
  assert_true(tids[1] != tids[3])
  assert_true(tids[2] != tids[3])
  // 闭包执行线程全部 = owner 线程（被钩线程从不执行 MoonBit 闭包）
  let mut k = 0
  while k < exec_threads.length() {
    assert_true(exec_threads[k] == owner_thread)
    k = k + 1
  }
  g.detach(hook_id)
  g.close()
}

///|
/// E1 marshal 重入：派发（pump）中经被钩路径再入队——重入件观测深度递增（0 → 1）、
/// FIFO 尾随派发；max_events=1 时重入件滞留到下一次 pump。
test "E1 marshal 重入：派发中入队（深度递增、FIFO、逐条边界）" {
  let g = Gum::init()
  let depths : Array[Int32] = []
  let hook_cell : Array[UInt64] = []
  let enter = fn(ctx : InvocationContext) {
    depths.push(ctx.depth)
    if ctx.depth == 0 && hook_cell.length() > 0 {
      // 重入：派发中经被钩路径再入队（记录观测深度 = 当前派发深度 1）
      ignore(mb_gum_test_fire_marshal(hook_cell[0], 1, 5, 5, 0))
    }
  }
  let leave = fn(_ctx : InvocationContext) { () }
  let hook_id = g.attach(b"target_add", enter, leave)
  hook_cell.push(hook_id)
  // 外层 → 重入 → 同一次 pump 内 FIFO 派发（depth 0、1）
  assert_eq(mb_gum_test_fire_marshal(hook_id, 1, 1, 2, 0), 0)
  assert_eq(g.pump_callbacks(10), 2)
  assert_eq(depths.length(), 2)
  assert_eq(depths[0], 0)
  assert_eq(depths[1], 1)
  assert_eq(mb_gum_test_marshal_pending(), 0)
  // 逐条边界：max_events=1 时重入件滞留到下一次
  assert_eq(mb_gum_test_fire_marshal(hook_id, 1, 1, 2, 0), 0)
  assert_eq(g.pump_callbacks(1), 1)
  assert_eq(mb_gum_test_marshal_pending(), 1)
  assert_eq(g.pump_callbacks(1), 1)
  assert_eq(mb_gum_test_marshal_pending(), 0)
  assert_eq(depths.length(), 4)
  assert_eq(depths[2], 0)
  assert_eq(depths[3], 1)
  // 错误路径：未知 hook 的被钩路径入队被拒（8）
  assert_eq(mb_gum_test_fire_marshal(9999, 1, 0, 0, 0), 8)
  g.detach(hook_id)
  g.close()
}

///|
/// E1 marshal 关闭竞态（单元级可测口径）：detach / close 时滞留未派发事件被安全丢弃
/// （不悬挂、不二次释放、不执行已释放闭包）；close 清空队列；关闭后 pump/fire 被明确拒绝。
test "E1 marshal 关闭竞态：detach/close 与滞留事件安全丢弃" {
  let g = Gum::init()
  let fired : Array[InvocationContext] = []
  let enter = fn(ctx : InvocationContext) { fired.push(ctx) }
  let leave = fn(ctx : InvocationContext) { fired.push(ctx) }
  let hook_id = g.attach(b"target_add", enter, leave)
  // 入队 3 条后 detach：滞留事件不再派发（安全丢弃），闭包成对释放
  assert_eq(mb_gum_test_fire_marshal(hook_id, 1, 1, 1, 0), 0)
  assert_eq(mb_gum_test_fire_marshal(hook_id, 2, 2, 2, 2), 0)
  assert_eq(mb_gum_test_fire_marshal(hook_id, 1, 3, 3, 0), 0)
  assert_eq(mb_gum_test_marshal_pending(), 3)
  g.detach(hook_id)
  assert_eq(mb_gum_test_live_closures(), 0)
  assert_eq(g.pump_callbacks(16), 0)
  assert_eq(fired.length(), 0)
  assert_true(mb_gum_test_marshal_dropped() == 3)
  // detach 后被钩路径入队被拒（8 = 无 listener）
  assert_eq(mb_gum_test_fire_marshal(hook_id, 1, 1, 1, 0), 8)
  // 重新挂接：入队 2 条后 close：队列清空、闭包释放、pump/fire 被拒
  let hook2 = g.attach(b"target_concat", enter, leave)
  assert_eq(mb_gum_test_fire_marshal(hook2, 1, 4, 4, 0), 0)
  assert_eq(mb_gum_test_fire_marshal(hook2, 1, 5, 5, 0), 0)
  assert_eq(mb_gum_test_marshal_pending(), 2)
  g.close()
  assert_eq(mb_gum_test_marshal_pending(), 0)
  assert_eq(mb_gum_test_live_hooks(), 0)
  assert_eq(mb_gum_test_live_closures(), 0)
  let r_pump = Ok(g.pump_callbacks(16)) catch { e => Err(e) }
  assert_true(r_pump is Err(GumError::NotInitialized))
  assert_eq(mb_gum_test_fire_marshal(hook2, 1, 1, 1, 0), 5)
  assert_eq(fired.length(), 0)
}

///|
/// E1 marshal 队列满：入队拒绝并计数（被钩线程绝不阻塞、事件丢弃可观测）；
/// owner 线程分批排空与丢弃计数一致。
test "E1 marshal 队列满：入队拒绝并计数（不阻塞被钩线程）" {
  let g = Gum::init()
  let nop_enter = fn(_ctx : InvocationContext) { () }
  let nop_leave = fn(_ctx : InvocationContext) { () }
  let hook_id = g.attach(b"target_add", nop_enter, nop_leave)
  let mut i = 0
  let mut ok = 0
  let mut full = 0
  while i < 300 {
    let st = mb_gum_test_fire_marshal(hook_id, 1, 1, 1, 0)
    if st == 0 {
      ok = ok + 1
    } else {
      full = full + 1
    }
    i = i + 1
  }
  assert_eq(ok + full, 300)
  assert_true(full > 0)
  assert_eq(mb_gum_test_marshal_pending(), ok)
  assert_true(mb_gum_test_marshal_dropped() == full)
  // owner 线程排空
  assert_eq(g.pump_callbacks(1000), ok)
  assert_eq(mb_gum_test_marshal_pending(), 0)
  g.detach(hook_id)
  g.close()
}

///|
/// E1 listener vtable 胶水预留（接口/类型设计，不链接真实二进制）：
/// on_enter/on_leave 由「被钩线程」调用时**只入队**、不执行闭包；owner 线程 pump 才执行；
/// create/destroy 成对持有/释放 `#owned` 闭包；销毁后 invoke 被拒、滞留事件安全丢弃；
/// close 释放未销毁胶水；对无效 hook 的 create 失败且释放闭包。
test "listener vtable 胶水预留：只入队 + 生命周期配平（成对释放）" {
  let g = Gum::init()
  let nop_enter = fn(_ctx : InvocationContext) { () }
  let nop_leave = fn(_ctx : InvocationContext) { () }
  let hook_id = g.attach(b"target_add", nop_enter, nop_leave)
  let glue_seen : Array[InvocationContext] = []
  let closure2 : () -> Unit = fn() {
    match make_invocation(hook_id) {
      Some(ctx) => glue_seen.push(ctx)
      None => ()
    }
  }
  // 胶水接管闭包所有权（#owned）；cb 为无捕获 FuncRef 适配器
  let listener = mb_gum_listener_glue_create(hook_id, fn(f) { f() }, closure2)
  assert_eq(mb_gum_test_live_glues(), 1)
  assert_eq(mb_gum_test_glue_closure_rc(listener), 1)
  // vtable 槽（被钩线程调用）：只入队，不执行闭包
  assert_eq(mb_gum_listener_glue_on_enter(listener, 21, 22), 0)
  assert_eq(mb_gum_listener_glue_on_leave(listener, 23, 24, 99), 0)
  assert_eq(glue_seen.length(), 0)
  assert_eq(mb_gum_test_marshal_pending(), 2)
  // owner 线程派发：闭包执行、上下文保真
  assert_eq(g.pump_callbacks(8), 2)
  assert_eq(glue_seen.length(), 2)
  assert_true(glue_seen[0].args[0] == 21)
  assert_true(glue_seen[0].args[1] == 22)
  assert_true(glue_seen[1].args[0] == 23)
  assert_true(glue_seen[1].args[1] == 24)
  match glue_seen[1].return_value {
    Some(v) => assert_true(v == 99)
    None => abort("on_leave 事件应带返回值")
  }
  // 销毁后滞留事件安全丢弃（不执行已释放闭包）
  assert_eq(mb_gum_listener_glue_on_enter(listener, 5, 5), 0)
  assert_eq(mb_gum_test_marshal_pending(), 1)
  assert_eq(mb_gum_listener_glue_destroy(listener), 0)
  assert_eq(mb_gum_test_live_glues(), 0)
  assert_eq(mb_gum_test_glue_closure_rc(listener), -1)
  assert_eq(g.pump_callbacks(8), 0)
  assert_eq(glue_seen.length(), 2)
  // 重复销毁返回 8、不二次释放；销毁后 invoke 被拒（8）
  assert_eq(mb_gum_listener_glue_destroy(listener), 8)
  assert_eq(mb_gum_listener_glue_on_enter(listener, 1, 1), 8)
  assert_eq(mb_gum_listener_glue_on_leave(listener, 1, 1, 0), 8)
  // 对无效 hook 的 create 失败：句柄为空、闭包已被释放（live 计数不增）
  // （闭包须为捕获型堆闭包：无捕获常量闭包为静态对象，rc 观测不适用）
  let sink_bad : Array[Int32] = []
  let bad = mb_gum_listener_glue_create(9999, fn(f) { f() }, fn() {
    sink_bad.push(0)
  })
  assert_eq(mb_gum_test_live_glues(), 0)
  assert_eq(mb_gum_test_glue_closure_rc(bad), -1)
  assert_eq(mb_gum_listener_glue_on_enter(bad, 1, 1), 8)
  // close 释放未销毁胶水及其闭包（成对释放）
  let sink3 : Array[Int32] = []
  let closure3 : () -> Unit = fn() { sink3.push(0) }
  let listener2 = mb_gum_listener_glue_create(hook_id, fn(f) { f() }, closure3)
  assert_eq(mb_gum_test_live_glues(), 1)
  assert_eq(mb_gum_test_glue_closure_rc(listener2), 1)
  // close 前经胶水入队一条滞留事件：close 后随队列清空、闭包释放，绝不悬挂
  assert_eq(mb_gum_listener_glue_on_enter(listener2, 6, 6), 0)
  assert_eq(mb_gum_test_marshal_pending(), 1)
  g.close()
  assert_eq(mb_gum_test_live_glues(), 0)
  assert_eq(mb_gum_test_marshal_pending(), 0)
  assert_eq(mb_gum_test_glue_closure_rc(listener2), -1)
  assert_eq(mb_gum_listener_glue_on_enter(listener2, 1, 1), 5)
}

///|
/// 缓冲容量校验（缓冲不足）：shim 层对过小 dst / 超长 length 返回 6，绝不越界写。
test "shim 缓冲容量校验（缓冲不足）" {
  let g = Gum::init()
  let tiny : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  let big : FixedArray[Byte] = FixedArray::make(512, b'\x00')
  // memory_read：length 超出 dst 容量 → 6
  assert_eq(mb_gum_memory_read(0x10000000, tiny, 16), 6)
  assert_eq(mb_gum_memory_read(0x10000000, tiny, 4), 0)
  // module_at / region_at：capacity 超出 dst 容量 → 6；容量足够 → 1
  let raw = mb_gum_enumerate_modules()
  assert_eq(mb_gum_module_at(raw, 0, tiny, 16), 6)
  assert_eq(mb_gum_region_at(0, tiny, 16), 6)
  assert_eq(mb_gum_module_at(raw, 0, big, 512), 1)
  assert_eq(mb_gum_region_at(0, big, 512), 1)
  assert_eq(mb_gum_module_at(raw, 2, big, 512), 0) // 枚举结束
  assert_eq(mb_gum_region_at(4, big, 512), 0) // 枚举结束
  mb_gum_modules_free(raw)
  // 公开 API：负 length = 缓冲容量非法
  let r = Ok(g.memory_read(0x10000000, -1)) catch { e => Err(e) }
  assert_true(r is Err(GumError::MemoryReadFailed(_, _)))
  g.close()
}
