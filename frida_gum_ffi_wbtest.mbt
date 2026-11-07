// Whitebox tests run within the package scope.
// Use them to validate internal helpers or invariants.
// Keep them focused; public behavior belongs in `_test.mbt`.
//
// 本轮为桌面 stub：真实 frida-gum devkit 链接受 ADR-0006 许可门禁（G1/G2）约束，本轮不做。

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
/// 门禁开关：gate 1 = 许可（ADR-0006 G1/G2），2 = ptrace。
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
/// 许可门禁可观察路径（ADR-0006）：门禁未过时 `Gum::init` 主动返回
/// `LicenseReviewRequired` / `PtraceDenied` 而非静默继续；失败的 init 不消耗生命周期。
test "许可门禁可观察路径（ADR-0006）" {
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
/// hook 回调触发与注销（ADR-0009 回调对）：`FuncRef` 无捕获适配器 + `#owned` 闭包
/// 二元组由 stub 成对持有/释放；回调内可重入（depth 递增）；detach 后不再触发；
/// close 释放未摘除的 listener 与闭包。
/// 注意：`on_enter`/`on_leave` 签名固定为不带 error，断言只记录上下文、在回调外执行。
test "hook 回调触发与注销（ADR-0009 回调对）" {
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
