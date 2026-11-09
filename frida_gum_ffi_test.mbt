// Blackbox tests run against the package's public API. Use `@frida_gum_ffi` to import.
// Prefer high-level behaviors over implementation details.
// Run `moon test` to execute and `moon test --update` to refresh snapshots.
//
// 当前为桌面 stub（stub/mb_gum_stub.c 模拟 interceptor 表 / 内存区 / 模块与区间表）：
// 真实 frida-gum devkit 链接受 G1 许可审查 + G2 更小替代评估双门禁（见 DECISIONS.md）约束，暂不进行。

///|
/// 逐字节比较（不依赖 `Bytes` 的 `Eq` 语义）。
fn bytes_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// 全链路（桌面 stub）：init → attach → memory_read/write → modules/regions → detach → close；
/// 覆盖重复 init/close、未 init 拒绝操作、缓冲容量校验、未知符号、重复挂接。
test "gum 公开 API 全链路（桌面 stub）" {
  let g = @frida_gum_ffi.Gum::init()
  assert_true(g.state is @frida_gum_ffi.GumState::Initialized)
  // 重复 init（已有活跃运行时）
  let r_dup_init = Ok(@frida_gum_ffi.Gum::init()) catch { e => Err(e) }
  assert_true(r_dup_init is Err(@frida_gum_ffi.GumError::AlreadyInitialized))
  let nop_enter = fn(_ctx : @frida_gum_ffi.InvocationContext) { () }
  let nop_leave = fn(_ctx : @frida_gum_ffi.InvocationContext) { () }
  // 未知符号 → UnknownSymbol
  let r_unknown = Ok(g.attach(b"no_such_symbol", nop_enter, nop_leave)) catch {
    e => Err(e)
  }
  match r_unknown {
    Err(@frida_gum_ffi.GumError::UnknownSymbol(name)) =>
      assert_eq(name, "no_such_symbol")
    _ => abort("attach(no_such_symbol) 应返回 UnknownSymbol")
  }
  // 正常挂接两个 hook
  let hook1 = g.attach(b"target_add", nop_enter, nop_leave)
  assert_true(hook1 != 0)
  let hook2 = g.attach(b"target_concat", nop_enter, nop_leave)
  assert_true(hook2 != 0)
  assert_true(hook1 != hook2)
  // 重复挂接同一符号 → AttachFailed
  let r_dup_attach = Ok(g.attach(b"target_add", nop_enter, nop_leave)) catch {
    e => Err(e)
  }
  assert_true(r_dup_attach is Err(@frida_gum_ffi.GumError::AttachFailed(_, _)))
  // modules：模拟世界模块表
  let modules = g.modules()
  assert_eq(modules.length(), 2)
  assert_eq(modules[0].name, "target_add.dll")
  assert_eq(modules[1].name, "mb_sim_host.exe")
  assert_true(modules[0].base != 0)
  assert_true(modules[0].size != 0)
  // regions：模拟世界区间表，且模块基址在区间中（世界自洽）
  let regions = g.regions()
  assert_eq(regions.length(), 4)
  let mut heap_base : UInt64 = 0
  let mut module_in_regions = false
  for r in regions {
    if r.path == "[simulated heap]" {
      heap_base = r.base
      assert_true(r.protection.read)
      assert_true(r.protection.write)
      assert_true(!r.protection.execute)
    }
    if r.base == modules[0].base {
      module_in_regions = true
    }
  }
  assert_true(heap_base != 0)
  assert_true(module_in_regions)
  // memory_read / memory_write 回环（stub 模拟内存初值为 i & 0xFF）
  let data = g.memory_read(heap_base, 4)
  assert_true(bytes_eq(data, b"\x00\x01\x02\x03"))
  g.memory_write(heap_base, b"\xde\xad\xbe\xef")
  assert_true(bytes_eq(g.memory_read(heap_base, 4), b"\xde\xad\xbe\xef"))
  // 非法地址 → InvalidAddress
  let r_bad_addr = Ok(g.memory_read(0x99999999, 4)) catch { e => Err(e) }
  assert_true(r_bad_addr is Err(@frida_gum_ffi.GumError::InvalidAddress(_)))
  // 缓冲容量校验：负 length → MemoryReadFailed
  let r_neg = Ok(g.memory_read(heap_base, -1)) catch { e => Err(e) }
  assert_true(r_neg is Err(@frida_gum_ffi.GumError::MemoryReadFailed(_, _)))
  // detach / 重复 detach
  g.detach(hook1)
  let r_detach = Ok(g.detach(hook1)) catch { e => Err(e) }
  assert_true(r_detach is Err(@frida_gum_ffi.GumError::DetachFailed(_, _)))
  // close / 重复 close / 未 init 拒绝操作
  g.close()
  let r_close = Ok(g.close()) catch { e => Err(e) }
  assert_true(r_close is Err(@frida_gum_ffi.GumError::NotInitialized))
  let r_read = Ok(g.memory_read(heap_base, 4)) catch { e => Err(e) }
  assert_true(r_read is Err(@frida_gum_ffi.GumError::NotInitialized))
  let r_write = Ok(g.memory_write(heap_base, b"\x00")) catch { e => Err(e) }
  assert_true(r_write is Err(@frida_gum_ffi.GumError::NotInitialized))
  let r_mods = Ok(g.modules()) catch { e => Err(e) }
  assert_true(r_mods is Err(@frida_gum_ffi.GumError::NotInitialized))
  let r_regs = Ok(g.regions()) catch { e => Err(e) }
  assert_true(r_regs is Err(@frida_gum_ffi.GumError::NotInitialized))
  let r_att = Ok(g.attach(b"target_add", nop_enter, nop_leave)) catch {
    e => Err(e)
  }
  assert_true(r_att is Err(@frida_gum_ffi.GumError::NotInitialized))
  let r_det = Ok(g.detach(hook2)) catch { e => Err(e) }
  assert_true(r_det is Err(@frida_gum_ffi.GumError::NotInitialized))
}

///|
/// `Gum::pump_callbacks` 公开契约（E1 marshal 派发泵，见 E1-CALLBACK-THREAD-SAFETY.md）：
/// 空队列派发 = 0；`max_events <= 0` → `CallbackBridgeFailed`（不 panic）；
/// 关闭后派发 → `NotInitialized`。
test "pump_callbacks 公开契约：空队列 / 参数非法 / 关闭后" {
  let g = @frida_gum_ffi.Gum::init()
  // 空队列派发 = 0
  assert_eq(g.pump_callbacks(8), 0)
  // 参数非法 → CallbackBridgeFailed（畸形输入禁 panic，走错误枚举）
  let r_zero = Ok(g.pump_callbacks(0)) catch { e => Err(e) }
  assert_true(r_zero is Err(@frida_gum_ffi.GumError::CallbackBridgeFailed(_)))
  let r_neg = Ok(g.pump_callbacks(-3)) catch { e => Err(e) }
  assert_true(r_neg is Err(@frida_gum_ffi.GumError::CallbackBridgeFailed(_)))
  // 关闭后派发 → NotInitialized
  g.close()
  let r_closed = Ok(g.pump_callbacks(8)) catch { e => Err(e) }
  assert_true(r_closed is Err(@frida_gum_ffi.GumError::NotInitialized))
}
