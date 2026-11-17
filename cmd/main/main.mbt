///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
///
/// 桌面 stub 演示（真实 frida-gum devkit 链接受 G1/G2 双门禁约束，见 README §2/§6；暂不进行）：
/// init → modules/regions → memory 读写回环 → detach → close。
/// `fail_mode`（W4 自测）：经真实公开 API 失败路径注入（非法地址读 → InvalidAddress）；
/// GumError 为只读 suberror，下游不可构造变体，故不用伪造错误。
fn demo(fail_mode : Bool) -> Unit raise {
  let g = @frida_gum_ffi.Gum::init()
  let modules = g.modules()
  for m in modules {
    println("module: \{m.name} @ \{m.base}")
  }
  let regions = g.regions()
  println("regions: \{regions.length()}")
  let mut heap_base : UInt64 = 0
  for r in regions {
    if r.path == "[simulated heap]" {
      heap_base = r.base
    }
  }
  let hook_id = g.attach(b"target_add", fn(_ctx) { () }, fn(_ctx) { () })
  if fail_mode {
    // 确定性失败注入：非法地址读必然 raise InvalidAddress（真实错误传播路径）
    let _ = g.memory_read(0x99999999, 1)
  }
  let data = g.memory_read(heap_base, 4)
  println("memory@heap[0..4] read: \{data.length()} bytes")
  g.memory_write(heap_base, b"\xde\xad\xbe\xef")
  g.detach(hook_id)
  g.close()
  println("gum lifecycle ok")
}

///|
/// W4 fail-closed：失败路径退出码 1（此前 fail-open：失败仍 exit 0）。
/// `--selftest-fail` 为确定性失败注入自测旗标（走真实公开 API 失败路径，不新增错误变体）；
/// 成功路径输出与退出码不变。
fn main {
  let fail_mode = @env.args().contains("--selftest-fail")
  let result = Ok(demo(fail_mode)) catch { e => Err(e) }
  match result {
    Ok(_) => println("frida_gum_ffi: desktop stub demo ok")
    Err(_) => {
      println("frida_gum_ffi: demo failed")
      @env.exit(1)
    }
  }
}
