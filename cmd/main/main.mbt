///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
///
/// 桌面 stub 演示（真实 frida-gum devkit 链接受 G1/G2 双门禁约束，见 docs/DECISIONS.md；暂不进行）：
/// init → modules/regions → memory 读写回环 → detach → close。
fn demo() -> Unit raise {
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
  let data = g.memory_read(heap_base, 4)
  println("memory@heap[0..4] read: \{data.length()} bytes")
  g.memory_write(heap_base, b"\xde\xad\xbe\xef")
  g.detach(hook_id)
  g.close()
  println("gum lifecycle ok")
}

///|
fn main {
  let result = Ok(demo()) catch { e => Err(e) }
  match result {
    Ok(_) => println("frida_gum_ffi: desktop stub demo ok")
    Err(_) => println("frida_gum_ffi: demo failed")
  }
}
