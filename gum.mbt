///|
/// ---- MoonBit 侧公开 API 实现（签名与 API.md / pkg.generated.mbti 一致）----
///
/// 资源与状态机（DESIGN.md §5/§6）：
///   - 进程级单例 runtime；init/deinit 单线程配对调用，同时最多一个活跃运行时；
///   - 重复 init（已有活跃运行时）→ `AlreadyInitialized`；重复 close / 未 init 操作 → `NotInitialized`；
///   - 失败逆序释放；`close` 释放全部句柄（含未 detach 的 listener 与 `#owned` 闭包）；
///   - C status → `GumError` 映射见 `stub/mb_gum_stub.c` 头部契约。
/// 桌面 stub：真实 frida-gum devkit 链接受 G1 许可审查 + G2 更小替代评估双门禁（见 DECISIONS.md）约束，当前不做。

///|
/// C status → `GumError`（init 阶段；3 = 许可门禁，4 = ptrace，9 = 重复 init）。
fn init_failure(code : Int32) -> GumError {
  if code == 3 {
    GumError::LicenseReviewRequired(
      "许可门禁（G1 许可审查 + G2 更小替代评估，见 DECISIONS.md）未通过，禁止链接真实 frida-gum devkit",
    )
  } else if code == 4 {
    GumError::PtraceDenied(
      "目标进程拒绝 ptrace 附加（ptrace 权限不足）",
    )
  } else if code == 9 {
    GumError::AlreadyInitialized
  } else {
    GumError::DevkitNotFound(
      "插桩运行时初始化失败（status=\{code}）",
    )
  }
}

///|
/// 由 stub 回传的上下文记录构造一次调用快照；无有效记录返回 `None`（绝不 panic）。
fn make_invocation(hook_id : HookId) -> InvocationContext? {
  let buf : FixedArray[Byte] = FixedArray::make(
    CONTEXT_BUFFER_CAPACITY,
    b'\x00',
  )
  let n = mb_gum_current_context(buf, CONTEXT_BUFFER_CAPACITY)
  if n <= 0 {
    return None
  }
  parse_context_record(Bytes::from_array(buf[0:n]), n, hook_id)
}

///|
/// 初始化插桩运行时。
///
/// - 获取资源：gum runtime + interceptor（进程级单例）；失败时逆序释放。
/// - 错误：devkit 缺失、重复初始化、ptrace 权限不足、许可门禁未过均以 `GumError` 传播。
/// - 线程：必须在单一线程完成 init，之后 hook 回调发生在被钩线程；禁止并发 init/deinit。
/// - 非目标：不做设备发现/传输/脚本运行时、不做 Java 方法 hook、不做符号解析。
pub fn Gum::init() -> Gum raise GumError {
  let runtime = mb_gum_init_embedded()
  let interceptor = mb_gum_interceptor_obtain(runtime)
  // 探针事务：确认运行时可用并取回门禁/重复 init 状态码（事务配平成对）。
  let st = mb_gum_transaction(interceptor, 1)
  if st != 0 {
    mb_gum_deinit_embedded(runtime) // 失败逆序释放（stub 对无效句柄为安全 no-op）
    raise init_failure(st)
  }
  let st2 = mb_gum_transaction(interceptor, 0)
  if st2 != 0 {
    mb_gum_deinit_embedded(runtime)
    raise init_failure(st2)
  }
  Gum::{ runtime, interceptor, state: GumState::Initialized, hook_count: 0, }
}

///|
/// 关闭运行时并释放全部句柄（含未 detach 的 listener 与 `#owned` 闭包）。
/// **不会二次释放，重复调用返回明确错误**（重复 close / 未初始化 → `NotInitialized`）。
pub fn Gum::close(self : Gum) -> Unit raise GumError {
  // 探针事务确认运行时存活并配平事务，再整体释放。
  let st = mb_gum_transaction(self.interceptor, 1)
  if st != 0 {
    raise GumError::NotInitialized
  }
  let st2 = mb_gum_transaction(self.interceptor, 0)
  if st2 != 0 {
    raise GumError::NotInitialized
  }
  mb_gum_deinit_embedded(self.runtime)
}

///|
/// 按符号挂 hook。回调经 **E1 marshal** 派发（见 `E1-CALLBACK-THREAD-SAFETY.md`）：
/// 被钩线程只把调用上下文浅拷贝入队，`on_enter` / `on_leave` **不在被钩线程执行**，
/// 而在 owner 线程调用 `Gum::pump_callbacks` 时执行、可重入（`depth` 为被钩线程观测深度）；
/// 回调内禁止阻塞与跨线程 JNI。
///
/// 回调桥（见 DECISIONS.md「回调桥设计」）：无捕获适配器 `invoke_closure`（`FuncRef`）+ 捕获用户回调的
/// `#owned` 闭包二元组传 C 侧；detach 时由 stub `moonbit_decref` 成对释放。
pub fn Gum::attach(
  self : Gum,
  symbol : Bytes,
  on_enter : (InvocationContext) -> Unit,
  on_leave : (InvocationContext) -> Unit,
) -> HookId raise GumError {
  let st = mb_gum_transaction(self.interceptor, 1)
  if st != 0 {
    if st == 5 {
      raise GumError::NotInitialized
    }
    raise GumError::AttachFailed(st, "无法开启 interceptor 事务")
  }
  let hook_id = mb_gum_attach(self.interceptor, symbol)
  if hook_id == 0 {
    // attach 失败原因由事务提交回传（1 = 未知符号，2 = 已挂/失败）。
    let reason = mb_gum_transaction(self.interceptor, 0)
    if reason == 1 {
      raise GumError::UnknownSymbol(bytes_to_string(symbol))
    }
    raise GumError::AttachFailed(reason, "interceptor 拒绝挂接")
  }
  let closure : () -> Unit = fn() {
    match make_invocation(hook_id) {
      Some(ctx) =>
        if ctx.point_cut is PointCut::Enter {
          on_enter(ctx)
        } else {
          on_leave(ctx)
        }
      None => ()
    }
  }
  // 无捕获适配器（见 DECISIONS.md「回调桥设计」）：`FuncRef` + `#owned` 闭包二元组传 C 侧；
  // detach / close 时由 stub `moonbit_decref` 成对释放闭包。
  let st2 = mb_gum_set_callbacks(self.runtime, hook_id, fn(f) { f() }, closure)
  if st2 != 0 {
    ignore(mb_gum_detach(self.interceptor, hook_id))
    ignore(mb_gum_transaction(self.interceptor, 0))
    if st2 == 5 {
      raise GumError::NotInitialized
    }
    raise GumError::AttachFailed(st2, "回调桥注册失败")
  }
  let st3 = mb_gum_transaction(self.interceptor, 0)
  if st3 != 0 {
    ignore(mb_gum_detach(self.interceptor, hook_id))
    if st3 == 5 {
      raise GumError::NotInitialized
    }
    raise GumError::AttachFailed(st3, "interceptor 事务提交失败")
  }
  hook_id
}

///|
/// 派发（pump）已 marshal 的回调事件：出队并在**本线程**执行 `on_enter` / `on_leave`
/// 闭包，返回本次派发条数。
///
/// - 线程：**必须在 owner 线程（初始化并使用本库的线程）调用**；被钩线程只入队不执行
///   MoonBit 闭包（E1 marshal，见 `E1-CALLBACK-THREAD-SAFETY.md`）。可重入：派发中入队的
///   新事件可在同一次 pump 中继续派发，直至 `max_events` 用尽或队列为空。
/// - 参数：`max_events > 0` 为单次派发上限；`<= 0` 视为参数非法。
/// - 错误：`CallbackBridgeFailed`（参数非法）；运行时已关闭 → `NotInitialized`。
/// - 关闭竞态：detach / close 后滞留的未派发事件被安全丢弃（不悬挂、不二次释放），
///   不会在派发时执行已释放闭包。
pub fn Gum::pump_callbacks(
  _self : Gum,
  max_events : Int32,
) -> Int32 raise GumError {
  let ret = mb_gum_marshal_drain(max_events)
  if ret >= 0 {
    return ret
  }
  if ret == -5 {
    raise GumError::NotInitialized
  }
  raise GumError::CallbackBridgeFailed(
    "pump_callbacks 的 max_events 必须为正数（\{max_events}）",
  )
}

///|
/// 摘除 hook 并释放回调闭包（listener 与 `#owned` 闭包成对释放）。
/// **不会二次释放，重复调用返回明确错误**（重复 detach → `DetachFailed`；运行时已关闭 → `NotInitialized`）。
pub fn Gum::detach(self : Gum, hook_id : HookId) -> Unit raise GumError {
  let st = mb_gum_detach(self.interceptor, hook_id)
  if st != 0 {
    if st == 5 {
      raise GumError::NotInitialized
    }
    raise GumError::DetachFailed(st, "摘除 hook 失败")
  }
}

///|
/// 读进程内存，返回原始字节（不做结构解释）；`length < 0` 视为缓冲容量非法。
pub fn Gum::memory_read(
  _self : Gum,
  address : Address,
  length : Int32,
) -> Bytes raise GumError {
  if length < 0 {
    raise GumError::MemoryReadFailed(address, length)
  }
  let dst : FixedArray[Byte] = FixedArray::make(length, b'\x00')
  let st = mb_gum_memory_read(address, dst, length)
  if st != 0 {
    if st == 5 {
      raise GumError::NotInitialized
    }
    if st == 7 {
      raise GumError::InvalidAddress(address)
    }
    raise GumError::MemoryReadFailed(address, length)
  }
  Bytes::from_array(dst[0:length])
}

///|
/// 写进程内存；调用方必须自行保证目标页可写与 W^X 约束。
pub fn Gum::memory_write(
  _self : Gum,
  address : Address,
  data : Bytes,
) -> Unit raise GumError {
  let length = data.length()
  let st = mb_gum_memory_write(address, data, length)
  if st != 0 {
    if st == 5 {
      raise GumError::NotInitialized
    }
    raise GumError::MemoryWriteFailed(address, length)
  }
}

///|
/// 枚举已加载模块（枚举结果由 `mb_gum_modules_free` 成对释放）。
pub fn Gum::modules(_self : Gum) -> Array[ModuleInfo] raise GumError {
  let raw = mb_gum_enumerate_modules()
  let dst : FixedArray[Byte] = FixedArray::make(ENUM_BUFFER_CAPACITY, b'\x00')
  let out : Array[ModuleInfo] = []
  let mut index = 0
  while true {
    let st = mb_gum_module_at(raw, index, dst, ENUM_BUFFER_CAPACITY)
    if st == 1 {
      out.push(parse_module_record(Bytes::from_array(dst)))
      index = index + 1
    } else if st == 0 {
      break
    } else {
      mb_gum_modules_free(raw)
      if st == 5 {
        raise GumError::NotInitialized
      }
      raise GumError::ModuleEnumerateFailed(st)
    }
  }
  mb_gum_modules_free(raw)
  out
}

///|
/// 枚举内存区间（用于定位目标 .so 基址）。
pub fn Gum::regions(_self : Gum) -> Array[MemoryRegion] raise GumError {
  let dst : FixedArray[Byte] = FixedArray::make(ENUM_BUFFER_CAPACITY, b'\x00')
  let out : Array[MemoryRegion] = []
  let mut index = 0
  while true {
    let st = mb_gum_region_at(index, dst, ENUM_BUFFER_CAPACITY)
    if st == 1 {
      out.push(parse_region_record(Bytes::from_array(dst)))
      index = index + 1
    } else if st == 0 {
      break
    } else {
      if st == 5 {
        raise GumError::NotInitialized
      }
      raise GumError::ModuleEnumerateFailed(st)
    }
  }
  out
}
