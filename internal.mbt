///|
/// ---- 私有 shim 与解析辅助（不导出，pkg.generated.mbti 不含本节符号）----
///
/// shim 可见性收敛决策（见 DECISIONS.md）后，`frida_gum_ffi.mbt` 的 12 个 `mb_gum_*` 也已收敛为包私有，
/// 与本节的私有 shim（`mb_gum_region_at` / `mb_gum_current_context` / `mb_gum_marshal_drain`）
/// 及 `listener_glue.mbt` 的 4 个 `mb_gum_listener_glue_*` 合计 19 个 `mb_gum_*` C 声明，
/// **全部是私有实现 ABI，非公共 API**。
/// 本节补齐两处数据源缺口：
///   1. `Gum::regions` 无数据源 shim → `mb_gum_region_at`；
///   2. 回调闭包签名固定为 `() -> Unit`，InvocationContext 无回传通道
///      → `mb_gum_current_context`（stub 序列化、MoonBit 侧解析）。
/// 另承载 E1 marshal 派发泵（见 `E1-CALLBACK-THREAD-SAFETY.md`）：
///   3. 被钩线程只入队、owner 线程派发 → `mb_gum_marshal_drain`（`Gum::pump_callbacks` 的 C 侧）。
/// 记录格式（小端）由 `stub/mb_gum_stub.c` 头部注释定义，两侧同构。

///|
/// 读取区间枚举第 `index` 项到 `dst`：1 = 有效，0 = 结束，其余为错误码。
#borrow(dst)
extern "C" fn mb_gum_region_at(
  index : Int32,
  dst : FixedArray[Byte],
  capacity : Int32,
) -> Int32 = "mb_gum_region_at"

///|
/// 回读当前触发的调用上下文记录：返回写入字节数（> 0），0 = 无上下文，其余为错误码。
#borrow(dst)
extern "C" fn mb_gum_current_context(
  dst : FixedArray[Byte],
  capacity : Int32,
) -> Int32 = "mb_gum_current_context"

///|
/// owner 线程派发泵（E1 marshal）：出队已 marshal 的调用事件并在**调用本函数的线程**执行
/// MoonBit 闭包（被钩线程绝不执行闭包）。返回 >= 0 = 派发条数，< 0 = 错误码取负
/// （-5 未初始化，-6 参数非法）。必须在 owner 线程调用（见 `Gum::pump_callbacks`）。
extern "C" fn mb_gum_marshal_drain(max_events : Int32) -> Int32 = "mb_gum_marshal_drain"

///|
/// 上下文记录缓冲容量（记录为 50 字节，留出余量）。
const CONTEXT_BUFFER_CAPACITY : Int32 = 128

///|
/// 模块/区间记录缓冲容量。
const ENUM_BUFFER_CAPACITY : Int32 = 512

///|
/// 读取小端 16 位无符号。
fn parse_u16_le(b : Bytes, off : Int32) -> Int32 {
  b[off].to_int() | (b[off + 1].to_int() << 8)
}

///|
/// 读取小端 32 位无符号（作为非负 Int 使用）。
fn parse_u32_le(b : Bytes, off : Int32) -> Int32 {
  b[off].to_int() |
  (b[off + 1].to_int() << 8) |
  (b[off + 2].to_int() << 16) |
  (b[off + 3].to_int() << 24)
}

///|
/// 读取小端 64 位。
fn parse_u64_le(b : Bytes, off : Int32) -> UInt64 {
  let mut v : UInt64 = 0
  for i in 0..<8 {
    v = v | (b[off + i].to_uint64() << (i * 8))
  }
  v
}

///|
/// 记录字段为 ASCII 字节；逐字节映射为 code point 后构造 String
///（`Bytes::to_unchecked_string` 会把字节对重解释为 UTF-16，不能用于此处）。
fn bytes_to_string(b : Bytes) -> String {
  record_string(b, 0, b.length())
}

///|
/// 从记录缓冲按 `[offset, offset+length)` 解出 ASCII 字符串。
fn record_string(b : Bytes, offset : Int32, length : Int32) -> String {
  let chars : Array[Char] = []
  for i in 0..<length {
    chars.push(b[offset + i].to_int().unsafe_to_char())
  }
  String::from_array(chars[:])
}

///|
/// 按 stub 记录格式解析模块项。
fn parse_module_record(b : Bytes) -> ModuleInfo {
  let name_len = parse_u16_le(b, 0)
  let name = record_string(b, 2, name_len)
  let path_off = 2 + name_len
  let path_len = parse_u16_le(b, path_off)
  let path = record_string(b, path_off + 2, path_len)
  let base_off = path_off + 2 + path_len
  ModuleInfo::{
    name,
    path,
    base: parse_u64_le(b, base_off),
    size: parse_u64_le(b, base_off + 8),
  }
}

///|
/// 按 stub 记录格式解析内存区间项（prot 位：bit0 = R，bit1 = W，bit2 = X）。
fn parse_region_record(b : Bytes) -> MemoryRegion {
  let path_off = 17
  let path_len = parse_u16_le(b, 17)
  let prot = b[16].to_int()
  MemoryRegion::{
    base: parse_u64_le(b, 0),
    end: parse_u64_le(b, 8),
    protection: MemoryProtection::{
      read: (prot & 1) != 0,
      write: (prot & 2) != 0,
      execute: (prot & 4) != 0,
    },
    path: record_string(b, path_off + 2, path_len),
  }
}

///|
/// 按 stub 记录格式解析调用上下文：
/// point u8 / depth i32 / thread_id u64 / fn_addr u64 / argc i32 / args / has_ret u8 / ret u64。
fn parse_context_record(
  b : Bytes,
  n : Int32,
  hook_id : HookId,
) -> InvocationContext? {
  let argc = parse_u32_le(b, 21)
  if argc < 0 || argc > 2 {
    return None
  }
  let need = 26 + argc * 8
  if n < need {
    return None
  }
  let point_cut = if b[0].to_int() == 1 {
    PointCut::Enter
  } else {
    PointCut::Leave
  }
  let args : Array[UInt64] = []
  for i in 0..<argc {
    args.push(parse_u64_le(b, 25 + i * 8))
  }
  let ret_off = 25 + argc * 8
  let return_value = if b[ret_off].to_int() == 1 {
    Some(parse_u64_le(b, ret_off + 1))
  } else {
    None
  }
  Some(InvocationContext::{
    hook_id,
    point_cut,
    thread_id: parse_u64_le(b, 5),
    depth: parse_u32_le(b, 1),
    function_address: parse_u64_le(b, 13),
    args,
    return_value,
  })
}
