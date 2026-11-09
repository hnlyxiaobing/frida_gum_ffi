/*
 * frida_gum_ffi — 桌面 C shim stub（G1/G2 双门禁未通过，见 DECISIONS.md；真实 devkit 禁止引入/链接/下载）。
 *
 * 本文件是**项目自带的 gum 行为模拟桩**，不是伪实现：
 *   - 模拟 interceptor 表（符号 → hook id → listener）、模拟进程内存区、模块表、内存区间表；
 *   - 使 moon build / moon test 在 Windows 桌面真实编译、链接、运行；
 *   - 「链接真实 frida-gum devkit」继续受 G1 许可审查 + G2 更小替代评估双门禁（见 DECISIONS.md）约束，当前不做。
 *
 * 回调路径（见 DECISIONS.md「回调桥设计」）：`FuncRef[(() -> Unit) -> Unit]` + `#owned closure` 二元组。
 * stub 保存 (cb, closure) 指针对：
 *   - 触发时：直接调用 cb(closure)；实测本工具链闭包参数为 borrow 约定，
 *     调用不消费引用（rc 不变），无需 incref；
 *   - 注销时（detach / deinit）：moonbit_decref(closure)，与 set 时的所有权转移成对。
 * `#owned` 语义见 moon FFI 文档「The borrow and owned attribute」。
 *
 * ---- status code 契约（MoonBit 侧错误映射依据）----
 *   0  OK
 *   1  unknown symbol（attach；事务提交时回传）
 *   2  attach failed / already attached
 *   3  license review required（G1/G2 门禁未通过，init 探针回传）
 *   4  ptrace denied（init 探针回传）
 *   5  not initialized（无活跃运行时）
 *   6  buffer too small / bad args
 *   7  invalid address
 *   8  generic failure
 *   9  already initialized（进程内已有活跃 runtime）
 * module_at / region_at 约定：1 = 有效记录，0 = 枚举结束，其余为上述错误码。
 *
 * shim 清单：
 *   公开（API.md 12 个）：mb_gum_init_embedded / mb_gum_deinit_embedded /
 *     mb_gum_interceptor_obtain / mb_gum_transaction / mb_gum_attach / mb_gum_detach /
 *     mb_gum_set_callbacks / mb_gum_memory_read / mb_gum_memory_write /
 *     mb_gum_enumerate_modules / mb_gum_module_at / mb_gum_modules_free
 *   私有（API.md 缺口补齐，不导出）：mb_gum_region_at（Gum::regions 数据源）、
 *     mb_gum_current_context（回调上下文回传通道）
 *   测试缝（仅供 _wbtest）：mb_gum_test_fire / mb_gum_test_set_gate /
 *     mb_gum_test_live_hooks / mb_gum_test_live_closures / mb_gum_test_closure_rc
 */

#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "moonbit.h"

/* ===================== 模拟世界常量 ===================== */

#define MB_SIM_MEM_BASE 0x10000000ULL
#define MB_SIM_MEM_SIZE 0x1000

#define MB_MAX_HOOKS 8

/* status codes */
#define MB_GUM_OK 0
#define MB_ERR_UNKNOWN_SYMBOL 1
#define MB_ERR_ATTACH_FAILED 2
#define MB_ERR_LICENSE_REVIEW 3
#define MB_ERR_PTRACE_DENIED 4
#define MB_ERR_NOT_INITIALIZED 5
#define MB_ERR_BUFFER 6
#define MB_ERR_INVALID_ADDRESS 7
#define MB_ERR_GENERIC 8
#define MB_ERR_ALREADY_INITIALIZED 9

/* gate ids for mb_gum_test_set_gate */
#define MB_GATE_LICENSE 1
#define MB_GATE_PTRACE 2

/* point cut in mb_gum_test_fire / context record */
#define MB_POINT_ENTER 1
#define MB_POINT_LEAVE 2

/* context record layout (little endian):
 *   [0]     point       u8
 *   [1..5)  depth       i32
 *   [5..13) thread_id   u64
 *   [13..21) fn_addr    u64
 *   [21..25) argc       i32
 *   [25..)  args        argc * u64
 *   [25+8*argc]         has_ret u8
 *   [26+8*argc..]       return_value u64
 */
#define MB_CTX_HEADER_SIZE 25
#define MB_CTX_MAX_ARGS 2

/* module record: u16 name_len, name, u16 path_len, path, u64 base, u64 size */
/* region record: u64 base, u64 end, u8 prot, u16 path_len, path */

/* ===================== 模拟世界数据 ===================== */

struct mb_symbol {
  const char *name;
  uint64_t addr;
};

static const struct mb_symbol mb_symbols[] = {
  { "target_add", 0x140000100ULL },
  { "target_concat", 0x140000140ULL },
  { "target_swap", 0x140000180ULL },
};
#define MB_SYMBOL_COUNT ((int32_t)(sizeof(mb_symbols) / sizeof(mb_symbols[0])))

struct mb_module {
  const char *name;
  const char *path;
  uint64_t base;
  uint64_t size;
};

static const struct mb_module mb_modules[] = {
  { "target_add.dll", "C:\\sim\\modules\\target_add.dll", 0x140000000ULL, 0x2000ULL },
  { "mb_sim_host.exe", "C:\\sim\\mb_sim_host.exe", 0x140010000ULL, 0x3000ULL },
};
#define MB_MODULE_COUNT ((int32_t)(sizeof(mb_modules) / sizeof(mb_modules[0])))

struct mb_region {
  uint64_t base;
  uint64_t end;
  uint8_t prot; /* bit0 = R, bit1 = W, bit2 = X */
  const char *path;
};

static const struct mb_region mb_regions[] = {
  { 0x140000000ULL, 0x140001000ULL, 5, "C:\\sim\\modules\\target_add.dll" },
  { 0x140001000ULL, 0x140002000ULL, 3, "C:\\sim\\modules\\target_add.dll" },
  { MB_SIM_MEM_BASE, MB_SIM_MEM_BASE + MB_SIM_MEM_SIZE, 3, "[simulated heap]" },
  { 0x140010000ULL, 0x140011000ULL, 5, "C:\\sim\\mb_sim_host.exe" },
};
#define MB_REGION_COUNT ((int32_t)(sizeof(mb_regions) / sizeof(mb_regions[0])))

/* ===================== 运行时状态 ===================== */

enum mb_state {
  MB_ST_UNINIT = 0,
  MB_ST_BLOCKED = 1, /* init 被许可门禁 / ptrace 门禁挡住 */
  MB_ST_ACTIVE = 2
};

typedef void (*mb_closure_fn)(void *closure);

struct mb_hook {
  int32_t active;
  uint64_t id;
  uint64_t fn_addr;
  char symbol[48];
  mb_closure_fn cb;
  void *closure;
};

static int32_t mb_state = MB_ST_UNINIT;
static int32_t mb_gate_license = 0;
static int32_t mb_gate_ptrace = 0;
static int32_t mb_last_init_reason = 0;

static int32_t mb_txn_open = 0;
static int32_t mb_txn_error = 0;

static int mb_runtime_token = 0;
static int mb_interceptor_token = 0;
static int mb_modules_token = 0;
static int32_t mb_modules_live = 0;

static struct mb_hook mb_hooks[MB_MAX_HOOKS];
static uint64_t mb_next_hook_id = 1;

static uint8_t mb_sim_mem[MB_SIM_MEM_SIZE];

/* 调用上下文（mb_gum_current_context 回传给 MoonBit 闭包） */
struct mb_ctx {
  int32_t active;
  uint8_t point;
  int32_t depth;
  uint64_t thread_id;
  uint64_t fn_addr;
  int32_t argc;
  uint64_t args[MB_CTX_MAX_ARGS];
  uint8_t has_ret;
  uint64_t ret;
};
static struct mb_ctx mb_ctx;
static int32_t mb_depth = 0;

/* ===================== 内部工具 ===================== */

static uint64_t mb_thread_id(void) {
#ifdef _WIN32
  return (uint64_t)GetCurrentThreadId();
#else
  return 1ULL;
#endif
}

static void mb_put_u16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void mb_put_u32(uint8_t *p, uint32_t v) {
  mb_put_u16(p, (uint16_t)(v & 0xFFFF));
  mb_put_u16(p + 2, (uint16_t)((v >> 16) & 0xFFFF));
}

static void mb_put_u64(uint8_t *p, uint64_t v) {
  mb_put_u32(p, (uint32_t)(v & 0xFFFFFFFFULL));
  mb_put_u32(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFULL));
}

static int32_t mb_buf_ok(const uint8_t *dst, int32_t capacity) {
  if (capacity < 0 || dst == NULL) {
    return 0;
  }
  if (capacity > Moonbit_array_length((void *)dst)) {
    return 0;
  }
  return 1;
}

static struct mb_hook *mb_find_hook(uint64_t hook_id) {
  int32_t i;
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    if (mb_hooks[i].active && mb_hooks[i].id == hook_id) {
      return &mb_hooks[i];
    }
  }
  return NULL;
}

static struct mb_hook *mb_find_hook_by_symbol(const char *name) {
  int32_t i;
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    if (mb_hooks[i].active && strcmp(mb_hooks[i].symbol, name) == 0) {
      return &mb_hooks[i];
    }
  }
  return NULL;
}

static void mb_release_hook(struct mb_hook *h) {
  if (h->closure != NULL) {
    moonbit_decref(h->closure);
    h->closure = NULL;
    h->cb = NULL;
  }
  h->active = 0;
}

static void mb_reset_world(void) {
  int32_t i;
  for (i = 0; i < MB_SIM_MEM_SIZE; i++) {
    mb_sim_mem[i] = (uint8_t)(i & 0xFF);
  }
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    mb_hooks[i].active = 0;
    mb_hooks[i].closure = NULL;
    mb_hooks[i].cb = NULL;
  }
  mb_txn_open = 0;
  mb_txn_error = 0;
  mb_modules_live = 0;
  memset(&mb_ctx, 0, sizeof(mb_ctx));
  mb_depth = 0;
}

static const struct mb_symbol *mb_find_symbol(const uint8_t *name, int32_t len) {
  int32_t i;
  for (i = 0; i < MB_SYMBOL_COUNT; i++) {
    size_t n = strlen(mb_symbols[i].name);
    if ((int32_t)n == len && memcmp(mb_symbols[i].name, name, (size_t)len) == 0) {
      return &mb_symbols[i];
    }
  }
  return NULL;
}

/* ===================== 公开 shim（API.md 12 个） ===================== */

MOONBIT_FFI_EXPORT
void *mb_gum_init_embedded(void) {
  if (mb_gate_license) {
    mb_state = MB_ST_BLOCKED;
    mb_last_init_reason = MB_ERR_LICENSE_REVIEW;
    return (void *)&mb_runtime_token;
  }
  if (mb_gate_ptrace) {
    mb_state = MB_ST_BLOCKED;
    mb_last_init_reason = MB_ERR_PTRACE_DENIED;
    return (void *)&mb_runtime_token;
  }
  if (mb_state != MB_ST_UNINIT) {
    mb_last_init_reason = MB_ERR_ALREADY_INITIALIZED;
    return NULL;
  }
  mb_reset_world();
  mb_state = MB_ST_ACTIVE;
  mb_last_init_reason = 0;
  return (void *)&mb_runtime_token;
}

MOONBIT_FFI_EXPORT
void mb_gum_deinit_embedded(void *runtime) {
  int32_t i;
  if (runtime == NULL || runtime != (void *)&mb_runtime_token) {
    return; /* 安全 no-op（含失败逆序释放路径） */
  }
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    if (mb_hooks[i].active) {
      mb_release_hook(&mb_hooks[i]); /* 成对释放 #owned 闭包 */
    }
  }
  mb_state = MB_ST_UNINIT;
  mb_last_init_reason = 0;
  mb_txn_open = 0;
  mb_txn_error = 0;
  mb_modules_live = 0;
}

MOONBIT_FFI_EXPORT
void *mb_gum_interceptor_obtain(void *runtime) {
  if (runtime == NULL || runtime != (void *)&mb_runtime_token) {
    return NULL;
  }
  if (mb_state != MB_ST_ACTIVE) {
    return NULL;
  }
  return (void *)&mb_interceptor_token;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_transaction(void *interceptor, int32_t begin) {
  if (interceptor == NULL) {
    /* init 探针：回传运行时不可用的原因（许可门禁 / ptrace / 重复 init） */
    return mb_last_init_reason != 0 ? mb_last_init_reason : MB_ERR_NOT_INITIALIZED;
  }
  if (mb_state != MB_ST_ACTIVE || interceptor != (void *)&mb_interceptor_token) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (begin == 1) {
    if (mb_txn_open) {
      return MB_ERR_GENERIC; /* 事务未配平（ADR：end twice 曾致 hang，此处显式报错） */
    }
    mb_txn_open = 1;
    mb_txn_error = 0;
    return MB_GUM_OK;
  }
  if (begin == 0) {
    if (!mb_txn_open) {
      return MB_ERR_GENERIC;
    }
    mb_txn_open = 0;
    {
      int32_t e = mb_txn_error;
      mb_txn_error = 0;
      return e;
    }
  }
  return MB_ERR_GENERIC;
}

MOONBIT_FFI_EXPORT
uint64_t mb_gum_attach(void *interceptor, uint8_t *symbol) {
  const struct mb_symbol *sym;
  int32_t i;
  int32_t len;
  if (interceptor != (void *)&mb_interceptor_token || mb_state != MB_ST_ACTIVE) {
    if (mb_txn_open) {
      mb_txn_error = MB_ERR_GENERIC;
    }
    return 0;
  }
  len = Moonbit_array_length(symbol);
  sym = mb_find_symbol(symbol, len);
  if (sym == NULL) {
    if (mb_txn_open) {
      mb_txn_error = MB_ERR_UNKNOWN_SYMBOL;
    }
    return 0;
  }
  if (mb_find_hook_by_symbol(sym->name) != NULL) {
    if (mb_txn_open) {
      mb_txn_error = MB_ERR_ATTACH_FAILED;
    }
    return 0;
  }
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    if (!mb_hooks[i].active) {
      mb_hooks[i].active = 1;
      mb_hooks[i].id = mb_next_hook_id++;
      mb_hooks[i].fn_addr = sym->addr;
      mb_hooks[i].cb = NULL;
      mb_hooks[i].closure = NULL;
      strncpy(mb_hooks[i].symbol, sym->name, sizeof(mb_hooks[i].symbol) - 1);
      mb_hooks[i].symbol[sizeof(mb_hooks[i].symbol) - 1] = '\0';
      return mb_hooks[i].id;
    }
  }
  if (mb_txn_open) {
    mb_txn_error = MB_ERR_ATTACH_FAILED;
  }
  return 0;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_detach(void *interceptor, uint64_t hook_id) {
  struct mb_hook *h;
  if (interceptor != (void *)&mb_interceptor_token || mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  h = mb_find_hook(hook_id);
  if (h == NULL) {
    return MB_ERR_GENERIC;
  }
  mb_release_hook(h); /* 释放 listener 与 #owned 闭包 */
  return MB_GUM_OK;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_set_callbacks(
  void *runtime,
  uint64_t hook_id,
  mb_closure_fn cb,
  void *closure
) {
  struct mb_hook *h;
  /* #owned(closure)：本函数获得闭包所有权，无论成败都负责释放 */
  if (runtime != (void *)&mb_runtime_token || mb_state != MB_ST_ACTIVE || cb == NULL) {
    if (closure != NULL) {
      moonbit_decref(closure);
    }
    return MB_ERR_NOT_INITIALIZED;
  }
  h = mb_find_hook(hook_id);
  if (h == NULL) {
    if (closure != NULL) {
      moonbit_decref(closure);
    }
    return MB_ERR_GENERIC;
  }
  if (h->closure != NULL) {
    moonbit_decref(h->closure); /* 覆盖注册时成对释放旧闭包 */
  }
  h->cb = cb;
  h->closure = closure;
  return MB_GUM_OK;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_memory_read(uint64_t address, uint8_t *dst, int32_t length) {
  if (!mb_buf_ok(dst, length) || length < 0) {
    return MB_ERR_BUFFER;
  }
  if (mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (address < MB_SIM_MEM_BASE ||
      address + (uint64_t)length > MB_SIM_MEM_BASE + MB_SIM_MEM_SIZE) {
    return MB_ERR_INVALID_ADDRESS;
  }
  memcpy(dst, &mb_sim_mem[address - MB_SIM_MEM_BASE], (size_t)length);
  return MB_GUM_OK;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_memory_write(uint64_t address, uint8_t *src, int32_t length) {
  if (!mb_buf_ok(src, length) || length < 0) {
    return MB_ERR_BUFFER;
  }
  if (mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (address < MB_SIM_MEM_BASE ||
      address + (uint64_t)length > MB_SIM_MEM_BASE + MB_SIM_MEM_SIZE) {
    return MB_ERR_INVALID_ADDRESS;
  }
  memcpy(&mb_sim_mem[address - MB_SIM_MEM_BASE], src, (size_t)length);
  return MB_GUM_OK;
}

MOONBIT_FFI_EXPORT
void *mb_gum_enumerate_modules(void) {
  if (mb_state != MB_ST_ACTIVE) {
    return NULL;
  }
  mb_modules_live = 1;
  return (void *)&mb_modules_token;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_module_at(void *modules, int32_t index, uint8_t *dst, int32_t capacity) {
  const struct mb_module *m;
  uint32_t name_len, path_len, need;
  uint8_t *p;
  if (!mb_buf_ok(dst, capacity)) {
    return MB_ERR_BUFFER;
  }
  if (mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (modules == NULL || !mb_modules_live) {
    return MB_ERR_GENERIC;
  }
  if (index < 0 || index >= MB_MODULE_COUNT) {
    return 0; /* 枚举结束 */
  }
  m = &mb_modules[index];
  name_len = (uint32_t)strlen(m->name);
  path_len = (uint32_t)strlen(m->path);
  need = 2 + name_len + 2 + path_len + 8 + 8;
  if (need > (uint32_t)capacity) {
    return MB_ERR_BUFFER;
  }
  p = dst;
  mb_put_u16(p, (uint16_t)name_len);
  p += 2;
  memcpy(p, m->name, name_len);
  p += name_len;
  mb_put_u16(p, (uint16_t)path_len);
  p += 2;
  memcpy(p, m->path, path_len);
  p += path_len;
  mb_put_u64(p, m->base);
  p += 8;
  mb_put_u64(p, m->size);
  return 1;
}

MOONBIT_FFI_EXPORT
void mb_gum_modules_free(void *modules) {
  if (modules == (void *)&mb_modules_token) {
    mb_modules_live = 0;
  }
}

/* ===================== 私有 shim（API.md 缺口补齐，不导出） ===================== */

/* Gum::regions 的数据源：API.md 的 12 个公开 shim 未覆盖内存区间枚举。 */
MOONBIT_FFI_EXPORT
int32_t mb_gum_region_at(int32_t index, uint8_t *dst, int32_t capacity) {
  const struct mb_region *r;
  uint32_t path_len, need;
  uint8_t *p;
  if (!mb_buf_ok(dst, capacity)) {
    return MB_ERR_BUFFER;
  }
  if (mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (index < 0 || index >= MB_REGION_COUNT) {
    return 0;
  }
  r = &mb_regions[index];
  path_len = (uint32_t)strlen(r->path);
  need = 8 + 8 + 1 + 2 + path_len;
  if (need > (uint32_t)capacity) {
    return MB_ERR_BUFFER;
  }
  p = dst;
  mb_put_u64(p, r->base);
  p += 8;
  mb_put_u64(p, r->end);
  p += 8;
  *p++ = r->prot;
  mb_put_u16(p, (uint16_t)path_len);
  p += 2;
  memcpy(p, r->path, path_len);
  return 1;
}

/* 回调上下文回传通道：`mb_gum_set_callbacks` 的闭包签名是 `() -> Unit`（API.md 固定），
 * 每次触发的 InvocationContext 由此 shim 序列化给 MoonBit 侧解析。 */
MOONBIT_FFI_EXPORT
int32_t mb_gum_current_context(uint8_t *dst, int32_t capacity) {
  uint32_t need;
  uint8_t *p;
  int32_t i;
  if (!mb_buf_ok(dst, capacity)) {
    return MB_ERR_BUFFER;
  }
  if (mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (!mb_ctx.active) {
    return 0;
  }
  need = (uint32_t)(MB_CTX_HEADER_SIZE + MB_CTX_MAX_ARGS * 8 + 1 + 8);
  if (need > (uint32_t)capacity) {
    return MB_ERR_BUFFER;
  }
  p = dst;
  *p++ = mb_ctx.point;
  mb_put_u32(p, (uint32_t)mb_ctx.depth);
  p += 4;
  mb_put_u64(p, mb_ctx.thread_id);
  p += 8;
  mb_put_u64(p, mb_ctx.fn_addr);
  p += 8;
  mb_put_u32(p, (uint32_t)mb_ctx.argc);
  p += 4;
  for (i = 0; i < MB_CTX_MAX_ARGS; i++) {
    mb_put_u64(p, mb_ctx.args[i]);
    p += 8;
  }
  *p++ = mb_ctx.has_ret;
  mb_put_u64(p, mb_ctx.ret);
  return (int32_t)need;
}

/* ===================== 测试缝（仅供 _wbtest 触发/断言） ===================== */

/* 模拟「被钩函数被调用」：填充当前上下文后按 (cb, closure) 对触发回调。 */
MOONBIT_FFI_EXPORT
int32_t mb_gum_test_fire(
  uint64_t hook_id,
  int32_t point,
  uint64_t arg0,
  uint64_t arg1,
  uint64_t ret
) {
  struct mb_hook *h;
  struct mb_ctx saved;
  if (mb_state != MB_ST_ACTIVE) {
    return MB_ERR_NOT_INITIALIZED;
  }
  if (point != MB_POINT_ENTER && point != MB_POINT_LEAVE) {
    return MB_ERR_BUFFER;
  }
  h = mb_find_hook(hook_id);
  if (h == NULL || h->cb == NULL || h->closure == NULL) {
    return MB_ERR_GENERIC;
  }
  saved = mb_ctx;
  memset(&mb_ctx, 0, sizeof(mb_ctx));
  mb_ctx.active = 1;
  mb_ctx.point = (uint8_t)point;
  mb_ctx.depth = mb_depth;
  mb_ctx.thread_id = mb_thread_id();
  mb_ctx.fn_addr = h->fn_addr;
  mb_ctx.argc = MB_CTX_MAX_ARGS;
  mb_ctx.args[0] = arg0;
  mb_ctx.args[1] = arg1;
  mb_ctx.has_ret = (point == MB_POINT_LEAVE) ? 1 : 0;
  mb_ctx.ret = ret;
  mb_depth++;
  /* 触发时不 incref：实测本工具链（moon 0.1.20261104）MoonBit 闭包参数为
   * borrow 约定，cb(closure) 不消费引用（rc 不变）；`#owned` 的唯一释放点在
   * 注销时的 moonbit_decref。该约定由 _wbtest 的 rc 断言守护。 */
  h->cb(h->closure);
  mb_depth--;
  mb_ctx = saved;
  return MB_GUM_OK;
}

/* 许可 / ptrace 门禁开关（模拟 G1/G2 门禁未通过时 init 的可观察信号）。 */
MOONBIT_FFI_EXPORT
int32_t mb_gum_test_set_gate(int32_t gate, int32_t enabled) {
  if (gate == MB_GATE_LICENSE) {
    mb_gate_license = enabled ? 1 : 0;
    return MB_GUM_OK;
  }
  if (gate == MB_GATE_PTRACE) {
    mb_gate_ptrace = enabled ? 1 : 0;
    return MB_GUM_OK;
  }
  return MB_ERR_BUFFER;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_test_live_hooks(void) {
  int32_t i, n = 0;
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    if (mb_hooks[i].active) {
      n++;
    }
  }
  return n;
}

MOONBIT_FFI_EXPORT
int32_t mb_gum_test_live_closures(void) {
  int32_t i, n = 0;
  for (i = 0; i < MB_MAX_HOOKS; i++) {
    if (mb_hooks[i].active && mb_hooks[i].closure != NULL) {
      n++;
    }
  }
  return n;
}

/* 观测闭包引用计数，验证「触发/注销成对持有与释放」不增不泄。 */
MOONBIT_FFI_EXPORT
int32_t mb_gum_test_closure_rc(uint64_t hook_id) {
  struct mb_hook *h = mb_find_hook(hook_id);
  if (h == NULL || h->closure == NULL) {
    return -1;
  }
  return Moonbit_rc_count(Moonbit_object_header(h->closure));
}
