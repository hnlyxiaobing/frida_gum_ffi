# hnlyxiaobing/frida_gum_ffi

> R2 冻结前 P0 整改（2026-11-07）。本包有 4 个 `#external` 句柄、14 个 `mb_gum_*` `extern "C"` shim 声明（**全部包私有 · 私有实现 ABI，非公共 API**；其中 12 个 R2 由 `pub` 收敛，不再出现在 `moon info` 快照）、回调/所有权规则、值类型与 8 个**已实现**的 `Gum::*` API（桌面 stub）。`moon check --deny-warn`：0 error 0 warn；`moon test`：**4/4 通过**（1 黑盒 + 3 白盒）。

frida-gum 进程内插桩的 C-FFI 封装；不含 frida-core、不做 Java 方法 hook。`preferred_target = "native"`（ADR-0007）。

> **实现门禁（ADR-0006）**：许可审查 G1 + 更小替代评估 G2 通过前**不链接真实 frida-gum devkit**（本轮门禁保持开放，表述不变；仅链接自带 `stub/mb_gum_stub.c`，不下载 devkit）。
> `Gum::close` / `Gum::detach`：**不会二次释放，重复调用返回明确错误**（重复 close → `NotInitialized`；重复 detach → `DetachFailed`，已关闭 → `NotInitialized`）。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；总体架构与决策见 `../docs/architecture.md`、`../docs/adr/`。

**当前状态：桌面 stub 实现 + 4 测试全过，五项门禁（clean / check --deny-warn / build / test / fmt --check）全绿；真实实现等 G1/G2 门禁放行。**
