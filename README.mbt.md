# hnlyxiaobing/frida_gum_ffi

> Round-1 · 架构与声明可评审（2026-11-06）。本包只有 4 个 `#external` 句柄、14 个 `extern "C"` shim 声明、回调/所有权规则、值类型与 `declare` 包装 API，**无 hook 逻辑、无 shim 实现**。`moon check`：0 error，8 × `[0068]`（预期）。

frida-gum 进程内插桩的 C-FFI 封装；不含 frida-core、不做 Java 方法 hook。`preferred_target = "native"`（ADR-0007）。

> **实现门禁（ADR-0006）**：许可审查 G1 + 更小替代评估 G2 通过前不进入实现轮。`moon build` / `moon test` 本轮**预期链接期失败**。

完整文档见同目录 `README.md`、`DESIGN.md`、`API.md`；总体架构与决策见 `../docs/architecture.md`、`../docs/adr/`。

**当前状态：等待评审，不进入实现。**
