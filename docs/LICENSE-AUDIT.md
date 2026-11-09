# LICENSE-AUDIT.md — frida / frida-gum 许可盘点（为 G1 许可审查铺路，只读网络核验）

> 日期：**2026-11-07** ｜ 盘点方式：**网络只读**（`web_fetch` / `Invoke-WebRequest` 仅读 LICENSE/COPYING 文本；**未下载任何二进制 / 源码包 / devkit，未把任何下载物落盘进工作区**；本文件为唯一产出）。
> 范围声明：**不触碰 G1/G2 许可门禁逻辑**（门禁仍保持开放，见 `DESIGN.md` / `API.md` / `DECISIONS.md`「门禁状态」）；本文只是把「许可证原文事实」固定下来，为 G1（许可审查）与 G2（链接闭环）提供输入。
> 所有结论标注证据等级：`[已复验]` / `[已复验-本地等价]` / `[仅据文档]` / `[仍需实测]`。

---

## 1. 盘点对象与来源（引用 URL + 抓取指纹）

| 对象 | 来源 URL | 抓取结果 | 字节数 | SHA-256（原始字节） | 证据等级 |
|---|---|---|---|---|---|
| frida-gum 许可证正文 | `https://raw.githubusercontent.com/frida/frida-gum/main/COPYING` | HTTP 200 | 5696 | `00764FCC23F0F2AC6D2619A1F9192E55176ECAAA525E76A47AAABC5D87FB087F` | `[已复验]`（2026-11-07 两次独立只读抓取，指纹一致） |
| frida-gum `LICENSE` 文件 | `https://raw.githubusercontent.com/frida/frida-gum/main/LICENSE` | HTTP 404（**不存在**，许可文件名是 `COPYING`） | — | — | `[已复验]` |
| frida-core 许可证正文 | `https://raw.githubusercontent.com/frida/frida-core/main/COPYING` | HTTP 200 | 2416 | `5EA1544B51A28BC823B03159190D4108F9FB4F4EF912389F5137C6D295E175B2` | `[已复验]`（2026-11-07 两次只读抓取均 200；一次超时后重试成功，两次内容指纹一致） |

> SHA-256 按**响应原始字节**计算（在内存中完成，未落盘），供后续复核比对；`main` 分支内容随上游漂移，复核时请连同日期一起比对。

---

## 2. 许可证类型（结论）

**frida-gum 与 frida-core 均为：wxWindows Library Licence, Version 3.1**（SPDX: `wxWindows`）`[已复验]`。

- 正文结构：GNU Library General Public Licence（"Library GPL"，LGPL 的前身）**version 2 or later** 的再许可条款 + `EXCEPTION NOTICE` 四条（静态链接例外）。
- **修正一处早期表述**：「frida-gum 与 frida-core 的 `COPYING` **逐字相同**」**不准确** `[已复验]`：
  - 两者**主体（wxWindows 3.1 正文 + EXCEPTION NOTICE 四条）一致**；
  - 但 frida-gum 的 `COPYING`（5696 B）在主体之后**追加了第三方 BSD-3-Clause 片段声明**（Mozilla source-map、Closure Compiler Base64 VLQ、Facebook regenerator 三段版权与免责声明）；frida-core 的 `COPYING`（2416 B）**无**该附录。
  - 正确表述应为：「许可主体一致（均 wxWindows 3.1 + 静态链接例外）；frida-gum 另附第三方 BSD-3-Clause 片段声明」。本仓 `../README.md` 的同源转述已按本节更正。
- `frida 17.25.2` PyPI 分类器即 `wxWindows Library Licence, Version 3.1`（沿用早期调研记录）`[已复验-本地等价]`（此条是早期网络核验记录的转述，本次盘点未重新抓取 PyPI）。

---

## 3. 关键条款（逐条，供 G1 审查用）

| # | 条款 | 原文要点（摘录） | 对本项目的含义 |
|---|---|---|---|
| L1 | 基础许可 | "This library is free software; you can redistribute it and/or modify it under the terms of the GNU Library General Public Licence … either version 2 … or (at your option) any later version." | 库**源码**层面按 GNU Library GPL v2+（弱 copyleft）传播；修改库本身需保持开源义务 |
| L2 | **EXCEPTION NOTICE 第 2 条（核心）** | "you may use, copy, link, modify and distribute **under your own terms, binary object code versions of works based on the Library**" | **静态/动态链接 frida-gum 产出的二进制物可以按自有条款分发**，不必把宿主 App 源码开源 —— 这是「链接 frida-gum devkit 构建真实 FFI」可行性的许可基础 |
| L3 | 第 1 条 | 例外适用于 "the text contained in this release of the library"，wxWindows 3.1 或其后版本 | 例外覆盖范围 = 本库文本本身 |
| L4 | **第 3 条（例外失效）** | 若把 GPL / Library GPL 代码拷入本库，"the exception does not apply to the code that you add in this way" | devkit 构建链若混入纯 (L)GPL 组件，例外**不覆盖**该部分；这正是 15 个 `subprojects/*.wrap` 必须逐项核对的原因 |
| L5 | 第 4 条 | 对本库的自行修改，作者可选择是否保留例外 | 上游/我方修改版若删掉例外声明，链接豁免随之消失；引入修改版前须重查 |
| L6 | BSD-3-Clause 附随义务（仅 frida-gum） | 二进制再分发须 "reproduce the above copyright notice, this list of conditions and the following disclaimer" | 若分发链接 gum 的二进制，**必须随附**这三段版权声明与免责声明（LICENSE/NOTICE 文本入库或随包分发） |

---

## 4. 对「链接 frida-gum devkit 构建真实 FFI」的合规含义

**一句话结论**：wxWindows 3.1 例外第 2 条使「链接 `libfrida-gum.a` devkit、以自有条款分发二进制」在许可文本层面**可行**，但须①随附 BSD-3 片段的版权与免责声明、②例外不覆盖混入的 (L)GPL 代码——15 个 `subprojects/*.wrap` 上游组件许可逐项核对（未决事项①）与法务复核（未决事项②）**未闭环前，G1 不通过，G2 真实链接不得启动**。

展开（均 `[推断]`，法律解读非法律意见，须法务复核）：

1. **可以做**：把 `libfrida-gum.a` 静态链接进本项目工具/宿主产物，闭源分发二进制（L2）。
2. **必须做**：分发二进制时随附 frida-gum `COPYING` 中 BSD-3-Clause 片段的版权与免责声明（L6）；保留 wxWindows 许可文本本身属审慎做法。
3. **仍缺**：`subprojects/*.wrap` 打包的 15 个上游组件（capstone / glib / quickjs / openssl / v8 / xz …）逐项许可核对——若 devkit 产物含纯 (L)GPL 组件，L4 会让例外对那部分失效（未决事项①，`[仍需实测]`）。
4. **仍缺**：法务对「静态链接进闭源分发形态」的最终结论（未决事项②，`[仍需实测]`）；以及 17.25.2 devkit 实际包含组件清单（未决事项③，`[仍需实测]`——本次盘点禁止下载 devkit，无法核对）。
5. **不属本盘点**：更小替代方案（ShadowHook / bhook / xHook，MIT、免 root）评估属 G2；frida-core 的设备发现/传输/脚本运行时不在 `frida_gum_ffi` 能力范围内；Java 方法 hook 需 `frida-java-bridge`（Frida 17 起不捆绑）。

---

## 5. 与本仓文档的核对结果

| 位置 | 表述 | 核对结论 | 处置 |
|---|---|---|---|
| 早期调研记录 | "frida-gum 与 frida-core 的 `COPYING` 逐字相同" | **不准确**（主体一致、gum 多 BSD 附录）`[已复验]` | 本仓 `../README.md` §更正 1 已按 §2 更正 |
| 许可类型与风险评级 | "wxWindows 3.1（含静态链接例外）"；许可风险由早期评估的"高"修正为"中——但需逐项核对 15 个 subprojects + 法务复核" | **成立** `[已复验]` | 不变 |
| `DESIGN.md` §10 合规 | "devkit 上游许可逐项清单、静态链接分发结论" 为 G1 交付物 | **成立**，与本文 §4 一致 | 不变；本文即该项的第一份输入 |
| `../README.md` / `API.md` / `../README.mbt.md` 的 G1/G2 门禁表述 | 门禁保持开放、不链接 devkit | **成立** `[已复验]` | 不变 |

---

## 6. 未决事项（G1 闭环前必须完成）

1. **`subprojects/*.wrap` 15 个上游组件逐项许可清单** `[仍需实测]` → 产出逐项表格后并入本仓 `DECISIONS.md`「门禁状态」与本文。
2. **法务对闭源分发形态的结论**（静态链接 wxWindows 3.1 进闭源 App 的合规解读）`[仍需实测]`。
3. **17.25.2 devkit 实际组件/体积核对** `[仍需实测]` —— 须在允许获取 devkit 的阶段做。
4. ~~`../README.md`「逐字相同」转述的清理~~ —— **已完成**（本仓内闭环，见 §2）。

> 本文档只固定「许可证原文事实 + 合规含义」，**不构成法律意见**；G1 通过与否由法务结论 + 逐项许可清单决定。门禁状态的唯一口径见本仓 `DECISIONS.md`「门禁状态」。
