# LICENSE-AUDIT-G1.md — frida-gum `subprojects/*.wrap` 15 组件许可逐项清单（G1 前置，Q2 事实层）

> 日期：**2026-11-09**（R4 轮）｜ 审计方式：**网络只读**——主控 2026-11-09 授权口径：`web_fetch` 只读抓取 frida-gum 仓库 `subprojects/*.wrap` **清单文本**与各上游组件 **LICENSE/COPYING 文本**（两类文本，仅对话内处理 + 摘录进本文件）；**未下载/落盘/链接任何 devkit、源码包、压缩包、二进制**，未建任何 wrap 原文副本，未 git clone `[已复验]`。
> 证据等级：网络文本一律 **`[仅据文档]`**（每条附 URL + 摘录 + 访问日期 2026-11-09）；法律解读一律 **`[推断]`**（非法律意见）；未核实 **`[仍需实测]`**，不硬凑。
> 范围：本文只固定「wrap 清单 + 各组件许可原文事实 + 兼容性标注 + 法务审查简报」；**G1 门禁状态不变（未通过）**——法务/用户终裁未闭环，结论性合规判定一律不得写成「已合规」。
> 关联：`LICENSE-AUDIT.md`（frida-gum 主文与 wxWindows 例外条款）、`DECISIONS.md`「门禁状态」、`G2-ALTERNATIVES-EVAL.md`（更小替代评估）。

---

## 0. 红线执行声明

| 项 | 内容 | 等级 |
|---|---|---|
| 抓取对象 | ① `frida/frida-gum` `subprojects/*.wrap` 清单文本 15 份；② 各组件 LICENSE/COPYING 文本 15 份；③ G2 评估对象 LICENSE/README（见 G2 文档） | `[已复验]` |
| 禁止对象 | frida-gum devkit（`frida-gum-devkit-*.tar.xz` 等）、源码包/tarball/zip、`.a/.so/.dll` 二进制——**全程未获取、未落盘、未链接**（ADR-0006 / D8-4 红线） | `[已复验]` |
| 落盘物 | 仅本文件（摘录为文本引用）；wrap/LICENSE 原文未建副本 | `[已复验]` |
| Q12（devkit 清单/体积核对） | **未做**（须 G1 闭环后方可获取 devkit 实物） | `[仍需实测]` |

## 1. wrap 清单枚举（15/15）

来源：`https://api.github.com/repos/frida/frida-gum/contents/subprojects`（HTTP 200，2026-11-09，目录清单元数据）→ 逐份 `https://raw.githubusercontent.com/frida/frida-gum/main/subprojects/<name>.wrap`（清单文本，均 `[wrap-git]` + `[provide]` 两节）`[仅据文档]`。

| # | wrap 文件 | 上游（wrap-git） | 钉定 revision | provide（依赖名） |
|---|---|---|---|---|
| 1 | capstone.wrap | `https://github.com/frida-forks/capstone.git` | `f919a03a5417e1c7ea3af7035225073437030ef2` | capstone |
| 2 | glib.wrap | `https://github.com/frida-forks/glib.git` | `f11db6352345ad21deb5f5783bb988bfca2a3d85` | glib-2.0, gobject-2.0, gthread-2.0, gmodule-2.0, gio-2.0, gio-unix-2.0, gio-win32-2.0 |
| 3 | glib-networking.wrap | `https://github.com/frida-forks/glib-networking.git` | `c8d811a906659f59eabc9f4dc3ad2ba22772bf0f` | gioapple, giognutls, gioopenssl |
| 4 | json-glib.wrap | `https://github.com/frida-forks/json-glib.git` | `0242c39f1f60f844c9df41e83434251b06609e82` | json-glib-1.0 |
| 5 | libdwarf.wrap | `https://github.com/frida-forks/libdwarf.git` | `9ac8cc22cab54d72cb355a44e85db716a7006f47` | libdwarf |
| 6 | libffi.wrap | `https://github.com/frida-forks/libffi.git` | `5cca756802a5d27988e7f9973e1299f684cfeff7` | libffi |
| 7 | libsoup.wrap | `https://github.com/frida-forks/libsoup.git` | `2537f36926436ef7ac7e2430c25755216ed54ca5` | libsoup-3.0 |
| 8 | libunwind.wrap | `https://github.com/frida-forks/libunwind.git` | `733d7d1c73f3512d2a50add2337157fa385a7e6e` | libunwind |
| 9 | minizip-ng.wrap | `https://github.com/frida-forks/minizip-ng.git` | `6475b3c6f810f00d62bb5ed7ef90d4a985447909` | minizip |
| 10 | openssl.wrap | `https://github.com/frida-forks/openssl.git` | `a94348d1cd4fb009e7c590fe4e193c2ea89f5ab8` | openssl, libcrypto, libssl |
| 11 | quickjs.wrap | `https://github.com/frida-forks/quickjs.git` | `6f3b5b4827d4c81af85627d66fce2ec3c8ab70d0` | quickjs |
| 12 | sqlite.wrap | `https://github.com/frida-forks/sqlite.git` | `2cfd2ffbef3fc25a11542f876a0ff8ecb2d50914` | sqlite3 |
| 13 | tinycc.wrap | `https://github.com/frida-forks/tinycc.git` | `c0b84021e3e5c8359a469b1af2bf4abd83a7a26a` | libtcc |
| 14 | v8.wrap | `https://github.com/frida-forks/v8.git` | `f6d7f6610f2f21e2817ed180b72ea750a3f63ce8` | v8-15.7 |
| 15 | xz.wrap | `https://github.com/frida-forks/xz.git` | `68289232393af1ff1756bcf05164cedfd792df59` | liblzma |

**与 ADR-0006 已具名清单的交叉核对**：ADR-0006/COMPATIBILITY 具名 6 个（capstone/glib/quickjs/openssl/v8/xz）全部在列 ✓；其余 9 个（glib-networking / json-glib / libdwarf / libffi / libsoup / libunwind / minizip-ng / sqlite / tinycc）此前仅有「…」占位、名称未登记，本轮**首次固化** `[仅据文档]`。数量恰为 **15**，与 ADR-0006「15 个上游组件」一致。

> 注：wrap 清单是 frida-gum **仓库构建依赖全集**；`libfrida-gum.a` devkit 实际编入的子集（如 GumJS 相关 v8/quickjs 是否编入）**须 G1 闭环后按 devkit 实物核对（Q12）** `[仍需实测]`。

## 2. 逐组件许可清单

> 「闭源静态链接分发兼容性」为 **`[推断]`**（法律解读，非法律意见，须法务终裁）；摘录均为 2026-11-09 只读抓取的原文片段。

| # | 组件 | 许可证（SPDX/描述） | 证据 URL（钉定 revision）+ 摘录 | 闭源静态链接分发兼容性 `[推断]` | 分发义务要点 |
|---|---|---|---|---|---|
| 1 | capstone | **BSD-3-Clause** | [capstone/LICENSE.TXT](https://raw.githubusercontent.com/frida-forks/capstone/f919a03a5417e1c7ea3af7035225073437030ef2/LICENSE.TXT)："Redistribution and use in source and binary forms… Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer…" | **兼容**（宽松许可） | 二进制分发附版权+免责声明 |
| 2 | glib | **LGPL-2.1-or-later** | [glib/COPYING](https://raw.githubusercontent.com/frida-forks/glib/f11db6352345ad21deb5f5783bb988bfca2a3d85/COPYING)（内容为 SPDX 指针 `LICENSES/LGPL-2.1-or-later.txt`）+ [LGPL-2.1-or-later.txt](https://raw.githubusercontent.com/frida-forks/glib/f11db6352345ad21deb5f5783bb988bfca2a3d85/LICENSES/LGPL-2.1-or-later.txt)："GNU LESSER GENERAL PUBLIC LICENSE Version 2.1… 6. As an exception to the Sections above, you may also combine or link a 'work that uses the Library' with the Library… distribute that work under terms of your choice, provided that the terms permit modification… and reverse engineering for debugging…" | **有条件兼容**：LGPL §6 允许链接进非自由程序，但**静态链接**须履行 §6 三选一（随附完整机器可读源码+可重链接对象 / 共享库机制 / 三年书面要约）+ 显著声明 + 许可副本 | **本清单最重义务项**；见 §3 |
| 3 | glib-networking | **LGPL-2.1**（仓库文本为 LGPL-2.1 全文；上游声明多为 or-later） | [glib-networking/COPYING](https://raw.githubusercontent.com/frida-forks/glib-networking/c8d811a906659f59eabc9f4dc3ad2ba22772bf0f/COPYING)："GNU LESSER GENERAL PUBLIC LICENSE Version 2.1, February 1999…"（全文） | **有条件兼容**（同 glib，LGPL §6） | 同 glib；版本「是否 or-later」以源码头声明为准 `[仍需实测]` |
| 4 | json-glib | **LGPL-2.1-or-later** | [json-glib/COPYING](https://raw.githubusercontent.com/frida-forks/json-glib/0242c39f1f60f844c9df41e83434251b06609e82/COPYING)：内容为 SPDX 指针 `LICENSES/LGPL-2.1-or-later.txt`（全文同 #2） | **有条件兼容**（同 glib，LGPL §6） | 同 glib |
| 5 | libdwarf | **混合**：libdwarf/ = **LGPL-2.1**（+ 少量 2-clause BSD）；dwarfdump/ = **GPL-2**；dwarfgen/ = 2-clause BSD；部分文件 public domain | [libdwarf/COPYING](https://raw.githubusercontent.com/frida-forks/libdwarf/9ac8cc22cab54d72cb355a44e85db716a7006f47/COPYING)："The source code in the libdwarf directory is LGPL version 2.1… A few of files use the two-clause BSD copyright ('FreeBSD License'). The source code in the dwarfdump directory is generally GPL version 2…" | **有条件兼容（高风险项）**：libdwarf 库本体 LGPL §6；**dwarfdump 为 GPL-2——若编入产物则纯 copyleft 传染，wxWindows 例外第 3 条不覆盖** `[推断]` | 需确认 devkit 只链 libdwarf 库、不含 dwarfdump `[仍需实测]`（Q12） |
| 6 | libffi | **MIT** | [libffi/LICENSE](https://raw.githubusercontent.com/frida-forks/libffi/5cca756802a5d27988e7f9973e1299f684cfeff7/LICENSE)："Permission is hereby granted, free of charge… The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software." | **兼容** | 附版权+许可声明 |
| 7 | libsoup | **GNU Library GPL v2**（观察到的 COPYING 即 Library GPL 2 全文；与 frida-gum 主文同族） | [libsoup/COPYING](https://raw.githubusercontent.com/frida-forks/libsoup/2537f36926436ef7ac7e2430c25755216ed54ca5/COPYING)："GNU LIBRARY GENERAL PUBLIC LICENSE Version 2, June 1991…"（全文） | **有条件兼容**（弱 copyleft §6 义务）；注意与上游常见「LGPL-2.1-or-later」表述的差异，以钉定树文本为准并登记差异 | 显著声明 + 许可副本 + §6 三选一 |
| 8 | libunwind | **MIT** | [libunwind/LICENSE](https://raw.githubusercontent.com/frida-forks/libunwind/733d7d1c73f3512d2a50add2337157fa385a7e6e/LICENSE)："Permission is hereby granted, free of charge… SOFTWARE IS PROVIDED 'AS IS'…" | **兼容** | 附版权+许可声明 |
| 9 | minizip-ng | **zlib License** | [minizip-ng/LICENSE](https://raw.githubusercontent.com/frida-forks/minizip-ng/6475b3c6f810f00d62bb5ed7ef90d4a985447909/LICENSE)："Condition of use and distribution are the same as zlib… 2. Altered source versions must be plainly marked as such… 3. This notice may not be removed or altered from any source distribution." | **兼容** | 保留许可声明；改动版须标示 |
| 10 | openssl | **Apache-2.0** | [openssl/LICENSE.txt](https://raw.githubusercontent.com/frida-forks/openssl/a94348d1cd4fb009e7c590fe4e193c2ea89f5ab8/LICENSE.txt)："Apache License Version 2.0, January 2004… You must give any other recipients of the Work or Derivative Works a copy of this License…" | **兼容**（含专利授予；注意 Apache 与 GPLv2 兼容性问题仅在混链 GPL 时相关） | 许可副本 + 归属声明 + NOTICE（若有） |
| 11 | quickjs | **MIT** | [quickjs/LICENSE](https://raw.githubusercontent.com/frida-forks/quickjs/6f3b5b4827d4c81af85627d66fce2ec3c8ab70d0/LICENSE)："QuickJS Javascript Engine Copyright (c) 2017-2021 Fabrice Bellard… Permission is hereby granted, free of charge…" | **兼容** | 附版权+许可声明 |
| 12 | sqlite | **Public Domain**（无 LICENSE 文件；官方版权声明页） | [sqlite 仓库 LICENSE](https://raw.githubusercontent.com/frida-forks/sqlite/2cfd2ffbef3fc25a11542f876a0ff8ecb2d50914/LICENSE) **HTTP 404（不存在）**；[sqlite.org/copyright.html](https://www.sqlite.org/copyright.html)："SQLite Is Public Domain… All of the code and documentation in SQLite has been dedicated to the public domain by the authors… Anyone is free to copy, modify, publish, use, compile, sell, or distribute the original SQLite code… for any purpose, commercial or non-commercial" | **兼容**（无许可义务）；辖区不承认公有领域时可购 Warranty of Title（官方页明示） | 无强制义务（建议致谢） |
| 13 | tinycc | **LGPL-2.1** | [tinycc/COPYING](https://raw.githubusercontent.com/frida-forks/tinycc/c0b84021e3e5c8359a469b1af2bf4abd83a7a26a/COPYING)："GNU LESSER GENERAL PUBLIC LICENSE Version 2.1, February 1999…"（全文） | **有条件兼容**（LGPL §6） | 同 glib；注意 tcc 作为运行时 JIT/编译器组件的链接形态 `[仍需实测]` |
| 14 | v8 | **BSD-3-Clause**（+ 子组件各自许可） | [v8/LICENSE](https://raw.githubusercontent.com/frida-forks/v8/f6d7f6610f2f21e2817ed180b72ea750a3f63ce8/LICENSE)："This license applies to all parts of V8 that are not externally maintained libraries… Redistribution and use in source and binary forms… Neither the name of Google Inc. nor the names of its contributors may be used to endorse or promote…"（列明 PCRE 测试/BSD、Strongtalk/BSD、valgrind/BSD、wasm-api/Apache 等子组件） | **兼容** | 版权+免责声明；子组件声明随附（多为测试/头文件） |
| 15 | xz | **liblzma = 0BSD**（工具/脚本另含 LGPLv2.1+/GPLv2+，不入 liblzma） | [xz/COPYING](https://raw.githubusercontent.com/frida-forks/xz/68289232393af1ff1756bcf05164cedfd792df59/COPYING)："XZ Utils Licensing… liblzma is under the BSD Zero Clause License (0BSD)… The scripts to grep, diff, and view compressed files… are under GNU GPLv2+… These scripts… aren't… [in liblzma]" | **兼容**（wrap provide 仅 `liblzma` = 0BSD）；若误链命令行工具/脚本代码则引入 GPL `[推断]` | 0BSD 无强制义务（建议致谢） |

## 3. 汇总与关键风险（法律解读均 `[推断]`，须法务终裁）

**许可家族分布**：宽松（BSD/MIT/zlib/Apache-2.0/0BSD/public domain）**10 个**（capstone/libffi/libunwind/minizip-ng/openssl/quickjs/sqlite/v8/xz + libdwarf 的 BSD 部分）；**弱 copyleft（LGPL-2.1 系 / Library GPL v2）5 个**（glib/glib-networking/json-glib/tinycc/libsoup）；**强 copyleft 隐患 1 处**（libdwarf 树内 dwarfdump/ = GPL-2）。

1. **LGPL 组件静态链接是本清单最重义务**（glib/json-glib/glib-networking/tinycc/libsoup）：LGPL §6 允许「work that uses the Library」以自有条款分发，但**静态链接**必须满足 §6 条件之一（随附完整机器可读库源码与可重链接对象 / 使用共享库机制 / 三年书面要约），并附显著声明与许可副本。这与 wxWindows `EXCEPTION NOTICE` 第 2 条（frida-gum 本体的二进制例外）**并行适用、互不替代**：例外第 3 条明示「拷入本库的 GPL / Library GPL 代码不受例外覆盖」。
2. **libdwarf 的 dwarfdump/（GPL-2）**：若 devkit 编入 dwarfdump 代码，该部分为纯 copyleft，闭源静态分发不可行（除非整链开源）`[推断]`；**须在 Q12 devkit 实物核对时确认只链 libdwarf 库** `[仍需实测]`。
3. **devkit 编入子集未知**：15 个 wrap 是仓库构建依赖全集，`libfrida-gum.a` 实际编入哪些（尤其 v8/quickjs/tinycc 等 GumJS/运行时组件）**未核**（禁获取 devkit 实物）`[仍需实测]`（Q12）。
4. **libsoup 许可表述差异**：钉定树 COPYING 为 Library GPL v2 全文，上游社区常见表述为 LGPL-2.1-or-later；本清单以**钉定 revision 文本**为准 `[仅据文档]`，差异移交法务。
5. **frida-gum 主文的 BSD-3 附随义务**（Mozilla/Closure/regenerator 三段声明，见 `LICENSE-AUDIT.md` §3 L6）与上表各组件义务**叠加**，分发物 NOTICE 清单须覆盖两者。

## 4. 法务审查简报（送审问题清单；**法务/用户终裁未闭环**）

> 以下为提交法务的**问题清单**，不是结论。任何「可/不可」判定在法务出具意见前均属 `[推断]`。

1. **wxWindows `EXCEPTION NOTICE` 第 2 条**（"distribute under your own terms, binary object code versions of works based on the Library"）对「`libfrida-gum.a` 静态链接进闭源 App」这一分发形态是否成立？（版本/司法辖区依赖）
2. **第 3 条例外失效范围**：devkit 构建链混入 LGPL-2.1 系组件（glib 等 5 个）时，例外不覆盖的「code that you add in this way」如何划界？LGPL §6 义务（源码/重链接/要约）在本分发形态下如何履行最简？
3. **libdwarf 树 dwarfdump/（GPL-2）**：若确认未编入 `libfrida-gum.a`，可否仅按 libdwarf/（LGPL-2.1）处理？需什么证据（devkit 符号清单 / 构建脚本）？
4. **NOTICE 集合**：最终分发物需随附的声明清单 = frida-gum BSD-3 三段 + capstone/v8 BSD-3 + libffi/quickjs/libunwind MIT + minizip zlib + Apache-2.0（openssl）+ LGPL 许可副本与显著声明（5 个弱 copyleft 组件）——该清单是否完备？
5. **libsoup Library GPL v2 文本**与上游 LGPL-2.1-or-later 表述不一致，以哪份为准？对 §6 义务范围有无影响？
6. **Q3 原问题**（静态链接 wxWindows 3.1 进闭源 App 的合规结论）在 1–5 之后的最终结论。

## 5. 状态

| 项 | 状态 | 等级 |
|---|---|---|
| Q2（15 组件逐项许可事实层） | **清单已逐项固化 15/15**（本文 §1–§2） | `[仅据文档]`（URL+摘录+日期齐备） |
| Q3 / G1 合规结论 | **未闭环**——法务/用户终裁未出；一切兼容性标注仅为 `[推断]` | `[仍需实测]` |
| G1 门禁 | **未通过**（事实层输入已备齐，待法务结论）；G2 真实链接继续冻结 | `[已复验]`（`DECISIONS.md`「门禁状态」） |
| Q12（devkit 实物清单/体积） | **未做**（红线：G1 闭环前禁获取 devkit） | `[仍需实测]` |
