# 细粒度功能与生命周期

`src/policy/features.hpp` 是稳定名称、位编号与中文用途的唯一描述符源；位编号只追加，不重排、不复用。所有功能默认关闭，VM maintenance 不属于可选 mask。

## API 与失败语义

主入口 `blook::features::set_desired(mask)` 全量替换可选功能，`set_one(id, enabled)` 原子修改单项，`update(set, clear)` 原子修改预设组；写入要求 PASSIVE_LEVEL。`query()` 返回一致快照 `{desired, effective, unsupported, status}`。不得用 query + set_desired 实现单项更新，否则会丢失并发修改。

安装所需入口后才发布 features/roles 的不可变引用计数快照；每次调用持有一代快照，不跨原函数调用持有发布锁。任一请求位不能实现（未知位、解析失败、prepare/arm 失败、窗口依赖缺失）时返回 STATUS_NOT_SUPPORTED，desired/effective 保持原值，unsupported 标记本次无法满足的位；可查询最近错误。无效枚举返回 STATUS_INVALID_PARAMETER。底层不同失败原因目前统一为不支持，不提供虚假的成功。失败过程中已经安装的服务可能留下透明旁路入口，既不启用失败请求，也不在线卸载它们。下一次成功更新清除错误。

## 稳定名称与原有作用范围

| 位 | 名称 | 用途与作用范围 |
| --- | --- | --- |
| 0 | scrub.first_contact | 目标进程接触已安装的 QuerySystem/QueryProcess 入口时首次清理 PEB/heap/debug flags；单独启用时安装 QuerySystem 作为触发入口。 |
| 1 | scrub.write_memory | 用户态工具写入非工具进程时临时中和 BeingDebugged 字节，保留原先不限于 target 的被写进程范围。 |
| 2 | nt.query_system.process | 对非工具调用者隐藏系统进程列表中的工具进程。 |
| 3 | nt.query_system.module | 对非工具调用者隐藏系统模块列表中的匹配模块。 |
| 4 | nt.query_system.kernel_debugger | 对非工具调用者返回无内核调试器状态。 |
| 5 | nt.query_process | 对用户态目标调用者隐藏进程调试信息。 |
| 6 | nt.set_thread | 阻止目标调用者设置 ThreadHideFromDebugger。 |
| 7 | nt.query_thread | 对目标调用者隐藏 ThreadHideFromDebugger。 |
| 8 | nt.get_context | 对目标调用者隐藏上下文硬件断点。 |
| 9 | nt.open_process | 拒绝目标调用者打开工具进程。 |
| 10 | nt.open_thread | 拒绝目标调用者打开工具线程。 |
| 11 | scrub.debug_attach | 成功附加调试器后清理被附加进程；保留原来的无 role 限制行为。 |
| 12 | window.query | 对目标调用者隐藏工具窗口所属 PID。 |
| 13 | window.find | 对目标调用者隐藏查找得到的工具窗口。 |
| 14 | window.list | 对目标调用者从窗口枚举移除工具窗口。 |
| 15 | window.foreground | 对目标调用者用上次可见窗口替代工具前台窗口。 |
| 16 | window.point | 对目标调用者隐藏坐标命中的工具窗口。 |

**本轮不收紧也不扩大 role 范围。** 特别是 QuerySystem 为 non-tool，而非 target-only；debug attach 无 role 限制；write scrub 排除 tool 被写进程但不要求它是 target。这些历史范围如需调整应单独评审，不与功能拆分混在一起。手动 `hide::scrub(pid, flags)` 仍是显式一次性动作，不受自动 scrub mask 限制。

## 共享入口与依赖

QuerySystem 的 process/module/kernel_debugger 是独立 typed handlers，共享一个物理入口。每次调用持有一代 policy_view 并在栈上构造 `dispatch_chain` 快照，handler 调用 next，最终只调用一次真实服务；不存在边执行边修改共享链。NtWriteVirtualMemory 同样以本地链组合必需 maintenance 和可选 scrub，关闭 scrub 仍保持 COW rebind。NtProtectVirtualMemory 始终只承担基础维护。早返回的拒绝类 NT 功能保持历史语义，不调用原服务。

窗口功能不依赖 NT hide。其余窗口功能仅需 QueryWindow 的真实 PID 查询基础入口；安装该入口不等于启用 `window.query` 过滤位，也不强迫安装整个 NT 预设。窗口功能各自只安装所需服务和基础依赖。旧注册表 HookMask/CoreHookMask/WindowHookMask/HideRewrite/HideNoCall 不再参与功能决策，已有 probe 记录代码保留。

## 生命周期限制

`hide::activate()` 是 NT 可选功能预设；`enable_windows()` 是窗口预设；`hide::deactivate()` 清除所有可选位。这些只是兼容包装，新 API 才是管理单元。active/windows_active 表示有效功能，而 window_hook_count 表示驻留物理入口数，因此关闭后该数量可以仍非零。

停用只让 handler 透明旁路，不移除 trampoline，不宣称物理撤销，也不等待已取得旧快照的调用完成。基础 maintenance 不受可选 mask 控制。`deactivate_maintenance` / `nt::remove_core` 不在线释放。整个驱动关闭沿用全局 hv/hook teardown，调用者必须保证 in-flight handler 排空之后，才调用 `hide::reset_after_shutdown()` 清零引用供下次启动。

全局关闭已接入 [gate 排空协议](<hook-lifecycle.md>)，只有在所有 CPU 撤补丁、在途调用归零和所有 CPU stop 之后才释放 trampoline。安装失败保留已经暴露给 CPU 的原函数入口，但不能把残留 ID 当作已武装成功。窗口入口与 NT 入口都经同一组计数 shim，不再依赖 call-original window。尚未在本机重新加载该修复版本。

## 查询与管理

- `blook-loader features` 同时输出每项状态和上表对应的一句话用途。
- `blook-loader feature nt.query_system.process on` 只改变该运行态功能，不写回文件。
- 文件中的 `[features]` 是持久化期望值；执行 `reload` 后全量替换功能和角色快照。
- `blook-loader page kernel <hex-address>` 查询该内核虚拟页的物理入口和已知逻辑绑定数量。用户域只看当前 SDK 会话；新 CLI 会话不能枚举其他会话的 hook。
- 内核 `query_page_hooks` 与用户 SDK `session::query_page` 共享页统计语义。用户态自己组合的 handler 用 `dispatch_chain::size() / enabled_count() / at()` 查询，不能由驱动猜测。

解析器默认所有可选功能关闭；仓库的 blook.ini 是显式开启 NT 预设的示例/本地配置，并非解析器默认。mandatory 的 NtProtectVirtualMemory（保护变化后的 COW/休眠项维护）和 NtWriteVirtualMemory（写入后的 COW 维护）不受可选功能开关控制；无法安装时拒绝启动。
