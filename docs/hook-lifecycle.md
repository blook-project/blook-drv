# Hook 生命周期与卸载回归

## 2026-09-28 的故障证据

21:07:53 的离线转储：0x3B / 0xC000001D，异常指令位于 blook_hook_leave_site 的 VMCALL。CPU 4 已进入 hv::stop 的 vCPU 内存释放，CPU 6 仍从已计数的 hook 返回；inflight=1、closing=0。构建脚本日志同一时刻执行了 stop。问题是 VMX 先于 hook 的最后一次返回被关闭，而不是配置语法错误。

转储、匹配 SYS/PDB 和完整调试器日志保留在本机忽略目录 minidumps 与 .cache 中，不随源码提交。

## 实现的不变量

1. 15 个已知签名的内置入口：在 root 中识别确切 CPL/RIP 并增加计数后，才跳入静态 MASM shim。shim 保持参数、栈对齐和真实 CALL/RET，调用 C++ handler。
2. handler 返回后，shim 恢复原始 RSP，在唯一 leave VMCALL 处退出。root 设置外部内核 RET 落点并释放引用；离开后不再执行驱动的 guest 代码。外部 RET 从可信、不可分页内核函数的指令边界校验得到，不在任意字节中搜索。
3. 开始关闭后禁止新的管理安装；已有 gate 仍允许进入和返回，直到**全部 CPU**完成 quiesce。每 CPU 清除暂存单步状态、撤掉 hook/watch、失效 EPT 并确认；quiescing 锁存后不能重新安装。
4. 等待全局引用归零时，保持 VMX、原函数 trampoline、gate 元数据和 policy 存活。不能持有 manager、hook/watch store 或广播锁等待。
5. 引用归零后逐 CPU stop；stop 确认同时保证各 CPU 的 root 返回尾部已结束。root 拒绝 quiesce 前或引用非零时的 stop。只有全部确认后才释放 vCPU 内存。
6. 最终卸载再 reset gate、销毁 hook/watch、清理 policy。电源暂停不 reset gate，也不释放 trampoline；恢复时使用新 EPT，只有全部恢复成功才解除 suspended。
7. 部分 CPU arm 失败也可能已有 handler 进入：保留其原函数/元数据至全局排空，但有效状态为失败。ID 存在不能当作成功武装；不在在线 feature-off 路径释放入口。

## 停止耗时与失败策略

关闭功能只更换不可变逻辑快照，已拿到旧快照的调用可以完成。全局卸载则必须等待原函数真正返回。内核卸载回调无法以失败状态拒绝卸载，因此这里**不设超时后强制释放**；如果原调用永久阻塞，或异常展开跳过 leave，卸载会保留资源并等待，SCM 可能报超时。不能把 SCM 超时当作可卸载/可重用内存的凭据。live 验证应在可恢复的隔离环境进行。

恢复失败保持 suspended，并走同一排空流程关闭 VMX；原先请求恢复的 hook/watch 保留重试意图，失败不得被下一次恢复跳过后误报成功。mandatory VM maintenance 安装不完整则拒绝启动。

## 本轮测试与尚未验证事项

- tests/hook_shutdown.cc：实际关闭路径调用的共享排空顺序，覆盖多个存量调用、延迟返回、零调用和 stop 确认后才释放。
- tests/ept/regression.cc：实际 EPT 引擎的同页多 hook、watch、待处理单步的 quiesce；关闭后拒绝重装，fresh EPT 允许恢复。
- tests/page_query.cc、dispatch.cc、configuration.cc：页所有权与计数、逻辑链、整份配置发布。
- tests/build_policy.ps1：普通构建不隐式 stop/start，隔离输出与显式生命周期参数的全部 32 组组合。

这些是编译和 host 验证，不是硬件证明。本轮没有在当前机器加载新驱动，也没有运行 live suites。隔离验证仍需覆盖：多个 CPU 同时停留在原函数、卸载与线程迁移、异常展开、部分安装失败、睡眠恢复失败与重试，以及不同 Windows 构建上的入口指令/CET 行为。SDK 的任意 raw redirect 不拥有这套内核 shim 的回收保证，调用方仍负责它自己的 handler/trampoline 存活。
