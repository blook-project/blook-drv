# blook-drv 系统概述

blook-drv 是面向 Windows x64 平台的 Intel VT-x 与扩展页表（Extended Page Tables, EPT）分析辅助驱动系统，包含内核驱动程序、用户态控制接口、命令行管理工具及宿主机验证测试套件。系统通过硬件辅助虚拟化技术在指定目标进程中建立影子执行视图，实现对用户态指令的无侵入拦截与内核行为监控。

## 文档索引

- [用户态 SDK](<sdk/README.md>)：C++23 头文件集成方式、只读状态查询、拦截接口与所有权生命周期。
- [架构与边界](<docs/architecture.md>)：分层架构、执行环境约束、IPC ABI v6 协议规范与 EPT 视图隔离机制。
- [Hook 卸载与蓝屏修复](<docs/hook-lifecycle.md>)：入口计数、跨 CPU 排空顺序及 live 验证边界。
- [细粒度功能](<docs/features.md>)：每个独立开关的一句话用途。
- [开发与测试指南](<docs/development.md>)：工具链依赖、构建流水线、宿主机测试分层与配置文件规格。

## 快速上手

运行宿主机模型测试与构建命令行工具需要准备 Windows x64 操作系统、支持 C++23 标准的 MSVC 编译器、Windows SDK 与 xmake。在仓库根目录的 PowerShell 终端中执行以下构建命令：

```powershell
xmake f -p windows -a x64 -m releasedbg -y
xmake build blook-tests
xmake run blook-tests
xmake build blook-loader

$loader = ".\build\windows\x64\releasedbg\blook-loader.exe"
& $loader --help
```

宿主机测试（`blook-tests`）在模拟环境中验证 EPT 引擎的页表映射与地址转换逻辑，执行过程中不访问物理虚拟化硬件，亦不调用内核驱动接口。

### 自动化构建脚本

自动化构建脚本 [Build.ps1](<scripts/Build.ps1>) 集中管理配置、编译、测试与签名流程。在未配置测试签名证书的环境中，指定 `-NoSign` 参数完成编译并执行宿主机测试：

```powershell
.\scripts\Build.ps1 -NoSign
```

脚本支持以下运行参数：

| 参数 | 执行行为 |
| --- | --- |
| `-NoSign` | 跳过内核驱动的数字签名阶段 |
| `-BuildDir build/offline` | 使用隔离构建目录，不覆盖正在运行的驱动镜像 |
| `-StopRunningDriver` | 显式允许停止已加载驱动；构建本身不再隐式停止、卸载或重新启动 |
| `-NoTests` | 跳过宿主机单元测试套件的执行 |
| `-Deploy` | 编译后向系统服务控制管理器（SCM）注册驱动服务 |
| `-Start` | 注册并启动驱动服务，激活所有逻辑处理器的虚拟化监控 |

### 服务状态查询

在驱动已安装并运行的环境中，通过命令行工具执行状态查询：

```powershell
& $loader status
```

查询操作通过只读方式打开设备符号链接 `\\.\BlookDrv`，不修改系统服务配置，亦不改变内核运行状态。输出中的 `running` 指示全局虚拟化引擎的运行状态，`enabled` 指示当前打开会话的修改授权状态。

用户态应用程序建立连接时，若仅需读取状态，可调用 `blook::client::session::open(blook::client::open_mode::read_only)` 创建只读会话，具体流程见 [用户态 SDK](<sdk/README.md#只读状态查询>)。

## 命令行接口

命令行工具 [main.cc](<src/loader/main.cc>) 提供服务生命周期控制、配置管理与动态分析接口。

| 功能类别 | 命令格式 | 说明 |
| --- | --- | --- |
| 帮助与诊断 | `blook-loader help` / `--help` | 显示命令用法说明 |
| | `blook-loader status` | 查询全局虚拟化状态、会话使能状态及当前拦截计数 |
| | `blook-loader ping` | 向驱动发送探测数据包，验证通信通道是否正常 |
| | `blook-loader version` | 查询内核驱动的版本信息 |
| 服务管理 | `blook-loader install <path>` | 向 SCM 注册驱动内核服务（要求指定驱动文件完整路径） |
| | `blook-loader start` | 启动驱动服务并在各逻辑处理器上初始化 VMX 架构 |
| | `blook-loader stop` | 停止驱动服务并退出虚拟化执行模式 |
| | `blook-loader uninstall` | 从 SCM 中注销驱动服务（要求服务处于停止状态） |
| 配置管理 | `blook-loader config-path <path>` | 校验单文件配置并登记 `Parameters\ConfigPath`，不修改运行态 |
| | `blook-loader reload` | 管理员手动要求驱动重读已登记路径 |
| | `blook-loader apply [path]` | 先登记路径再 reload；缺省为当前目录的配置文件，两阶段不具备原子事务语义 |
| 功能与查询 | `blook-loader features` | 列出 17 项功能的期望/生效状态及一句话用途 |
| | `blook-loader feature <name> <on|off>` | 独立切换一个运行态功能，不修改文件；下次 reload 以文件为准 |
| | `blook-loader page <self|pid|kernel> <hex-address>` | 查询物理入口、已知逻辑绑定与不透明入口数；用户域仅限当前会话 |
| 分析干预 | `blook-loader hook <self|pid> <address> <bytes>` | 在目标进程的指定虚拟地址处安装 EPT 拦截补丁 |
| | `blook-loader hide [windows] <on|off>` | 启用或停用内核隐匿策略，可选附加 win32k 窗口过滤 |
| | `blook-loader pin <tool|target> <pid>` | 将指定进程绑定为分析工具角色或被分析目标角色 |
| | `blook-loader unpin <pid>` | 解除指定进程的角色绑定 |
| | `blook-loader scrub <pid>` | 清除目标进程 PEB 与堆结构中的调试器特征标志 |

卸载驱动服务前必须先停止驱动服务，并释放设备句柄。全局关闭执行“所有 CPU 撤补丁 → 等待 handler 排空 → 所有 CPU 退出 VMX → 回收”的顺序；等待不持有 handler 需要的管理锁。未返回或异常展开的 handler 会延迟停止，SCM 超时不代表可强行释放；详见 [生命周期](<docs/hook-lifecycle.md>)。普通构建不再自动停止或重启服务。

## 配置体系

配置唯一来源是单个 UTF-8 INI 文件，示例见 [blook.ini](<blook.ini>)；不再把功能值分散写入注册表。服务键 `HKLM\SYSTEM\CurrentControlSet\Services\BlookDrv\Parameters` 的 `ConfigPath`（`REG_SZ`，例如 `\??\D:\blook-drv\blook.ini`）仅保存本地文件路径。启动时读取，运行时仅由管理员显式 `reload` / `apply` 重读，**没有后台轮询或文件监视**。

```ini
[device]
allow_users = false
[hypervisor]
hide_timing = true
[diagnostics]
page_fault_trace = 0
[features]
nt.query_system.process = false
window.list = false
[roles]
tool = x64dbg.exe
tool = windbg.exe
```

- **启动专用设置**：`allow_users`（默认 `false`）、`hide_timing`（默认 `true`）、`page_fault_trace`（默认 `0`）为 startup-only；改动后需要重启。reload 检测到差异时报告 `restart_required` 并拒绝整份候选配置，不会部分更新 features/roles。
- **独立逻辑功能**：`[features]` 的 17 项均默认关闭；完整名称、用途及历史作用范围见 [细粒度功能](<docs/features.md>)。共享物理入口不等于功能相互启用，窗口功能不依赖 NT hide。基础 VM maintenance 不属于可选开关。旧 `[hooks]` 配置须迁移，旧注册表 `HookMask` / `CoreHookMask` / `WindowHookMask` / `HideRewrite` / `HideNoCall` 不再决策功能。
- **完整角色快照**：`[roles]` 使用重复 `tool` / `target` / `watched` 行，每行一个 ASCII basename，大小写不敏感的精确匹配；不接受 PID、路径、通配符、逗号列表或空规则。无内置静态工具名称默认；示例工具名是文件显式规则，缺失规则为空。手动 `pin` 是独立的 PID 操作，不是配置语法。

文件 ACL 必须仅允许 Administrators/SYSTEM 写入，父目录也必须可信且禁止低权限用户替换文件或改写路径；路径限制不能替代 ACL 部署。`config-path` 要求服务已安装但不要求运行，`reload` 要求匹配驱动运行。`apply` 是先持久登记再运行应用，**不是磁盘、注册表与内存的原子事务**；reload 失败不会回滚已登记的路径。失败诊断、语法及迁移说明见 [开发指南](<docs/development.md#配置规范与错误语义>)。

本轮针对 2026-09-28 的卸载蓝屏修正了 gate 排空顺序，并新增 host 回归；修复版本尚未 live 验证，宿主模型通过不能代替真实内核验证。raw 重复/重叠 patch 仍拒绝；同一函数多逻辑处理通过 typed `dispatch_chain` 与一个入口实现，详见 [SDK](<sdk/README.md#同一函数的逻辑处理链>)。

## 源码组织

系统源码按职责划分为驱动内核、通信协议、策略计算、用户接口与宿主机测试五个层次：

| 模块路径 | 职责范围 |
| --- | --- |
| [main.cc](<src/driver/main.cc>) / [session.cc](<src/driver/session.cc>) | 驱动入口点、设备对象创建、IRP 分派、会话管理与系统电源/进程事件通知 |
| [hooks.cc](<src/driver/hooks.cc>) / [hooks.hpp](<src/driver/hooks.hpp>) | EPT hook 注册表、物理页锁定、所有权校验与拦截发布 |
| [hv.cpp](<src/driver/hv/hv.cpp>) / [ept.cpp](<src/driver/hv/ept.cpp>) | VMX 状态初始化、VMCS 配置、EPT 双层页表构建与 VM-exit 处理 |
| [hide.cc](<src/driver/hide/hide.cc>) | 内核系统服务过滤、win32k 窗口隐藏及进程角色匹配逻辑 |
| [protocol.hpp](<src/ipc/protocol.hpp>) | 全局 `ipc` 命名空间定义、定长通信结构体与 ABI v6 控制码 |
| [hook.hpp](<src/policy/hook.hpp>) / [x86_length.hpp](<src/policy/x86_length.hpp>) | 无系统依赖的策略逻辑，包括页边界计算与 x86_64 指令长度解码 |
| [ept.hpp](<src/client/ept.hpp>) | 用户态 C++23 API，提供 `session` 与 `hook` 抽象封装 |
| [main.cc](<src/loader/main.cc>) | 命令行管理程序，提供服务控制、配置解析与诊断操作 |
| [unit.cc](<tests/unit.cc>) / [ept](<tests/ept>) / [ept_edges](<tests/ept_edges>) | GoogleTest 宿主机测试，验证策略、EPT 映射、JIT 写后同步与边界状态 |
| [ept_live](<tests/ept_live>) | 显式 opt-in 的 GoogleTest 真实 JIT、透明读写与撤销回归，默认安全跳过 |
