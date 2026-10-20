# blook-drv 架构与边界

[返回首页](<../README.md>) · [用户态 SDK](<../sdk/README.md>) · [开发与测试指南](<development.md>)

本文阐述 blook-drv 系统的分层架构、执行环境约束、IPC ABI v6 通信协议、资源所有权模型与 EPT 双视图切换机制，并明确各层的功能职责与验证边界。

## 分层架构

系统划分为用户态客户端、设备与会话层、Hook 注册表、Hypervisor 核心与策略层：

```text
┌─────────────────────────────────────────────────────────────┐
│                 用户态应用 / blook-loader                     │
│        (blook::client：句柄生命周期、expected 返回值、请求封装)        │
└──────────────────────────────┬──────────────────────────────┘
                               │ CreateFileW / DeviceIoControl
                               ▼
┌─────────────────────────────────────────────────────────────┐
│   \\.\BlookDrv：设备 ACL + METHOD_BUFFERED IOCTL (ABI v6)  │
│        (校验调用者进程、会话使能状态、请求结构体长度与版本)          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  会话管理 (session.cc) ──► Hook 注册表 (hooks.cc)            │
│  (会话令牌授权、电源回调、      (物理页锁定、所有权校验、       │
│   进程生命周期事件监控)         影子页构建、发布与撤销)        │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│  Hypervisor 核心 (hv.cpp / ept.cpp)                         │
│  (每 CPU VMX 状态机、VMCS 配置、EPT 双层页表映射、VM-exit 分派) │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────┴──────────────────────────────┐
│  策略与模型层 (policy / tests)                               │
│  (指令长度解码、页边界规则、整数定义、宿主机 EPT 引擎模拟测试)    │
└─────────────────────────────────────────────────────────────┘
```

### 模块职责划分

| 层次 | 核心文件 | 主要职责 | 边界约束 |
| --- | --- | --- | --- |
| 命令行工具 | [main.cc](<../src/loader/main.cc>) | 提供 CLI 交互、驱动服务安装与生命周期管理、配置文件解析、只读状态诊断 | 不执行硬件虚拟化指令，查询操作不隐式修改系统服务配置 |
| 用户态 SDK | [ept.hpp](<../src/client/ept.hpp>) | 提供类型安全的 C++23 接口，管理连接生命周期与 RAII 撤销尝试 | 不直接操作物理地址，依靠 IOCTL 接口委托内核执行特权操作 |
| 通信协议 | [protocol.hpp](<../src/ipc/protocol.hpp>) | 定义固定宽度字段、定长结构体、IOCTL 控制码与 ABI 版本标识 | 仅传递纯值类型，禁止包含指针、标准库容器或动态对象 |
| 设备与会话 | [main.cc](<../src/driver/main.cc>) / [session.cc](<../src/driver/session.cc>) | 管理设备对象创建与 ACL、IRP 分派、会话令牌分配、系统电源与进程通知 | 仅在 `PASSIVE_LEVEL` 下处理 IRP，拒绝 WOW64 模式调用方 |
| Hook 注册表 | [hooks.cc](<../src/driver/hooks.cc>) / [hooks.hpp](<../src/driver/hooks.hpp>) | 维护拦截槽位、锁定目标物理页、校验会话令牌授权、管理补丁生成与撤销 | 限制最大 64 个全局拦截项，同物理页同地址空间禁止冲突拦截 |
| Hypervisor | [hv.cpp](<../src/driver/hv/hv.cpp>) / [ept.cpp](<../src/driver/hv/ept.cpp>) | 初始化各逻辑处理器的 VMX 架构、配置 VMCS、维护 EPT 视图与处理 VM-exit | VMX root 模式运行，不调用常规内核文件系统或动态分配例程 |
| 隐匿策略 | [hide.cc](<../src/driver/hide/hide.cc>) | 拦截内核系统服务与 win32k 窗口查询，对目标角色进程实施特征过滤 | 依赖系统未导出的内部结构偏移，服务解析失败时自动跳过 |
| 策略与测试 | [hook.hpp](<../src/policy/hook.hpp>) / [unit.cc](<../tests/unit.cc>) | 指令长度解码、页边界计算以及宿主机环境下的 EPT 模型验证 | 宿主机测试依赖模拟内存环境，不与实际硬件虚拟化交互 |

## 执行环境与运行时约束

系统统一采用 C++23 规范编写，但在用户态与内核态执行环境下遵循不同的运行时约束：

### 用户态执行环境

- **运行库支持**：使用完整的 MSVC C++ 运行时库与 Windows API。
- **错误机制**：操作以 `std::expected<T, std::error_code>`（即 `blook::client::result<T>`）返回显式状态，错误值取自 `std::system_category()`；堆内存耗尽等标准库基础异常通过标准机制处理。
- **内存管理**：使用标准库智能指针（如 `std::shared_ptr`）管理通信连接，通过 `VirtualAllocEx` 分配跨进程跳转字面量。

### 内核态执行环境

- **编译选项**：驱动编译使用 `/kernel`、`/GR-`（禁用 RTTI）、`/EHs-c-`（禁用 C++ 异常展开）、`/GS-`、`/Zc:threadSafeInit-` 以及 `set_exceptions("no-cxx")`。
- **运行时环境**：驱动脱离用户态 CRT 运行，不使用局部静态变量的线程安全初始化保护。对象管理使用内核非分页池（NonPagedPool）、placement new 与显式析构。
- **异常与探测**：使用 WDK 提供的结构化异常处理（SEH，即 `__try` / `__except`）探测用户态缓冲区，严禁依赖 C++ 异常。
- **执行上下文与中断级别**：IRP 分派函数必须在 `PASSIVE_LEVEL` 下执行。VMX root 执行热路径具有极高的执行约束，严禁在 VM-exit 处理循环中调用可能阻塞、触发页错误或需要低 IRQL 的内核 API（如 `Zw*` 函数、文件 I/O 或池内存分配）。

## 通信协议与 ABI v6

用户态 SDK 与内核驱动之间通过 Windows `METHOD_BUFFERED` IOCTL 机制进行通信。访问控制要求调用方句柄同时具备读权限与写权限（`GENERIC_READ | GENERIC_WRITE`）。

通信协议定义于 [protocol.hpp](<../src/ipc/protocol.hpp>) 中的全局 `ipc` 命名空间，当前 ABI 版本常量为 `ipc::abi_version = 6`。

### 结构体规范与内存对齐

协议采用定长值对象，禁止使用平台原生指针或动态变长数据。所有包含标头的修改请求结构体首部均为 8 字节的 `ipc::Header`：

```cpp
struct Header {
    uint32_t version{abi_version}; // 固定为 6
    uint32_t size{};               // 整个请求包的字节尺寸
};
```

核心协议结构体的字节尺寸与对齐边界如下：

| 结构体名称 | 尺寸（字节） | 对齐（字节） | 用途 |
| --- | ---: | ---: | --- |
| `ipc::Header` | 8 | 4 | 请求统一标头，标明版本与尺寸 |
| `ipc::PingRequest` / `PingResponse` | 12 / 8 | 4 / 4 | 通信通道连通性与回显探测 |
| `ipc::VersionInfo` | 8 | 2 | 驱动语义版本查询响应 |
| `ipc::EnableRequest` | 8 | 4 | 请求当前会话使能修改权限 |
| `ipc::InstallRequest` / `InstallResponse` | 96 / 8 | 4 / 8 | 安装 EPT 拦截补丁并返回 64 位拦截 ID |
| `ipc::HookRequest` | 16 | 8 | 根据 ID 执行拦截撤销或影子快照刷新 |
| `ipc::HideRequest` | 24 | 4 | 控制全局隐匿、窗口隐藏及进程角色绑定 |
| `ipc::ScrubRequest` | 16 | 4 | 清除目标进程 PEB 与堆中的调试标志 |
| `ipc::QueryResponse` | 32 | 4 | 只读查询全局与会话运行状态数据 |
| `ipc::QueryPageRequest` / `QueryPageResponse` | 32 / 2112 | 8 / 8 | 逻辑虚拟页查询；user 限当前 session-token，kernel count-only |
| `ipc::PageHookRow` | 32 | 8 | 授权范围内的用户 hook ID、目标及休眠/武装状态 |
| `ipc::ConfigurationRequest` / `ConfigurationResponse` | 16 / 40 | 4 / 8 | 查询配置状态或管理员手动重读 |
| `ipc::FeaturesRequest` / `FeaturesResponse` | 24 / 40 | 4 / 8 | 查询独立功能快照或管理员修改单项 |

### 安全门禁与权限校验

1. **设备访问控制（ACL）**：设备对象 `\Device\BlookDrv` 创建时默认配置严格的安全描述符，仅允许 SYSTEM 与 Administrators 组读写。若在配置文件中显式启用 `allow_users = true`，驱动创建设备时增加交互式用户权限。
2. **架构检查**：驱动分派例程检查调用进程架构，显式拒绝来自 WOW64（32 位子系统）的调用请求，仅接受原生 64 位调用者。
3. **会话与进程绑定**：会话在初次打开设备时生成，与发起调用的进程 PID 严格绑定。同一会话后续所有请求必须源自该 PID，防止跨进程句柄复制绕过鉴权。
4. **会话容量上限**：驱动维护最多 64 个并发活动的会话对象。

### 页查询的最小披露

`QUERY_PAGE` 的地址代表一个逻辑 4 KiB 虚拟页，不是物理页枚举。user 域的条目及计数仅限当前 session-token 所有 hook，允许查询该会话的远程目标但不泄露其他会话；kernel 域必须 PID 为零，仅返回计数，不返回 ID、目标地址或 page base。prepared/dormant 的注册计数与当前 armed 数分开报告，查询不隐式 ENABLE。

ABI v6 的页响应新增 `logical_count`、`enabled_logical_count` 和 `opaque_count`。前两项统计已登记内置入口上的逻辑绑定及当前武装入口上的有效绑定；mandatory VM maintenance 也计入。相同功能绑定在两个入口时按两处绑定计数，而不是全局去重的 feature 数。raw 补丁后面的用户进程调用链属于不透明数据，不能从一个补丁推断一个 handler；请在目标进程查询 typed chain。内核页查询按 feature writer → hook registry 的锁顺序获得一致功能/注册表快照。

### 单文件配置与功能发布

[配置读取器](<../src/driver/configuration.cc>) 在 `PASSIVE_LEVEL` 从服务 `Parameters\ConfigPath` 指向的本地 UTF-8 文件读取完整候选；注册表只登记路径，旧 `HookMask` / `CoreHookMask` / `WindowHookMask` / `HideRewrite` / `HideNoCall` 不参与功能决策。无后台轮询，只有启动与管理员显式 reload 读取。配置文件 ACL 必须仅允许 Administrators/SYSTEM 写入，所有父目录必须可信，不能靠路径校验替代防替换权限。

[配置状态](<../src/driver/configuration_state.cc>) 先校验再申请功能，成功后替换角色及当前快照并增加 generation；解析或功能失败保留旧配置。`allow_users`、`hide_timing`、`page_fault_trace` 只在启动应用，差异会拒绝整个 reload，返回 `restart_required`。loader 的 `apply` 先持久登记再调用 reload，失败不会回滚路径，不是磁盘/注册表/内存原子事务。reload 与 feature 修改要求管理员身份，不以 ENABLE 标志作为这两个管理操作的门禁。

`[roles]` 是重复 `tool` / `target` / `watched` 行组成的完整快照，按 ASCII basename 大小写不敏感精确匹配，不支持 PID、路径、通配符、列表或静态默认工具名称。手动 PID pin 另行管理，不等同于配置规则。

[17 项逻辑功能](<features.md>) 全部默认关闭且各自独立；共享入口由 typed `dispatch_chain` 快照组合，多个 handler 经 next 调到 original，而不是叠加 raw patch。窗口功能仅安装自身必要入口及 QueryWindow 基础依赖，不启用其过滤位或 NT 预设。VM maintenance 始终独立于可选功能。失败可留下透明旁路入口，停用只更新逻辑 mask，不在线释放 trampoline，也不等待旧调用快照排空；`window_hooks` 是驻留入口数而不是开启的逻辑功能数。

## 资源所有权与生命周期

系统明确区分并维护三个独立维度的所有权概念：

1. **连接所有者（Connection Owner）**：打开设备文件句柄的用户态进程，以进程 PID 为标识。
2. **修改授权所有者（Modification Owner）**：会话创建时由内核分配的全局单调递增 64 位会话令牌（Session Token）。
3. **执行目标所有者（Target Owner）**：拦截生效的目标进程 PID。对于用户态 hook，驱动锁定目标进程的 PEB identity 物理页并记录其 PFN 作为地址空间标识；对于内核 hook，作用域为全局。

```text
连接所有者 (Caller PID) ──(拥有)──► 会话令牌 (Session Token)
                                         │ (记录于拦截项)
                                         ▼
执行目标所有者 (Target PID) ◄──(施加)── EPT 拦截项 (Hook Entry)
```

### 资源释放与回收机制

- **显式按令牌回收**：当调用方发起撤销请求（`IOCTL_BLOOK_REMOVE`）时，驱动在 Hook 注册表中查找目标 ID。只有当请求携带的会话令牌与该拦截项登记的创建者令牌完全一致时，驱动才允许注销。
- **目标进程退出回收**：驱动注册了系统级进程创建与销毁回调（`PsSetCreateProcessNotifyRoutine`）。当目标进程退出时，内核回调接收到通知，自动遍历 Hook 注册表，注销所有以该目标 PID 登记的拦截项，并解除该 PID 的角色绑定与隐匿跟踪。
- **调用方退出与会话清理**：当用户态会话关闭设备句柄时，驱动执行会话清理操作（`session.cc` 中的 `revoke`），将当前会话标志置为不可用，并调用 `revoke_session(token)`，只撤销该会话创建的拦截（包括跨进程目标）。同一调用进程的其他会话不受影响。调用进程退出时，对它的全部会话执行上述清理；目标进程退出则独立调用 `revoke_process(target_pid)`，跨会话撤销所有针对该目标的拦截。

### 内置 hook 的卸载屏障

15 个已知签名的内置系统服务入口使用 root gate → 静态 MASM shim → C++ handler。进入驱动代码前计数；返回时恢复原始栈，再经认证的 leave VMCALL 转移到内核映像中已校验的 RET。只有全部 CPU 撤补丁确认、在途引用归零、全部 CPU stop 确认之后，才清空 gate 元数据和回收 trampoline。单个功能的关闭只是逻辑旁路，不启动这套全局关闭流程。详见 [生命周期](<hook-lifecycle.md>)。

## Hypervisor 与 EPT 双视图

驱动初始化阶段在所有活动逻辑处理器上依次执行 `VMXON`，并为每个处理器构建独立的虚拟机控制结构（VMCS）。

### 双 EPT 视图映射机制

系统利用 Intel EPT 技术对目标物理内存构建分离的访问视图：

1. **执行视图（Execution View / Shadow Page）**：当 CPU 在目标地址空间执行代码时，EPT 映射指向分配的影子物理页。影子页内写入了经过指令边界对齐与重构的拦截指令。
2. **数据视图（Data View / Original Page）**：当任何进程对该虚拟地址进行内存读取（如内存扫描、校验和计算或调试器内存检查）或写入时，EPT 映射指向未修改的原始物理页。

通过上述机制，目标进程在读取自身代码段时仅能获取原始指令序列，从而隔离内存检测操作。

### 物理页锁定与冲突规则

- **内存锁定机制**：安装拦截时，驱动将目标虚拟地址转换为 MDL（内存描述符列表）并锁定对应的物理页，保证页面在拦截生命周期内不会被操作系统换出至分页文件。
- **同页合并（页组）**：同一物理页在同一执行作用域内可容纳多个拦截项。驱动按（物理页，作用域）建立页组，组内共享一个影子页；安装时将所有成员的补丁合并进该影子页，撤销某个成员时按剩余成员重建。作用域的划分：内核拦截为全局作用域，用户拦截按进程身份页（PEB PFN）划分，因此多个进程共享同一镜像页时各自持有独立影子。
- **合并冲突拒绝**：同作用域内补丁的指令覆盖区间不得重叠，否则驱动拒绝安装并返回 `STATUS_OBJECT_NAME_COLLISION`；内核（全局）作用域与任何用户作用域在同一物理页上互不兼容，同样以该状态拒绝。
- **全局拦截容量**：Hook 注册表支持最大活动拦截数量由 `blook::max_hooks` 限制为 64 项；页组数量与拦截项同上限，影子页按页组分配。

### 电源管理与处理器状态同步

驱动通过 `ExRegisterCallback` 订阅 `\Callback\PowerState` 的系统状态锁通知。暂停时拒绝新会话与 IOCTL，并走与卸载相同的撤补丁/排空/stop 屏障，但保留 gate 和注册表资源；恢复时创建新的 EPT，重开 gate 管理并恢复原已武装的 hook 与未命中的 watch。任何恢复失败都会再次安全停止并保留 suspended/错误状态，不报告半套恢复成功。

对于处理器动态变更通知，系统在检测到新处理器热添加时返回 `STATUS_NOT_SUPPORTED`，防止未经初始化的逻辑处理器执行受控页面。

## 验证边界与能力范围

当前单文件配置、ABI v6、独立功能与 typed dispatch 重构已有源码编译和 host 测试结果，**未做当前版本 live 验证**。同地址重复 raw patch 仍拒绝，typed 链只组合有明确签名的逻辑 handler；不提供通用 detour 重定位保证。关闭功能不等于卸载。全局卸载已实现显式 quiesce/drain/stop 屏障；reset 必须发生在该屏障之后，不能替代屏障。未完成硬件级并发卸载、休眠恢复和异常退出验证。

- **模型测试与硬件环境**：宿主机测试套件（`blook-tests`）验证 EPT 页表结构拼接算法与边界策略，不能代替物理硬件上的 Intel VT-x 执行验证。
- **平台兼容性要求**：驱动依赖 Intel 处理器的 VT-x 与 EPT 硬件扩展；加载前检测 CPUID 与 MSR 特征位。若系统已运行其他不支持嵌套虚拟化的虚拟机监控程序或启用了基于虚拟化的安全性（VBS），驱动初始化将主动中止。
- **动态服务解析**：win32k 与部分内核系统服务的隐匿依赖符号与未导出结构体偏移解析。若当前 Windows 内部版本缺少对应导出或特征匹配失败，请求相应功能会失败并保留旧 effective mask，查询 `unsupported` 与 `last_status` 获取诊断；`window_hooks` 只反映驻留物理入口数，不能据此判断过滤已启用。
