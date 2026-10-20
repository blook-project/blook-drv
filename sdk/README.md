# blook-drv 用户态 SDK

[返回首页](<../README.md>) · [架构与边界](<../docs/architecture.md>) · [开发与测试指南](<../docs/development.md>)

blook-drv 用户态 SDK 提供基于 C++23 标准的头文件库接口，供分析工具、自动化组件与宿主程序同内核驱动建立通信。SDK 封装了设备连接建立、状态查询、双 EPT 视图拦截、内核服务隐匿与调试标记清除等功能。

SDK 主入口头文件为 [ept.hpp](<../src/client/ept.hpp>)，核心类型位于 `blook::client` 命名空间；底层通信协议与常数定义位于全局 `ipc` 命名空间（[protocol.hpp](<../src/ipc/protocol.hpp>)）。

## 工程集成

### 环境依赖

集成 SDK 需要满足以下编译与运行环境：

- **编译器**：支持 C++23 标准的 MSVC 编译器，要求完整支持 `std::expected` 与 concept 约束。
- **平台与架构**：Windows 10/11 x64 操作系统。
- **系统链接库**：链接 `advapi32.lib`。

SDK 采用头文件库（header-only）组织，接口依赖仓库 `src` 目录下的 `client/`、`ipc/` 与 `policy/` 模块。调用工程应将仓库的 `src` 根目录添加至包含路径中。

### 构建配置示例

使用 xmake 构建的项目可通过以下配置引入源码树：

```lua
set_languages("cxx23")
set_arch("x64")

target("blook-client-tool")
    set_kind("binary")
    add_files("src/main.cpp")
    add_includedirs("deps/blook-drv/src")
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    add_syslinks("advapi32")
```

对于使用 CMake 的项目，添加对应的包含路径与链接依赖：

```cmake
cmake_minimum_required(VERSION 3.20)
project(blook-client-tool CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(blook-client-tool src/main.cpp)
target_include_directories(blook-client-tool PRIVATE deps/blook-drv/src)
target_link_libraries(blook-client-tool PRIVATE advapi32)
```

仓库同时提供了独立的包定义文件：位于仓库根目录的 [xmake.lua](<../packages/b/blook-client/xmake.lua>) 与 [blook-drv-sdk.lua](<blook-drv-sdk.lua>)。包定义将 master 版本固定到特定 commit，通过包管理器集成时仅拉取头文件，不触发驱动编译。

## 只读状态查询

应用程序通过 `blook::client::session::open(blook::client::open_mode::read_only)` 创建只读连接。只读连接打开设备符号链接 `\\.\BlookDrv`，但不向驱动发送使能指令（`IOCTL_BLOOK_ENABLE`），适用于系统状态诊断与监控场景。

```cpp
#include <client/ept.hpp>
#include <cstdio>

int main() {
    // 建立未使能修改能力的只读会话
    auto session = blook::client::session::open(blook::client::open_mode::read_only);
    if (!session) {
        std::fprintf(stderr, "打开驱动设备失败，Win32 错误码: %lu\n",
                     session.error().value());
        return 1;
    }

    // 执行状态查询
    const auto info = session->query();
    if (!info) {
        std::fprintf(stderr, "查询状态失败，Win32 错误码: %lu\n",
                     info.error().value());
        return 1;
    }

    // 校验通信协议 ABI 版本
    if (info->abi != ipc::abi_version) {
        std::fprintf(stderr, "协议 ABI 不匹配: 客户端=%u, 驱动=%u\n",
                     ipc::abi_version, info->abi);
        return 2;
    }

    std::printf("驱动 ABI: %u\n", info->abi);
    std::printf("虚拟化引擎运行状态: %s\n", info->running ? "已启动" : "已停止");
    std::printf("当前会话使能状态: %s\n", info->enabled ? "已使能" : "只读");
    std::printf("作用于当前进程的拦截数: %u\n", info->hooks);
    std::printf("内核隐匿状态: %s\n", info->hidden ? "已启用" : "已停用");
    std::printf("已安装的窗口服务拦截数: %u\n", info->window_hooks);
    std::printf("后端状态码 (NTSTATUS): 0x%08X\n",
                static_cast<unsigned>(info->backend_status));

    return 0;
}
```

### 查询协议与 ABI v6

查询接口调用成功后返回 `blook::client::session_info`：它是 32 字节固定布局的 `ipc::QueryResponse` _wire 结构体的解码视图，整型标志已转换为 `bool`。

| 字段 | 类型 | 说明与口径 |
| --- | --- | --- |
| `abi` | `uint32_t` | 驱动通信协议版本，现行为 `6`；调用方应与 `ipc::abi_version` 比较校验 |
| `version` | `uint32_t` | 驱动协议兼容标识，当前实现同 `abi_version`；产品语义版本通过版本 IOCTL 查询 |
| `running` | `bool` | 全局 Intel VT-x 虚拟化引擎运行标志；`1` 表示已启动，`0` 表示已停止 |
| `enabled` | `bool` | 当前会话是否获得修改授权；通过 `open(open_mode::read_write)` 请求使能，只读会话不使能 |
| `hooks` | `uint32_t` | 作用于**调用方进程**的活动用户态拦截总数，不包含针对其他进程的拦截计数 |
| `hidden` | `bool` | 全局 NT 可选功能有效状态，不表示所有 17 项都已启用 |
| `window_hooks` | `uint32_t` | win32k 驻留物理入口计数，功能关闭后仍可能非零；有效逻辑功能应查询 `query_features()` |
| `backend_status` | `int32_t` | 驱动底层记录的原始内核 `NTSTATUS` 状态码（如 `STATUS_SUCCESS`） |

## API 接口参考

SDK 核心操作集中于 `blook::client::session` 与 `blook::client::hook` 两个类型。

### 会话生命周期与配置

| 接口方法 | 说明 |
| --- | --- |
| `session::open(open_mode mode = open_mode::read_write)` | 打开驱动设备句柄。`read_write` 模式会同时向驱动请求会话使能，允许执行后续修改操作；`read_only` 仅建立只读连接 |
| `session::query()` | 发起只读查询，返回解码后的 `session_info`（布尔标志已转换为 `bool`） |
| `session::query_page(const void* address, pid target = {}, uint32_t domain = ipc::page_domain_user)` | 只读查询逻辑 4 KiB 虚拟页的注册/武装/休眠计数及授权范围内的条目 |
| `session::query_configuration(bool reload = false)` | 返回配置代数、配置快照功能位、启动 ACL 设置及最近状态/错误行；`true` 与 reload 操作等价 |
| `session::reload_configuration()` | 管理员显式重读已登记的 `Parameters\ConfigPath`，返回 `ConfigurationResponse` |
| `session::query_features()` | 查询当前 `desired` / `effective` / `unsupported` 与 `last_status` |
| `session::set_feature(blook::feature::id id, bool enabled)` | 管理员原子修改单一稳定逻辑位（也保留 uint32_t 重载），不做 query + 全量回写 |
| `session::hide(bool enable)` | 兼容包装：开启 NT 预设；关闭时清除全部可选位，不在线卸载物理入口 |
| `session::hide_windows(bool enable)` | 兼容包装：独立开启或关闭窗口预设，不隐式开启 NT 功能 |
| `session::pin(pid process, process_role role)` | 将指定进程绑定为指定角色（`process_role::tool` 或 `process_role::target`） |
| `session::unpin(pid process)` | 解除指定进程的角色绑定 |
| `session::scrub(pid process, scrub flags = scrub::all)` | 清除指定目标进程内存中的调试器特征标志（支持 `scrub::peb`、`scrub::heap` 组合） |

### 页查询与配置权限边界

`query_page` 按逻辑虚拟页而非 PFN 查询，不读取目标字节。user 域的计数和条目均仅包含**当前连接 session-token 所有**的 hook，包括该会话安装到远程 PID 的项；同一进程的另一个会话也不能枚举它们。user 的 `pid{}` 表示调用进程。kernel 域要求 PID 为零，仅返回 count-only 统计，`entry_count`、`page_base` 和 PID 为零，不返回内核 hook ID 或地址。`registered_count` 包含 prepared/dormant 项，`armed_count` 还受最后成功发布及 backend running 状态约束；不能将注册数当成有效执行数。

只读查询不要求 ENABLE，但设备 IOCTL 仍要求底层句柄具有读写访问权限；`open_mode::read_only` 指不请求修改使能，不是绕过 ACL。reload 和 feature 修改要求管理员鉴权，不以 ENABLE 标志作为这两个管理操作的门禁，即使 `allow_users=true` 也不授予普通用户这些管理能力。

配置是单文件 UTF-8 的完整快照，无后台轮询；管理员手动登记路径及重读的命令和可信文件 ACL 要求见 [配置规范](<../docs/development.md#配置规范与错误语义>)。`allow_users`、`hide_timing`、`page_fault_trace` 是 startup-only，差异导致整份 reload 拒绝并标记 `restart_required`。IOCTL 传输成功不代表应用成功，必须检查 `ConfigurationResponse::last_status`、`error_line` 和 `restart_required`。配置 `features` 是上次成功配置快照，不一定反映随后 `set_feature` 的运行态更改；实时状态以 `query_features()` 为准，下次成功 reload 会全量替换功能位。

17 项功能各自独立、默认全关，稳定 ID、用途及失败状态见 [细粒度功能](<../docs/features.md>)。功能失败保留旧 desired/effective，可能留下透明旁路的驻留入口；`set_feature()` 也需检查响应的 `last_status`，不能仅凭 `result` 有值判断已启用。停用不构成 in-flight 调用排空屏障，也不承诺安全回收 trampoline。

页响应额外区分 `logical_count`（内置入口的全部已知 handler 绑定）、`enabled_logical_count`（当前武装入口上的有效绑定）与 `opaque_count`（无法得知逻辑链的 raw 补丁数）。同一功能跨入口重复绑定会分别计数。用户态逻辑链只能在目标进程用 typed chain 查询；新开的 CLI/SDK 会话看不到旧会话拥有的 hook。ABI v6 与 v5 页响应不兼容。

### EPT 拦截与重定向

| 接口方法 | 说明 |
| --- | --- |
| `session::patch(void* address, byte_range auto&& bytes, pid target = pid::current())` | 在指定进程的虚拟地址处安装二进制补丁，返回 `hook` 对象；字节序列接受任何 1 字节连续范围（`std::byte`/`uint8_t` 数组、`std::vector`、`std::span` 等） |
| `session::redirect(void* target, void* replacement, pid owner = pid::current())` | 在目标进程中分配跳转字面量并安装 6 字节间接跳转，将目标函数执行导向替代函数 |
| `hook::id()` | 读取当前拦截项的全局唯一 64 位标识符 |
| `hook::refresh()` | 在目标模块代码重新加载或发生修改后，重新同步 EPT 影子页的快照数据（同页所有拦截项的补丁会一并重新合并） |
| `hook::remove()` | 显式撤销拦截项；同页其余拦截项不受影响，其影子页会被重建。成功撤销后清空本地 ID |

`pid` 是强类型进程标识：`pid::current()` 表示当前进程，默认构造的 `pid{}`（值为 0）在驱动侧同样表示调用进程自身。

## 拦截机制与约束条件

### 页内边界与指令长度对齐

安装补丁时，SDK 校验补丁字节长度必须位于 `1` 至 `64` 字节之间，且 `[address, address + bytes.size())` 必须完整落在单个 4 KiB 物理页内，不支持跨页补丁。

驱动内核在接收到补丁请求后，利用内建的轻量级 x86_64 指令解码器校验目标地址代码。若传入的补丁长度截断了某条完整指令，内核将自动扩展覆盖范围至该完整指令的边界，并使用 `0x90`（NOP）填充尾部未覆盖的字节。若目标指令无法被解码器正确识别，驱动将拒绝安装请求并返回错误。

### 同一物理页上的多个拦截

同一进程在同一 4 KiB 页内可以在全局容量上限内安装多个互不重叠的拦截项：驱动会将它们合并进该进程独立的影子页，每个补丁按各自的指令覆盖区间写入。数据读操作仍然返回原始字节，执行时由 EPT 按需切换合并后的影子视图。撤销其中一个拦截项只会从影子页重建中移除对应补丁，其余拦截项保持生效。

合并规则：

- 同进程（同一身份页作用域）的拦截项要求覆盖区间互不重叠；重叠或完全相同的区间会被拒绝（`ERROR_OBJECT_NAME_COLLISION` 对应的驱动状态）。
- 内核（全局作用域）拦截项之间可以共页，但同样不允许区间重叠。
- 内核拦截项与用户拦截项永不共页：全局作用域与进程作用域在同一物理页上会互相冲突。
- 多个进程共享同一物理镜像页时（如系统 DLL），每个进程各自持有独立的影子页与补丁集。

### 同一函数的逻辑处理链

同一入口重复或重叠的 raw `patch` / `redirect` 仍被拒绝，不会自动将跨 session 的机器码补丁串联。SDK 公开 `blook::client::dispatch_chain<Signature, Capacity>`（[dispatch.hpp](<../src/policy/dispatch.hpp>)）：一个物理入口进入同签名 dispatcher，多个逻辑 handler 通过 `next` 组合。以下仅展示 typed 链，不安装 hook：

```cpp
using chain_type = blook::client::dispatch_chain<int(int), 4>;
int add_one(void*, chain_type::continuation next, int value) {
    return next(value) + 1;
}
int double_result(void*, chain_type::continuation next, int value) {
    return next(value) * 2;
}
int known_original(int value) { return value; }

int logical_example(int value) {
    chain_type snapshot;
    if (!snapshot.add({1, add_one, nullptr, 0}) ||
        !snapshot.add({2, double_result, nullptr, 10}))
        return known_original(value);
    return snapshot.invoke(known_original, value);
}
```

优先级按升序、同优先级按登记顺序，逻辑 ID 不得重复；每个 handler 必须至多调用一次 next，也可不调用 next 来短路。接入函数 hook 时，由调用者在目标进程内准备 dispatcher，并仅做一次 `redirect`；`original` 必须是调用者提供的、签名正确且有效的 callable，不能把已 redirect 的入口当 original 导致递归。SDK **没有自动生成通用 trampoline 或通用 detour 指令重定位**。调用者负责同步发布调用快照，调用期间不得修改它，并保证 handler/context/original 存活直至读者排空；逻辑链不解决任意并发物理卸载安全。

链支持 `set_enabled(id, bool)` 单独开关，`size()` / `enabled_count()` 分别查询全部/启用条目，`at(index)` 按分发顺序只读枚举 ID、优先级、名称和一句话用途，越界返回 nullptr。禁用不删除条目；复制出的旧快照不受新快照修改影响。示例：

    chain_type next = current; // 必须在所属注册表的同步保护下复制/发布
    next.set_enabled(2, false);
    auto all = next.size();
    auto enabled = next.enabled_count();
    const auto* first = next.at(0);

entry 的 name/purpose 是调用方持有的字符串指针，需与 handler/context 一样覆盖快照读者的生命周期。驱动内置入口的全局回收由 [gate 屏障](<../docs/hook-lifecycle.md>) 负责；用户进程自行安装的 raw redirect 的 handler 生命周期仍由该进程管理。

### 入口重定向机制

`session::redirect` 用于将函数入口拦截并跳转至替代函数。函数内部调用 [ept.hpp](<../src/client/ept.hpp>) 中的 `entry_jump` 辅助函数，构造 6 字节的 RIP 相对间接跳转指令：

```text
ff 25 xx xx xx xx    ; jmp qword ptr [rip + rel32]
```

重定向过程要求如下约束：

1. **字面量（Literal）存储**：跳转目标绝对地址（64 位指针）存储于独立的 8 字节内存空间中。`redirect` 通过 `VirtualAlloc` 或 `VirtualAllocEx` 在进程地址空间中分配该页面。
2. **相对位移范围**：字面量存储地址相对跳转指令下一条指令的位移必须处于带符号 32 位整数范围内（即 `[-2 GiB, +2 GiB]`）。若寻址超出该范围，`entry_jump` 返回空 `std::optional`，`redirect` 终止安装并返回 `ERROR_INVALID_PARAMETER`。
3. **内存生命周期**：分配的字面量页面在拦截生效期间必须保持可读。为了避免替代函数返回时出现非法内存访问，SDK 当前不自动释放已分配的字面量内存。

## 对象生命周期与所有权

### 连接共享与 RAII 设计

`session` 结构管理与驱动设备的底层通信，内部持有共享连接结构 `std::shared_ptr<detail::connection>`。

1. **会话对象**：`session` 采用仅移动（move-only）语义，禁止拷贝。
2. **拦截对象**：由 `session::patch` 或 `session::redirect` 返回的 `hook` 对象同样持有底层连接的 `shared_ptr` 引用。只要仍有 `hook` 实例处于存活状态，底层驱动句柄将保持开启。
3. **析构与撤销**：`hook` 的析构函数尝试调用 `remove()` 撤销内核拦截；由于析构函数无法传递返回值，若需要确保拦截已撤销并获取明确状态，应显式调用 `hook::remove()`。

### 内核所有权与进程级清理

驱动内部通过三层维度管理资源所有权：

1. **会话令牌（Session Token）**：每个打开设备的会话分配独立的 64 位令牌。安装拦截时，拦截项记录创建该拦截的会话令牌。`remove()` 与 `refresh()` 操作要求调用方会话令牌与记录严格一致，其他会话无法修改该拦截。
2. **目标进程生命周期**：内核注册进程创建与退出通知回调。当被拦截的目标进程终止时，驱动自动定位并回收所有绑定到该目标 PID 的拦截项与角色标记，避免孤儿拦截残留。
3. **调用进程会话清理**：关闭连接时，驱动按该连接的会话令牌撤销它创建的全部拦截，包括针对其他进程的拦截；不会撤销同一进程中其他连接创建的拦截。临时只读查询或统计句柄的关闭不影响正在工作的 hook。调用进程退出时，驱动撤销其所有会话创建的拦截，并独立清理以该进程为目标的拦截。

## 错误处理规范

SDK 接口统一采用 `blook::client::result<T>`（即 `std::expected<T, std::error_code>`）作为返回类型，错误值来自 `std::system_category()`：

- 操作成功时，通过解引用或箭头运算符访问数据。
- 操作失败时，通过 `.error()` 获取 `std::error_code`，以 `.error().value()` 取得原始 Win32 错误码；`std::error_code` 可直接与 `std::format`、条件判断及标准库错误设施协作。

| 错误码 | 对应场景 | 处理方式 |
| --- | --- | --- |
| `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` | 设备符号链接 `\\.\BlookDrv` 不存在 | 确认驱动服务已注册并成功启动 |
| `ERROR_ACCESS_DENIED` | 设备 ACL、管理员门禁或会话所有权校验失败 | 核对管理员身份及创建会话；[配置文件](<../blook.ini>) 中的 `allow_users` 仅控制 startup-only 设备 ACL，不能绕过令牌或管理操作鉴权 |
| `ERROR_INVALID_HANDLE` | 设备连接未建立或已被释放 | 检查 `session` 对象是否已析构或移动 |
| `ERROR_INVALID_PARAMETER` | 补丁长度超出范围、跨越 4 KiB 页边界、指令无法解码或重定向位移越界 | 检查目标虚拟地址、补丁长度及汇编指令合法性 |
| `ERROR_INVALID_DATA` | 内核返回的响应包尺寸与协议定义不匹配 | 检查客户端 SDK 与内核驱动的 ABI 版本一致性 |
| `ERROR_NOT_READY` | 内核虚拟化引擎未处于运行状态 | 确认驱动加载时硬件虚拟化初始化成功 |
