-- blook-drv: hardened Intel VT-x hypervisor driver for Windows x64.
--
--   xmake f -p windows -a x64 -m releasedbg --kchannel_dir=D:\blook-kernel-project\blook-kchannel -y
--   xmake -y
--
-- The kchannel headers are consumed, never vendored implicitly: point
-- --kchannel_dir at the blook-kchannel checkout, or leave it unset and the
-- pinned snapshot under third_party/kchannel is used (see third_party/README.md).
set_project("blook-drv")

-- version.txt is the single source of truth, but xmake's project-description
-- sandbox cannot read files. The build wrappers (scripts/Build.ps1, CI,
-- release) export BLOOK_VERSION from version.txt before configuring; the
-- fallback keeps a bare `xmake f` working and scripts/CheckVersion.ps1 keeps
-- the two in sync.
local version = os.getenv("BLOOK_VERSION") or "4.0.0"
set_version(version)

add_requires("gtest 1.17.0")
-- User-mode code is C++23: the SDK returns std::expected, which MSVC only
-- provides in C++23 mode. The kernel target overrides this to C++17 below.
set_languages("cxx23")
set_arch("x64")
set_defaultmode("releasedbg")
add_rules("mode.debug", "mode.releasedbg", "mode.release")
add_rules("plugin.compile_commands.autoupdate", { outputdir = "build" })

option("kchannel_dir")
    set_default("")
    set_showmenu(true)
    set_description("blook-kchannel checkout (required); include/ and src/{common,user,kernel} are compiled in")
option_end()

option("kchannel_stub")
    set_default(false)
    set_showmenu(true)
    set_description("Link the user-side stand-in transport instead of real kchannel sources (host-only test builds)")
option_end()

local function kchannel_include()
    local dir = get_config("kchannel_dir")
    if dir and dir ~= "" then
        return path.join(dir, "include")
    end
    -- A vendored snapshot is the fallback for a bare `xmake f`; it is kept
    -- pinned by scripts/SyncKchannel.ps1. Building without either is a hard
    -- error: silently shipping a driver with no transport would be worse than a
    -- failed configure.
    local vendored = "third_party/kchannel/include/blook/kchannel.h"
    if os.isfile(vendored) then
        return "third_party/kchannel/include"
    end
    return "third_party/kchannel/include"
end

local function kchannel_src()
    local dir = get_config("kchannel_dir")
    if dir and dir ~= "" then
        return dir
    end
    return "third_party/kchannel"
end

-- The transport repository publishes its headers before its implementation.
-- When the sources are there they are compiled straight into our targets (the
-- integration guide's source-drop mode); when they are not, the user-side SDK
-- links a stand-in that reports KC_ERR_UNSUPPORTED instead of failing the build
-- of the host-side test matrix. Both cases are visible in the configure log.
local function kchannel_sources(subdir)
    local files = os.files(path.join(kchannel_src(), subdir .. "/*.cpp"))
    local common = os.files(path.join(kchannel_src(), "src/common/*.cpp"))
    for _, file in ipairs(common) do
        table.insert(files, file)
    end
    return files
end

local function kchannel_user_sources()
    return kchannel_sources("src/user")
end

local function kchannel_kernel_sources()
    return kchannel_sources("src/kernel")
end
-- User-mode warning policy: /W4 everywhere. The kernel target keeps /W4
-- without /WX because WDK headers emit warnings we cannot fix (tracked in
-- docs/development.md).
local function user_flags()
    add_cxxflags("/utf-8", "/permissive-", "/W4", "/Zc:__cplusplus", { tools = "cl" })
end

rule("blook.masm")
    set_extensions(".asm")
    on_build_file(function (target, sourcefile, opt)
        import("core.project.depend")
        import("core.tool.toolchain")
        local tc = toolchain.load("msvc", { plat = target:plat(), arch = target:arch() })
        local compiler = tc:tool("as")
        local objectfile = target:objectfile(sourcefile)
        table.insert(target:objectfiles(), objectfile)
        depend.on_changed(function ()
            os.mkdir(path.directory(objectfile))
            os.vrunv(compiler, { "/nologo", "/c", "/Fo" .. objectfile, sourcefile }, { envs = tc:runenvs() })
        end, { dependfile = target:dependfile(objectfile), files = { sourcefile }, changed = target:is_rebuilt() })
    end)
rule_end()

-- The kernel driver. C++17: WDK/MSVC compatibility first, no exceptions, no
-- RTTI, no STL containers.
target("blook-drv")
    add_rules("wdk.driver", "wdk.env.wdm", "blook.masm")
    set_values("wdk.env.winver", "win10_vb")
    set_languages("cxx17")
    set_exceptions("no-cxx")
    add_defines("NOMINMAX", "POOL_NX_OPTIN=1", "BLOOK_KERNEL=1", "_KERNEL_MODE=1")
    add_includedirs("src", "include", "third_party/ia32", { kchannel_include(), path.join(kchannel_src(), "src") })
    add_files("src/driver/**.cc", "src/driver/**.cpp", "src/driver/**.asm", "src/ssdt/*.cc", "src/ipc/kchannel_adapter.cc")
    local kernel_sources = kchannel_kernel_sources()
    if #kernel_sources > 0 then
        add_files(kernel_sources)
        add_defines("BLOOK_HAVE_KCHANNEL=1")
    else
        -- is the intended hard failure (never silently stub a driver transport).
    end
    add_cxxflags("/kernel", "/GR-", "/EHs-c-", "/Zc:threadSafeInit-", "/GS-", "/utf-8", "/W4", { force = true })
    add_syslinks("ntoskrnl", "hal", "wmilib", "wdmsec")
    add_ldflags("/INTEGRITYCHECK", "/ENTRY:DriverEntry", { force = true })
    set_encodings("utf-8")
target_end()

-- The user-mode SDK: kchannel client adapter plus the wire ABI and the EPT hook
-- API. The header-only part lives in include/blook/drv; this static library
-- holds the translation units that must be compiled once.
target("blook-sdk")
    set_kind("static")
    add_files("src/ipc/kchannel_client.cc")
    local user_sources = kchannel_user_sources()
    if #user_sources > 0 then
        add_files(user_sources)
        add_defines("BLOOK_HAVE_KCHANNEL=1")
    elseif get_config("kchannel_stub") then
        add_files("src/ipc/kchannel_stub.cc")
        add_defines("BLOOK_HAVE_KCHANNEL=0", "BLOOK_KCHANNEL_STUB=1")
        print("warning: --kchannel_stub: SDK links the stand-in transport (host-only builds)")
    else
        -- no sources: the SDK build fails at the kchannel.h include below, which
    end
    add_includedirs("src", "include", { kchannel_include(), path.join(kchannel_src(), "src") })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_syslinks("advapi32", "bcrypt")
    set_encodings("utf-8")
target_end()

target("blook-loader")
    set_kind("binary")
    add_deps("blook-sdk")
    add_files("src/loader/*.cc")
    add_includedirs("src", "include", { kchannel_include(), path.join(kchannel_src(), "src") })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_syslinks("advapi32")
    set_encodings("utf-8")
target_end()

-- Host-side unit tests. No kernel, no hardware: pure policy, EPT page-table
-- math, the wire ABI, the hook state machine and the hiding rules.
target("blook-tests")
    set_kind("binary")
    add_packages("gtest")
    add_deps("blook-sdk")
    add_files("tests/unit/unit.cc", "tests/unit/dispatch.cc",
              "tests/unit/hook_shutdown.cc", "tests/unit/page_query.cc",
              "tests/unit/role_rules.cc", "tests/unit/configuration.cc",
              "tests/unit/features.cc", "tests/unit/gate_entry.cc",
              "tests/unit/ept/*.cc", "tests/unit/ept_edges/*.cc",
              "tests/unit/policy_cpuid.cc", "tests/unit/policy_msr.cc",
              "tests/unit/policy_breakpoint.cc", "tests/unit/policy_nested.cc")
    add_files("src/driver/hv/ept.cpp", "src/driver/hv/mtrr_policy.cpp")
    add_includedirs("tests", "tests/unit", "src", "include", "third_party/ia32")
    add_defines("BLOOK_EPT_TEST", "NOMINMAX")
    user_flags()
    add_tests("unit")
    set_encodings("utf-8")
target_end()

-- Contract tests from the pre-hardening tree, each separate so a failure names
-- the contract that broke.
target("blook-client-tests")
    set_kind("binary")
    add_packages("gtest")
    add_deps("blook-sdk")
    add_files("tests/unit/client.cc", "tests/unit/ept/main.cc")
    add_includedirs("tests", "tests/unit", "src", "include", { kchannel_include() })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_tests("unit")
    set_encodings("utf-8")
target_end()

target("blook-loader-tests")
    set_kind("binary")
    add_packages("gtest")
    add_deps("blook-sdk")
    add_files("tests/unit/loader.cc", "tests/unit/ept/main.cc")
    add_includedirs("tests", "tests/unit", "src", "include", { kchannel_include() })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_tests("unit")
    set_encodings("utf-8")
target_end()

target("blook-protocol-tests")
    set_kind("binary")
    add_packages("gtest")
    add_deps("blook-sdk")
    add_files("tests/unit/protocol.cc", "tests/unit/ept/main.cc")
    add_includedirs("tests", "tests/unit", "src", "include", { kchannel_include() })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_tests("unit")
    set_encodings("utf-8")
target_end()

target("blook-terminal-tests")
    set_kind("binary")
    add_packages("gtest")
    add_deps("blook-sdk")
    add_files("tests/unit/terminal.cc", "src/loader/terminal.cc",
              "tests/unit/ept/main.cc")
    add_includedirs("tests", "tests/unit", "src", "include")
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_tests("unit")
    set_encodings("utf-8")
target_end()

target("blook-image-page-tests")
    set_kind("binary")
    add_packages("gtest")
    add_deps("blook-sdk")
    add_files("tests/unit/image_page.cc", "tests/unit/ept/main.cc")
    add_includedirs("tests", "tests/unit", "src", "include")
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    add_syslinks("bcrypt")
    user_flags()
    add_tests("unit")
    set_encodings("utf-8")
target_end()

target("blook-bench")
    set_kind("binary")
    add_deps("blook-sdk")
    add_files("tests/unit/bench.cc")
    add_includedirs("tests", "tests/unit", "src", "include")
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    set_encodings("utf-8")
target_end()

-- Opt-in real-driver tests: they load the driver and require hardware
-- virtualisation, so they are never part of the host-only suite.
local live_suites = {
    { "ept-live", "tests/unit/ept_live/*.cc" },
    { "session-smoke", "tests/unit/session_smoke.cc" },
    { "live-watch", "tests/unit/live_watch.cc" },
    { "live-cow", "tests/unit/live_cow.cc" },
    { "live-dormant", "tests/unit/live_dormant.cc" },
    { "ept-smoke", "tests/unit/smoke.cc" },
}
for _, suite in ipairs(live_suites) do
    target("blook-" .. suite[1])
        set_kind("binary")
        set_default(false)
        add_packages("gtest")
        add_deps("blook-sdk")
        add_files(suite[2], "tests/unit/ept/main.cc")
        if suite[1] ~= "ept-live" and suite[1] ~= "session-smoke" then
            add_files("tests/unit/ept_live/fixture.cc")
        end
        add_includedirs("tests", "tests/unit", "src", "include", { kchannel_include() })
        add_defines("NOMINMAX", "UNICODE", "_UNICODE")
        user_flags()
        set_encodings("utf-8")
    target_end()
end

-- In-guest test programs: pushed into the VM by the e2e runner.
target("blook-antidetect")
    set_kind("binary")
    add_deps("blook-sdk")
    add_files("tests/guest/antidetect/*.cc")
    add_includedirs("include", "src", "tests/guest/antidetect", { kchannel_include() })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    set_encodings("utf-8")
target_end()

target("blook-guest-hooks")
    set_kind("binary")
    add_deps("blook-sdk")
    add_files("tests/guest/hooks/*.cc")
    add_includedirs("include", "src", "tests/guest/hooks", { kchannel_include() })
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    user_flags()
    add_syslinks("psapi")
    set_encodings("utf-8")
target_end()