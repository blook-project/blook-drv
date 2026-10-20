-- xmake package definition for blook-drv, published through
-- blook-project/blook-xmake-repo. scripts/publish-registry.ps1 rewrites the
-- <VERSION>/<SHA256> placeholders below with the release values.
--
-- Consume it with:
--   add_repositories("blook https://github.com/blook-project/blook-xmake-repo.git")
--   add_requires("blook-drv <VERSION>")
--   target("app"):add_packages("blook-drv")
package("blook-drv")
    set_description("blook-drv: hardened VT-x hypervisor driver and user-mode EPT hook SDK")
    set_kind("library", { headeronly = true })

    add_urls("https://github.com/blook-project/blook-drv/releases/download/v$(version)/blook-drv-$(version).zip")
    add_versions("<VERSION>", "<SHA256>")

    on_install("windows", function (package)
        -- The SDK is header-only; the prebuilt .sys lives next to it so a
        -- consumer can deploy the exact binary the headers were built with.
        os.cp("include", package:installdir())
        os.cp("sdk", package:installdir())
        os.cp("blook-drv.sys", package:installdir("bin"))
    end)

    on_test(function (package)
        assert(package:check_cxxsnippets({ test = [[
            #include <blook/drv/wire.hpp>
            static_assert(wire::abi_version == 7, "wire ABI");
        ]] }, { configs = { languages = "cxx20", cxflags = "/EHsc", defines = "NOMINMAX" } }))
    end)
package_end()
