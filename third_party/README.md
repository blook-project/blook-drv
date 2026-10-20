# Third-party code

Everything here is vendored because it is either not packaged or must be pinned
to a revision whose bit-field layout the driver depends on.

| Path | Origin | Licence | Why pinned |
|---|---|---|---|
| `ia32/ia32.hpp` | [jonomango/hv](https://github.com/jonomango/hv) (derived from HyperPlatform) | MIT | Exact bit-field layout of VMCS/EPT/MSR structures. A newer revision can silently change field order. |
| `kchannel/` | [blook-project/blook-kchannel](https://github.com/blook-project/blook-kchannel) | MIT | Pinned snapshot of the transport headers/sources so this repository's CI does not depend on a second checkout. Replaced by `--kchannel_dir=<repo>` during cross-repository development; `scripts/SyncKchannel.ps1` refreshes it and records the commit. |

`LICENSES/` holds the full text of every vendored licence.
