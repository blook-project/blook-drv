# DRY RUN - NOT EVIDENCE OF DRIVER FUNCTION

This directory was produced with `scripts/E2E.ps1 -DryRun`: the harness validated
the 56-case matrix and wrote its report, but **no VM was created and no driver
was loaded**. It proves the harness works; it does not prove the hypervisor
does. A real run is only valid with `"dry_run": false` (or no flag) and the
per-case screenshots/state artefacts listed in docs/evidence/README.md.